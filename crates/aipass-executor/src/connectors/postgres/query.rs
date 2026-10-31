// SPDX-License-Identifier: Apache-2.0
//! `postgres.query_view`: parameter validation, normalization and SQL generation.
//!
//! The model never supplies SQL. It supplies a view name, field names and filter values;
//! names are matched **exactly** against the resource allowlist and then emitted as quoted
//! identifiers taken from the configuration, and every value is a bound text parameter cast
//! to the column's type (looked up in `information_schema.columns`). There is no
//! "starts with SELECT" heuristic anywhere (§9.6).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use aipass_types::ApiError;
use aipass_types::models::{GrantScope, PostgresScope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::config::{PgConfig, ViewConfig, quote_ident, split_view};
use crate::errors;

/// Operation name.
pub const QUERY_VIEW: &str = "postgres.query_view";
/// Max selected fields.
pub const MAX_FIELDS: usize = 64;
/// Max filters.
pub const MAX_FILTERS: usize = 16;
/// Max order-by terms.
pub const MAX_ORDER_BY: usize = 4;
/// Max values in `in`.
pub const MAX_IN_VALUES: usize = 100;
/// Max length of a text value.
pub const MAX_VALUE_CHARS: usize = 1024;
/// Max `period_days`.
pub const MAX_PERIOD_DAYS: u64 = 3660;

/// Filter operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    /// `=`
    Eq,
    /// `<>`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Lte,
    /// `>`
    Gt,
    /// `>=`
    Gte,
    /// `IN (…)`
    In,
    /// `BETWEEN a AND b`
    Between,
    /// `IS NULL`
    IsNull,
    /// `IS NOT NULL`
    NotNull,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Ascending.
    #[default]
    Asc,
    /// Descending.
    Desc,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterInput {
    field: String,
    op: FilterOp,
    #[serde(default)]
    value: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderInput {
    field: String,
    #[serde(default)]
    direction: Direction,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryViewInput {
    view: String,
    fields: Vec<String>,
    #[serde(default)]
    filters: Vec<FilterInput>,
    #[serde(default)]
    order_by: Vec<OrderInput>,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    period_days: Option<u64>,
}

/// A normalized filter value (always text; bound as a parameter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterValue {
    /// Scalar.
    One(String),
    /// `in` / `between`.
    Many(Vec<String>),
}

/// A normalized filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Field.
    pub field: String,
    /// Operator.
    pub op: FilterOp,
    /// Value(s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<FilterValue>,
}

/// A normalized order-by term.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// Field.
    pub field: String,
    /// Direction.
    pub direction: Direction,
}

/// Normalized `postgres.query_view` parameters (these are what the digest covers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryView {
    /// `schema.view`.
    pub view: String,
    /// Selected fields (de-duplicated, request order kept).
    pub fields: Vec<String>,
    /// Filters.
    pub filters: Vec<Filter>,
    /// Ordering.
    pub order_by: Vec<Order>,
    /// Requested row limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Only rows whose `date_field` is within the last N days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_days: Option<u64>,
}

/// JSON Schema of the parameters (published in `OperationSpec`).
pub fn parameters_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["view", "fields"],
        "properties": {
            "view": {"type": "string", "description": "Allowlisted view, e.g. analytics.subscription_daily"},
            "fields": {"type": "array", "minItems": 1, "maxItems": MAX_FIELDS, "items": {"type": "string"}},
            "filters": {"type": "array", "maxItems": MAX_FILTERS, "items": {
                "type": "object", "additionalProperties": false, "required": ["field", "op"],
                "properties": {
                    "field": {"type": "string"},
                    "op": {"type": "string", "enum": ["eq","ne","lt","lte","gt","gte","in","between","is_null","not_null"]},
                    "value": {"description": "scalar; array for in (≤100) / between (exactly 2); omitted for is_null / not_null"}
                }
            }},
            "order_by": {"type": "array", "maxItems": MAX_ORDER_BY, "items": {
                "type": "object", "additionalProperties": false, "required": ["field"],
                "properties": {"field": {"type": "string"}, "direction": {"type": "string", "enum": ["asc", "desc"]}}
            }},
            "limit": {"type": "integer", "minimum": 1, "maximum": super::config::HARD_MAX_ROWS},
            "period_days": {"type": "integer", "minimum": 1, "maximum": MAX_PERIOD_DAYS}
        }
    })
}

fn scalar_text(v: &Value) -> Result<String, &'static str> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return Err("value must be a string, number or boolean"),
    };
    if s.chars().count() > MAX_VALUE_CHARS {
        return Err("value too long");
    }
    if s.contains('\0') {
        return Err("value contains NUL");
    }
    Ok(s)
}

/// Validate a filter's value against its operator and convert it to text.
pub fn filter_value_text(
    op: FilterOp,
    value: Option<&Value>,
) -> Result<Option<FilterValue>, &'static str> {
    match op {
        FilterOp::IsNull | FilterOp::NotNull => match value {
            None | Some(Value::Null) => Ok(None),
            _ => Err("is_null / not_null take no value"),
        },
        FilterOp::In => {
            let arr = value
                .and_then(Value::as_array)
                .ok_or("in needs an array value")?;
            if arr.is_empty() || arr.len() > MAX_IN_VALUES {
                return Err("in needs 1..=100 values");
            }
            Ok(Some(FilterValue::Many(
                arr.iter().map(scalar_text).collect::<Result<_, _>>()?,
            )))
        }
        FilterOp::Between => {
            let arr = value
                .and_then(Value::as_array)
                .ok_or("between needs [low, high]")?;
            if arr.len() != 2 {
                return Err("between needs exactly two values");
            }
            Ok(Some(FilterValue::Many(
                arr.iter().map(scalar_text).collect::<Result<_, _>>()?,
            )))
        }
        _ => {
            let v = value.ok_or("a value is required")?;
            Ok(Some(FilterValue::One(scalar_text(v)?)))
        }
    }
}

fn not_allowed_view() -> ApiError {
    errors::scope_denied(
        "该视图不在本资源允许的范围内",
        "That view is not allowlisted for this resource.",
    )
}

fn not_allowed_field(field: &str) -> ApiError {
    let _ = field;
    errors::scope_denied(
        "请求的字段不在该视图允许的字段范围内",
        "A requested field is not allowlisted for this view.",
    )
}

/// Validate and normalize parameters; returns the normalized params and required scope.
pub fn normalize(cfg: &PgConfig, params: &Value) -> Result<(QueryView, GrantScope), ApiError> {
    let input: QueryViewInput = serde_json::from_value(params.clone()).map_err(|_| {
        errors::invalid(
            "参数格式无效（需要 view、fields，可选 filters、order_by、limit、period_days）",
            "Invalid parameters (expected view, fields and optional filters, order_by, limit, period_days).",
        )
    })?;
    let view_cfg: &ViewConfig = cfg.view(&input.view).ok_or_else(not_allowed_view)?;
    let allowed: BTreeSet<&str> = view_cfg.fields.iter().map(String::as_str).collect();

    if input.fields.is_empty() || input.fields.len() > MAX_FIELDS {
        return Err(errors::invalid_param(
            "fields",
            "fields 需要 1 到 64 个字段",
            "fields needs 1 to 64 entries.",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut fields = Vec::new();
    for f in input.fields {
        if !allowed.contains(f.as_str()) {
            return Err(not_allowed_field(&f));
        }
        if seen.insert(f.clone()) {
            fields.push(f);
        }
    }

    if input.filters.len() > MAX_FILTERS {
        return Err(errors::invalid_param(
            "filters",
            "过滤条件过多",
            "Too many filters.",
        ));
    }
    let mut filters = Vec::new();
    for f in input.filters {
        if !allowed.contains(f.field.as_str()) {
            return Err(not_allowed_field(&f.field));
        }
        let value = filter_value_text(f.op, f.value.as_ref()).map_err(|_| {
            errors::invalid_param(
                "filters.value",
                "过滤条件的取值与运算符不匹配",
                "A filter value does not fit its operator.",
            )
        })?;
        filters.push(Filter {
            field: f.field,
            op: f.op,
            value,
        });
    }

    if input.order_by.len() > MAX_ORDER_BY {
        return Err(errors::invalid_param(
            "order_by",
            "排序条件过多",
            "Too many order_by terms.",
        ));
    }
    let mut order_by = Vec::new();
    for o in input.order_by {
        if !allowed.contains(o.field.as_str()) {
            return Err(not_allowed_field(&o.field));
        }
        order_by.push(Order {
            field: o.field,
            direction: o.direction,
        });
    }

    if let Some(l) = input.limit
        && !(1..=super::config::HARD_MAX_ROWS).contains(&l)
    {
        return Err(errors::invalid_param(
            "limit",
            "limit 超出范围",
            "limit is out of range.",
        ));
    }
    if let Some(p) = input.period_days {
        if !(1..=MAX_PERIOD_DAYS).contains(&p) {
            return Err(errors::invalid_param(
                "period_days",
                "period_days 超出范围",
                "period_days is out of range.",
            ));
        }
        if view_cfg.date_field.is_none() {
            return Err(errors::invalid_param(
                "period_days",
                "该视图未配置日期字段，不能按天数筛选",
                "This view has no date_field; period_days is not available.",
            ));
        }
    }

    let mut scope_fields: BTreeSet<String> = fields.iter().cloned().collect();
    scope_fields.extend(filters.iter().map(|f| f.field.clone()));
    scope_fields.extend(order_by.iter().map(|o| o.field.clone()));
    let mut views = BTreeMap::new();
    views.insert(input.view.clone(), scope_fields.into_iter().collect());
    let scope = GrantScope {
        operations: vec![QUERY_VIEW.to_owned()],
        postgres: Some(PostgresScope { views }),
        github: None,
        http_api: None,
    };
    Ok((
        QueryView {
            view: input.view,
            fields,
            filters,
            order_by,
            limit: input.limit,
            period_days: input.period_days,
        },
        scope,
    ))
}

/// Column type as reported by `information_schema.columns`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnType {
    /// `udt_schema`.
    pub udt_schema: String,
    /// `udt_name`.
    pub udt_name: String,
}

impl ColumnType {
    /// Type expression for a cast: `"pg_catalog"."int4"`.
    pub fn cast_expr(&self) -> String {
        format!(
            "{}.{}",
            quote_ident(&self.udt_schema),
            quote_ident(&self.udt_name)
        )
    }
}

/// Generated statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltQuery {
    /// SQL text (identifiers quoted, values as `$n`).
    pub sql: String,
    /// Text parameters.
    pub params: Vec<String>,
}

struct Builder {
    params: Vec<String>,
}

impl Builder {
    fn bind(&mut self, value: &str, ty: &ColumnType) -> String {
        self.params.push(value.to_owned());
        format!("(${}::text)::{}", self.params.len(), ty.cast_expr())
    }

    fn condition(
        &mut self,
        field: &str,
        op: FilterOp,
        value: Option<&FilterValue>,
        types: &HashMap<String, ColumnType>,
    ) -> Result<String, ApiError> {
        let ty = types.get(field).ok_or_else(field_invisible)?;
        let col = quote_ident(field);
        let one = |b: &mut Builder| -> Result<String, ApiError> {
            match value {
                Some(FilterValue::One(v)) => Ok(b.bind(v, ty)),
                _ => Err(errors::invalid(
                    "过滤条件缺少取值",
                    "A filter is missing its value.",
                )),
            }
        };
        Ok(match op {
            FilterOp::Eq => format!("{col} = {}", one(self)?),
            FilterOp::Ne => format!("{col} <> {}", one(self)?),
            FilterOp::Lt => format!("{col} < {}", one(self)?),
            FilterOp::Lte => format!("{col} <= {}", one(self)?),
            FilterOp::Gt => format!("{col} > {}", one(self)?),
            FilterOp::Gte => format!("{col} >= {}", one(self)?),
            FilterOp::IsNull => format!("{col} IS NULL"),
            FilterOp::NotNull => format!("{col} IS NOT NULL"),
            FilterOp::In => match value {
                Some(FilterValue::Many(vs)) if !vs.is_empty() => {
                    let items: Vec<String> = vs.iter().map(|v| self.bind(v, ty)).collect();
                    format!("{col} IN ({})", items.join(", "))
                }
                _ => {
                    return Err(errors::invalid(
                        "in 需要取值列表",
                        "in needs a list of values.",
                    ));
                }
            },
            FilterOp::Between => match value {
                Some(FilterValue::Many(vs)) if vs.len() == 2 => {
                    let a = self.bind(&vs[0], ty);
                    let b = self.bind(&vs[1], ty);
                    format!("{col} BETWEEN {a} AND {b}")
                }
                _ => {
                    return Err(errors::invalid(
                        "between 需要两个取值",
                        "between needs exactly two values.",
                    ));
                }
            },
        })
    }
}

fn field_invisible() -> ApiError {
    errors::scope_denied(
        "数据库账号无法读取请求的字段或视图",
        "The database role cannot read the requested view or field.",
    )
    .with_detail("reason", "not_visible_to_role")
}

/// Build the statement. `fetch_rows` is the `LIMIT` (row cap + 1 to detect truncation).
pub fn build(
    q: &QueryView,
    view_cfg: &ViewConfig,
    types: &HashMap<String, ColumnType>,
    fetch_rows: u64,
) -> Result<BuiltQuery, ApiError> {
    let (schema, view) = split_view(&q.view).ok_or_else(|| errors::bad_config("allowed_views"))?;
    let mut b = Builder { params: Vec::new() };
    for f in &q.fields {
        if !types.contains_key(f) {
            return Err(field_invisible());
        }
    }
    let select: Vec<String> = q.fields.iter().map(|f| quote_ident(f)).collect();
    let mut conds = Vec::new();
    for f in &view_cfg.row_filter {
        let v = filter_value_text(f.op, f.value.as_ref())
            .map_err(|_| errors::bad_config("allowed_views.row_filter"))?;
        conds.push(b.condition(&f.field, f.op, v.as_ref(), types)?);
    }
    for f in &q.filters {
        conds.push(b.condition(&f.field, f.op, f.value.as_ref(), types)?);
    }
    if let Some(days) = q.period_days {
        let date_field = view_cfg
            .date_field
            .as_deref()
            .ok_or_else(|| errors::bad_config("date_field"))?;
        if !types.contains_key(date_field) {
            return Err(field_invisible());
        }
        b.params.push(days.to_string());
        conds.push(format!(
            "{} >= (CURRENT_DATE - (${}::text)::integer)",
            quote_ident(date_field),
            b.params.len()
        ));
    }
    let mut sql = format!(
        "SELECT pg_catalog.row_to_json(t)::text FROM (SELECT {} FROM {}.{}",
        select.join(", "),
        quote_ident(schema),
        quote_ident(view)
    );
    if !conds.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conds.join(" AND "));
    }
    if !q.order_by.is_empty() {
        let terms: Vec<String> = q
            .order_by
            .iter()
            .map(|o| {
                format!(
                    "{} {}",
                    quote_ident(&o.field),
                    match o.direction {
                        Direction::Asc => "ASC NULLS LAST",
                        Direction::Desc => "DESC NULLS LAST",
                    }
                )
            })
            .collect();
        sql.push_str(" ORDER BY ");
        sql.push_str(&terms.join(", "));
    }
    sql.push_str(&format!(" LIMIT {fetch_rows}) AS t"));
    Ok(BuiltQuery {
        sql,
        params: b.params,
    })
}

/// SQL that lists the visible columns of a relation.
pub const COLUMNS_SQL: &str = "SELECT column_name::text, udt_schema::text, udt_name::text \
     FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> PgConfig {
        PgConfig::parse(&json!({
            "host":"h","dbname":"d",
            "allowed_views":{"analytics.subscription_daily":{
                "fields":["day","plan","subscriptions"],"date_field":"day",
                "row_filter":[{"field":"tenant_id","op":"eq","value":"lure"}]}}
        }))
        .unwrap()
    }

    fn types() -> HashMap<String, ColumnType> {
        let t = |n: &str| ColumnType {
            udt_schema: "pg_catalog".into(),
            udt_name: n.into(),
        };
        HashMap::from([
            ("day".to_owned(), t("date")),
            ("plan".to_owned(), t("text")),
            ("subscriptions".to_owned(), t("int4")),
            ("tenant_id".to_owned(), t("text")),
        ])
    }

    #[test]
    fn normalize_and_build() {
        let c = cfg();
        let (q, scope) = normalize(
            &c,
            &json!({"view":"analytics.subscription_daily","fields":["day","plan","day"],
                    "filters":[{"field":"subscriptions","op":"gte","value":2},
                               {"field":"plan","op":"in","value":["pro","team"]}],
                    "order_by":[{"field":"day","direction":"desc"}],"period_days":30}),
        )
        .unwrap();
        assert_eq!(q.fields, vec!["day", "plan"]);
        assert_eq!(
            scope.postgres.unwrap().views["analytics.subscription_daily"],
            vec!["day", "plan", "subscriptions"]
        );
        let b = build(&q, c.view(&q.view).unwrap(), &types(), 11).unwrap();
        assert_eq!(
            b.sql,
            "SELECT pg_catalog.row_to_json(t)::text FROM (SELECT \"day\", \"plan\" FROM \"analytics\".\"subscription_daily\" \
             WHERE \"tenant_id\" = ($1::text)::\"pg_catalog\".\"text\" AND \"subscriptions\" >= ($2::text)::\"pg_catalog\".\"int4\" \
             AND \"plan\" IN (($3::text)::\"pg_catalog\".\"text\", ($4::text)::\"pg_catalog\".\"text\") \
             AND \"day\" >= (CURRENT_DATE - ($5::text)::integer) ORDER BY \"day\" DESC NULLS LAST LIMIT 11) AS t"
        );
        assert_eq!(b.params, vec!["lure", "2", "pro", "team", "30"]);
        // normalization is idempotent
        let again = normalize(&c, &serde_json::to_value(&q).unwrap()).unwrap().0;
        assert_eq!(again, q);
    }

    #[test]
    fn injection_attempts_are_rejected_or_bound() {
        let c = cfg();
        for bad in [
            json!({"view":"analytics.subscription_daily; DROP TABLE x","fields":["day"]}),
            json!({"view":"shop.customers","fields":["email"]}),
            json!({"view":"pg_read_file('/etc/passwd')","fields":["day"]}),
            json!({"view":"analytics.subscription_daily","fields":["day\" FROM shop.customers --"]}),
            json!({"view":"analytics.subscription_daily","fields":["pg_read_file('/etc/passwd')"]}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"filters":[{"field":"1=1 OR true","op":"eq","value":1}]}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"filters":[{"field":"tenant_id","op":"eq","value":"other"}]}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"order_by":[{"field":"random()"}]}),
        ] {
            let e = normalize(&c, &bad).unwrap_err();
            assert_eq!(e.code, aipass_types::ErrorCode::ScopeDenied, "{bad}");
        }
        for bad in [
            json!({"view":"analytics.subscription_daily","fields":["day"],"filters":[{"field":"plan","op":"like","value":"%"}]}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"order_by":[{"field":"day","direction":"desc; DROP"}]}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"limit":"1; DROP"}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"period_days":"30 OR 1=1"}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"sql":"SELECT 1"}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"filters":[{"field":"plan","op":"eq","value":{"a":1}}]}),
            json!({"view":"analytics.subscription_daily","fields":["day"],"filters":[{"field":"plan","op":"eq","value":"a\u{0}b"}]}),
        ] {
            let e = normalize(&c, &bad).unwrap_err();
            assert_eq!(e.code, aipass_types::ErrorCode::InvalidRequest, "{bad}");
        }
        let (q, _) = normalize(
            &c,
            &json!({"view":"analytics.subscription_daily","fields":["day"],
                    "filters":[{"field":"plan","op":"eq","value":"x'); SELECT pg_read_file('/etc/passwd'); --"}]}),
        )
        .unwrap();
        let b = build(&q, c.view(&q.view).unwrap(), &types(), 2).unwrap();
        assert!(!b.sql.contains("pg_read_file"));
        assert_eq!(b.params[1], "x'); SELECT pg_read_file('/etc/passwd'); --");
    }
}
