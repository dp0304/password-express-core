// SPDX-License-Identifier: Apache-2.0
//! Codex `config.toml` editing with `toml_edit` (comments, formatting and every other table
//! are preserved): `[mcp_servers.aipass] command = "…", args = […]`.

use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::model::{McpEntry, SERVER_KEY};

/// Container table.
pub const CONTAINER: &str = "mcp_servers";

/// TOML edit failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TomlEditError {
    /// Not valid TOML (line/column + message).
    Parse(String),
    /// `mcp_servers` or `mcp_servers.aipass` exists but is not a table.
    NotATable(String),
}

fn parse(src: &str) -> Result<DocumentMut, TomlEditError> {
    src.parse::<DocumentMut>()
        .map_err(|e| TomlEditError::Parse(e.to_string()))
}

fn args_array(entry: &McpEntry) -> Array {
    let mut a = Array::new();
    for arg in &entry.args {
        a.push(arg.as_str());
    }
    a
}

/// `(command, args)` of an existing entry.
pub type TomlEntry = (Option<String>, Vec<String>);

/// Read `mcp_servers.aipass` → (command, args) if present.
pub fn get_entry(src: &str) -> Result<Option<TomlEntry>, TomlEditError> {
    let doc = parse(src)?;
    let Some(servers) = doc.get(CONTAINER) else {
        return Ok(None);
    };
    let Some(servers) = servers.as_table_like() else {
        return Err(TomlEditError::NotATable(CONTAINER.into()));
    };
    let Some(ours) = servers.get(SERVER_KEY) else {
        return Ok(None);
    };
    let Some(t) = ours.as_table_like() else {
        return Err(TomlEditError::NotATable(format!("{CONTAINER}.{SERVER_KEY}")));
    };
    let command = t.get("command").and_then(Item::as_str).map(str::to_owned);
    let args = t
        .get("args")
        .and_then(Item::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    Ok(Some((command, args)))
}

/// Set `mcp_servers.aipass` to `entry`, editing in place when it exists.
pub fn upsert(src: &str, entry: &McpEntry) -> Result<String, TomlEditError> {
    let mut doc = parse(src)?;
    let root = doc.as_table_mut();
    if !root.contains_key(CONTAINER) {
        let mut t = Table::new();
        t.set_implicit(true);
        root.insert(CONTAINER, Item::Table(t));
    }
    let servers = root
        .get_mut(CONTAINER)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| TomlEditError::NotATable(CONTAINER.into()))?;
    let command = entry.command_str();
    match servers.get_mut(SERVER_KEY) {
        Some(item) => {
            if let Some(t) = item.as_table_mut() {
                // keep the header (position, comments) — replace the keys we own
                let keys: Vec<String> = t.iter().map(|(k, _)| k.to_owned()).collect();
                for k in keys {
                    t.remove(&k);
                }
                t.insert("command", toml_edit::value(command));
                t.insert("args", toml_edit::value(args_array(entry)));
            } else if let Some(it) = item.as_inline_table_mut() {
                let keys: Vec<String> = it.iter().map(|(k, _)| k.to_owned()).collect();
                for k in keys {
                    it.remove(&k);
                }
                it.insert("command", Value::from(command));
                it.insert("args", Value::Array(args_array(entry)));
            } else {
                return Err(TomlEditError::NotATable(format!("{CONTAINER}.{SERVER_KEY}")));
            }
        }
        None => {
            let container = root.get_mut(CONTAINER).ok_or_else(|| TomlEditError::NotATable(CONTAINER.into()))?;
            if let Some(it) = container.as_inline_table_mut() {
                let mut ours = toml_edit::InlineTable::new();
                ours.insert("command", Value::from(command));
                ours.insert("args", Value::Array(args_array(entry)));
                it.insert(SERVER_KEY, Value::InlineTable(ours));
            } else if let Some(t) = container.as_table_mut() {
                let mut ours = Table::new();
                ours.insert("command", toml_edit::value(command));
                ours.insert("args", toml_edit::value(args_array(entry)));
                t.insert(SERVER_KEY, Item::Table(ours));
            } else {
                return Err(TomlEditError::NotATable(CONTAINER.into()));
            }
        }
    }
    let mut out = doc.to_string();
    if !src.is_empty() && src.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Remove `mcp_servers.aipass` (and an implicit, now empty `mcp_servers`). `Ok(None)` when
/// absent.
pub fn remove(src: &str) -> Result<Option<String>, TomlEditError> {
    let mut doc = parse(src)?;
    let root = doc.as_table_mut();
    let Some(servers_item) = root.get_mut(CONTAINER) else {
        return Ok(None);
    };
    let Some(servers) = servers_item.as_table_like_mut() else {
        return Err(TomlEditError::NotATable(CONTAINER.into()));
    };
    if servers.remove(SERVER_KEY).is_none() {
        return Ok(None);
    }
    let drop_container = servers.is_empty()
        && root
            .get(CONTAINER)
            .and_then(Item::as_table)
            .is_some_and(Table::is_implicit);
    if drop_container {
        root.remove(CONTAINER);
    }
    Ok(Some(doc.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipass_types::ConnectionId;

    fn entry() -> McpEntry {
        McpEntry::stdio(
            "/Users/me/.local/bin/aipass-mcp",
            &ConnectionId::parse("conn_01jbz3k6w8a7m2q4t5v9x0y1z4").unwrap(),
        )
        .unwrap()
    }

    fn roundtrip(src: &str) -> String {
        let after = upsert(src, &entry()).unwrap();
        let (cmd, args) = get_entry(&after).unwrap().unwrap();
        assert_eq!(cmd.as_deref(), Some("/Users/me/.local/bin/aipass-mcp"));
        assert_eq!(args, vec!["stdio", "--connection", "conn_01jbz3k6w8a7m2q4t5v9x0y1z4"]);
        let back = remove(&after).unwrap().unwrap();
        assert_eq!(back, src, "after apply:\n{after}");
        after
    }

    #[test]
    fn preserves_comments_and_other_servers() {
        let src = "# Codex config\nmodel = \"gpt-5\" # inline comment\n\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"docs-mcp\"] # keep\n\n[profiles.fast]\nmodel = \"o4-mini\"\n";
        let after = roundtrip(src);
        assert!(after.contains("# Codex config\nmodel = \"gpt-5\" # inline comment\n"));
        assert!(after.contains("args = [\"-y\", \"docs-mcp\"] # keep"));
        assert!(after.contains("[mcp_servers.aipass]\ncommand = \"/Users/me/.local/bin/aipass-mcp\"\nargs = [\"stdio\", \"--connection\", \"conn_01jbz3k6w8a7m2q4t5v9x0y1z4\"]\n"));
        assert!(!after.contains("[mcp_servers]\n"), "no explicit container header: {after}");
    }

    #[test]
    fn empty_and_no_servers() {
        roundtrip("");
        roundtrip("model = \"gpt-5\"\n");
        roundtrip("[mcp_servers]\n# explicit container kept\n");
    }

    #[test]
    fn update_in_place() {
        let src = "[mcp_servers.aipass]\n# ours\ncommand = \"/old/aipass-mcp\"\nargs = [\"stdio\"]\nenv = { X = \"1\" }\n\n[other]\na = 1\n";
        let after = upsert(src, &entry()).unwrap();
        assert!(!after.contains("/old/"));
        assert!(!after.contains("env ="));
        assert!(after.find("[mcp_servers.aipass]").unwrap() < after.find("[other]").unwrap());
        assert_eq!(upsert(&after, &entry()).unwrap(), after, "idempotent");
        let removed = remove(&after).unwrap().unwrap();
        assert!(removed.contains("[other]\na = 1"));
        assert!(!removed.contains("aipass"));
        assert_eq!(remove("a = 1\n").unwrap(), None);
    }

    #[test]
    fn rejects_bad_shapes() {
        assert!(matches!(upsert("mcp_servers = 3\n", &entry()), Err(TomlEditError::NotATable(_))));
        assert!(matches!(upsert("[mcp_servers\n", &entry()), Err(TomlEditError::Parse(_))));
        let inline = "mcp_servers = { aipass = { command = \"/x\" } }\n";
        let after = upsert(inline, &entry()).unwrap();
        assert!(get_entry(&after).unwrap().unwrap().1.len() == 3, "{after}");
    }
}
