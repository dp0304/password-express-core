// SPDX-License-Identifier: Apache-2.0
//! Minimal **format-preserving** JSON / JSONC editor.
//!
//! Host configs are user files (VS Code's `mcp.json` is JSONC with comments and trailing
//! commas; `~/.claude.json` is a large machine-written file). Re-serializing them would
//! reorder keys, drop comments and churn whitespace, so this module parses the text into a
//! span tree and edits **only the bytes of our member** (`<container>.aipass`). Everything
//! else stays byte-identical, and removing a member we inserted restores the original text.

use std::fmt::Write as _;

/// Parse error with byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset.
    pub offset: usize,
    /// Message.
    pub message: String,
}

impl ParseError {
    /// 1-based (line, column) of the offset in `src`.
    pub fn line_col(&self, src: &str) -> (usize, usize) {
        let upto = &src[..self.offset.min(src.len())];
        let line = upto.matches('\n').count() + 1;
        let col = upto.rsplit('\n').next().map(|l| l.chars().count()).unwrap_or(0) + 1;
        (line, col)
    }
}

/// A parsed value with its byte span `[start, end)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// Kind.
    pub kind: Kind,
    /// Start offset (first byte of the value).
    pub start: usize,
    /// End offset (one past the last byte).
    pub end: usize,
}

/// Value kinds.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// Object members in source order.
    Object(Vec<Member>),
    /// Array items.
    Array(Vec<Node>),
    /// Decoded string.
    Str(String),
    /// Number (raw text).
    Num(String),
    /// Boolean.
    Bool(bool),
    /// Null.
    Null,
}

/// An object member.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// Decoded key.
    pub key: String,
    /// Offset of the key's opening quote.
    pub key_start: usize,
    /// Value.
    pub value: Node,
    /// Offset of the comma following the value, if any.
    pub comma: Option<usize>,
}

impl Node {
    /// Object members, if an object.
    pub fn members(&self) -> Option<&[Member]> {
        match &self.kind {
            Kind::Object(m) => Some(m),
            _ => None,
        }
    }

    /// Last member named `key`.
    pub fn get(&self, key: &str) -> Option<&Member> {
        self.members()?.iter().rev().find(|m| m.key == key)
    }

    /// Convert to `serde_json::Value`.
    pub fn to_value(&self) -> serde_json::Value {
        use serde_json::Value;
        match &self.kind {
            Kind::Object(ms) => {
                let mut map = serde_json::Map::new();
                for m in ms {
                    map.insert(m.key.clone(), m.value.to_value());
                }
                Value::Object(map)
            }
            Kind::Array(items) => Value::Array(items.iter().map(Node::to_value).collect()),
            Kind::Str(s) => Value::String(s.clone()),
            Kind::Num(n) => serde_json::from_str(n).unwrap_or(Value::Null),
            Kind::Bool(b) => Value::Bool(*b),
            Kind::Null => Value::Null,
        }
    }
}

struct Parser<'a> {
    src: &'a str,
    b: &'a [u8],
    pos: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 256;

impl<'a> Parser<'a> {
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            offset: self.pos,
            message: msg.into(),
        })
    }

    fn skip_ws(&mut self) -> Result<(), ParseError> {
        loop {
            match self.b.get(self.pos) {
                Some(b' ' | b'\t' | b'\n' | b'\r') => self.pos += 1,
                Some(b'/') => match self.b.get(self.pos + 1) {
                    Some(b'/') => {
                        while let Some(&c) = self.b.get(self.pos) {
                            if c == b'\n' {
                                break;
                            }
                            self.pos += 1;
                        }
                    }
                    Some(b'*') => {
                        let start = self.pos;
                        self.pos += 2;
                        loop {
                            match self.b.get(self.pos) {
                                None => {
                                    self.pos = start;
                                    return self.err("unterminated block comment");
                                }
                                Some(b'*') if self.b.get(self.pos + 1) == Some(&b'/') => {
                                    self.pos += 2;
                                    break;
                                }
                                Some(_) => self.pos += 1,
                            }
                        }
                    }
                    _ => return self.err("unexpected '/'"),
                },
                _ => return Ok(()),
            }
        }
    }

    fn value(&mut self) -> Result<Node, ParseError> {
        self.skip_ws()?;
        let start = self.pos;
        match self.b.get(self.pos) {
            None => self.err("unexpected end of input"),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => {
                let s = self.string()?;
                Ok(Node {
                    kind: Kind::Str(s),
                    start,
                    end: self.pos,
                })
            }
            Some(b't') => self.literal("true", Kind::Bool(true)),
            Some(b'f') => self.literal("false", Kind::Bool(false)),
            Some(b'n') => self.literal("null", Kind::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                while let Some(&c) = self.b.get(self.pos) {
                    if c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E') {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                let raw = &self.src[start..self.pos];
                if serde_json::from_str::<serde_json::Number>(raw).is_err() {
                    self.pos = start;
                    return self.err("invalid number");
                }
                Ok(Node {
                    kind: Kind::Num(raw.to_owned()),
                    start,
                    end: self.pos,
                })
            }
            Some(_) => self.err("unexpected character"),
        }
    }

    fn literal(&mut self, word: &str, kind: Kind) -> Result<Node, ParseError> {
        let start = self.pos;
        if self.src[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(Node {
                kind,
                start,
                end: self.pos,
            })
        } else {
            self.err("invalid literal")
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        // at '"'
        let start = self.pos;
        self.pos += 1;
        let mut out = String::new();
        loop {
            let Some(&c) = self.b.get(self.pos) else {
                self.pos = start;
                return self.err("unterminated string");
            };
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let Some(&e) = self.b.get(self.pos + 1) else {
                        return self.err("bad escape");
                    };
                    self.pos += 2;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.pos) == Some(&b'\\')
                                    && self.b.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return self.err("invalid surrogate pair");
                                    }
                                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                } else {
                                    return self.err("lone surrogate");
                                }
                            } else {
                                hi
                            };
                            match char::from_u32(cp) {
                                Some(ch) => out.push(ch),
                                None => return self.err("invalid code point"),
                            }
                        }
                        _ => return self.err("bad escape"),
                    }
                }
                c if c < 0x20 => return self.err("control character in string"),
                _ => {
                    // copy one UTF-8 char
                    let ch_len = utf8_len(c);
                    let end = (self.pos + ch_len).min(self.b.len());
                    out.push_str(&self.src[self.pos..end]);
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let s = self.src.get(self.pos..self.pos + 4).unwrap_or("");
        let v = u32::from_str_radix(s, 16).or_else(|_| self.err("bad \\u escape"))?;
        if s.len() != 4 {
            return self.err("bad \\u escape");
        }
        self.pos += 4;
        Ok(v)
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.err("nesting too deep");
        }
        Ok(())
    }

    fn object(&mut self) -> Result<Node, ParseError> {
        self.enter()?;
        let start = self.pos;
        self.pos += 1; // '{'
        let mut members = Vec::new();
        loop {
            self.skip_ws()?;
            match self.b.get(self.pos) {
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                Some(b'"') => {
                    let key_start = self.pos;
                    let key = self.string()?;
                    self.skip_ws()?;
                    if self.b.get(self.pos) != Some(&b':') {
                        return self.err("expected ':'");
                    }
                    self.pos += 1;
                    let value = self.value()?;
                    self.skip_ws()?;
                    let comma = if self.b.get(self.pos) == Some(&b',') {
                        let c = self.pos;
                        self.pos += 1;
                        Some(c)
                    } else {
                        None
                    };
                    let had_comma = comma.is_some();
                    members.push(Member {
                        key,
                        key_start,
                        value,
                        comma,
                    });
                    if !had_comma {
                        self.skip_ws()?;
                        if self.b.get(self.pos) != Some(&b'}') {
                            return self.err("expected ',' or '}'");
                        }
                    }
                }
                None => return self.err("unterminated object"),
                _ => return self.err("expected a string key"),
            }
        }
        self.depth -= 1;
        Ok(Node {
            kind: Kind::Object(members),
            start,
            end: self.pos,
        })
    }

    fn array(&mut self) -> Result<Node, ParseError> {
        self.enter()?;
        let start = self.pos;
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws()?;
            match self.b.get(self.pos) {
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                None => return self.err("unterminated array"),
                _ => {
                    items.push(self.value()?);
                    self.skip_ws()?;
                    match self.b.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {}
                        _ => return self.err("expected ',' or ']'"),
                    }
                }
            }
        }
        self.depth -= 1;
        Ok(Node {
            kind: Kind::Array(items),
            start,
            end: self.pos,
        })
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Parse a JSON(C) document. `Ok(None)` for a blank document (whitespace/comments only).
pub fn parse(src: &str) -> Result<Option<Node>, ParseError> {
    let mut p = Parser {
        src,
        b: src.as_bytes(),
        pos: 0,
        depth: 0,
    };
    if src.starts_with('\u{FEFF}') {
        p.pos = 3;
    }
    p.skip_ws()?;
    if p.pos >= src.len() {
        return Ok(None);
    }
    let v = p.value()?;
    p.skip_ws()?;
    if p.pos != src.len() {
        return p.err("trailing characters after the document");
    }
    Ok(Some(v))
}

/// An insertion-ordered JSON value used to render entries (key order matters for humans).
#[derive(Debug, Clone, PartialEq)]
pub enum Ordered {
    /// Object.
    Obj(Vec<(String, Ordered)>),
    /// Array.
    Arr(Vec<Ordered>),
    /// String.
    Str(String),
}

impl Ordered {
    /// Render like `JSON.stringify(v, null, unit)` with continuation lines prefixed by `base`.
    pub fn render(&self, unit: &str, base: &str, nl: &str) -> String {
        let mut out = String::new();
        self.render_into(&mut out, unit, base, nl);
        out
    }

    fn render_into(&self, out: &mut String, unit: &str, base: &str, nl: &str) {
        match self {
            Ordered::Str(s) => out.push_str(&json_string(s)),
            Ordered::Arr(items) if items.is_empty() => out.push_str("[]"),
            Ordered::Obj(items) if items.is_empty() => out.push_str("{}"),
            Ordered::Arr(items) => {
                out.push('[');
                let inner = format!("{base}{unit}");
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{nl}{inner}");
                    it.render_into(out, unit, &inner, nl);
                }
                let _ = write!(out, "{nl}{base}]");
            }
            Ordered::Obj(items) => {
                out.push('{');
                let inner = format!("{base}{unit}");
                for (i, (k, v)) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    let _ = write!(out, "{nl}{inner}{}: ", json_string(k));
                    v.render_into(out, unit, &inner, nl);
                }
                let _ = write!(out, "{nl}{base}}}");
            }
        }
    }

    /// Single-line rendering (`{"a": "b"}`).
    pub fn render_compact(&self) -> String {
        match self {
            Ordered::Str(s) => json_string(s),
            Ordered::Arr(items) => format!(
                "[{}]",
                items.iter().map(Ordered::render_compact).collect::<Vec<_>>().join(", ")
            ),
            Ordered::Obj(items) => format!(
                "{{{}}}",
                items
                    .iter()
                    .map(|(k, v)| format!("{}: {}", json_string(k), v.render_compact()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Convert to `serde_json::Value`.
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            Ordered::Str(s) => serde_json::Value::String(s.clone()),
            Ordered::Arr(a) => serde_json::Value::Array(a.iter().map(Ordered::to_value).collect()),
            Ordered::Obj(o) => serde_json::Value::Object(
                o.iter().map(|(k, v)| (k.clone(), v.to_value())).collect(),
            ),
        }
    }
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Leading whitespace of the line containing `offset`.
fn line_indent(src: &str, offset: usize) -> &str {
    let line_start = src[..offset].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let rest = &src[line_start..];
    let n = rest.len() - rest.trim_start_matches([' ', '\t']).len();
    &rest[..n]
}

/// Indent unit of the document: the leading whitespace of the first indented line (default
/// two spaces).
pub fn detect_indent(src: &str) -> String {
    for line in src.lines() {
        let trimmed = line.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.len() == line.len() {
            continue;
        }
        let ws = &line[..line.len() - trimmed.len()];
        if ws.starts_with('\t') {
            return "\t".into();
        }
        return ws.to_owned();
    }
    "  ".into()
}

/// Newline style of the document.
pub fn detect_newline(src: &str) -> &'static str {
    if src.contains("\r\n") { "\r\n" } else { "\n" }
}

/// Edit error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// The document does not parse.
    Parse(ParseError),
    /// The document root, or the container, is not an object.
    NotAnObject(String),
}

impl From<ParseError> for EditError {
    fn from(e: ParseError) -> Self {
        EditError::Parse(e)
    }
}

fn splice(src: &str, start: usize, end: usize, with: &str) -> String {
    let mut s = String::with_capacity(src.len() + with.len());
    s.push_str(&src[..start]);
    s.push_str(with);
    s.push_str(&src[end..]);
    s
}

/// Insert `key: value` as the last member of object `obj`.
fn insert_member(src: &str, obj: &Node, key: &str, value: &Ordered) -> String {
    let unit = detect_indent(src);
    let nl = detect_newline(src);
    let members = obj.members().unwrap_or(&[]);
    let multiline = src[obj.start..obj.end].contains('\n');
    match members.last() {
        Some(last) if multiline => {
            let indent = line_indent(src, last.key_start).to_owned();
            let text = format!(
                ",{nl}{indent}{}: {}",
                json_string(key),
                value.render(&unit, &indent, nl)
            );
            splice(src, last.value.end, last.value.end, &text)
        }
        Some(last) => {
            let text = format!(", {}: {}", json_string(key), value.render_compact());
            splice(src, last.value.end, last.value.end, &text)
        }
        None => {
            let outer = line_indent(src, obj.start).to_owned();
            let inner = format!("{outer}{unit}");
            let interior = &src[obj.start + 1..obj.end - 1];
            let kv = format!(
                "{}: {}",
                json_string(key),
                value.render(&unit, &inner, nl)
            );
            if interior.trim().is_empty() {
                splice(
                    src,
                    obj.start + 1,
                    obj.end - 1,
                    &format!("{nl}{inner}{kv}{nl}{outer}"),
                )
            } else {
                // keep comments that live inside the empty object
                splice(src, obj.start + 1, obj.start + 1, &format!("{nl}{inner}{kv}"))
            }
        }
    }
}

/// Remove member `idx` of object `obj`.
fn remove_member(src: &str, obj: &Node, idx: usize) -> String {
    let members = obj.members().unwrap_or(&[]);
    let m = &members[idx];
    if idx > 0 {
        let prev = &members[idx - 1];
        let from = prev.comma.unwrap_or(prev.value.end);
        return splice(src, from, m.value.end, "");
    }
    if let Some(next) = members.get(1) {
        return splice(src, m.key_start, next.key_start, "");
    }
    // only member: also drop the whitespace between '{' and the key (inverse of insertion)
    let end = m.comma.map(|c| c + 1).unwrap_or(m.value.end);
    let from = if src[obj.start + 1..m.key_start].trim().is_empty() {
        obj.start + 1
    } else {
        m.key_start
    };
    let out = splice(src, from, end, "");
    let open = obj.start + 1;
    let close = obj.end - 1 - (end - from);
    if out[open..close].trim().is_empty() {
        splice(&out, open, close, "")
    } else {
        out
    }
}

/// Look up `root.<container>.<key>`.
pub fn get_member(src: &str, container: &str, key: &str) -> Result<Option<serde_json::Value>, EditError> {
    let Some(root) = parse(src)? else {
        return Ok(None);
    };
    let Some(c) = root.get(container) else {
        return Ok(None);
    };
    Ok(c.value.get(key).map(|m| m.value.to_value()))
}

/// Set `root.<container>.<key> = value`, touching only those bytes.
pub fn upsert(src: &str, container: &str, key: &str, value: &Ordered) -> Result<String, EditError> {
    let Some(root) = parse(src)? else {
        // blank file: write a fresh document (keeping any leading comments)
        let nl = detect_newline(src);
        let unit = "  ";
        let doc = Ordered::Obj(vec![(
            container.to_owned(),
            Ordered::Obj(vec![(key.to_owned(), value.clone())]),
        )]);
        let mut out = src.trim_end().to_owned();
        if !out.is_empty() {
            out.push_str(nl);
        }
        out.push_str(&doc.render(unit, "", nl));
        out.push_str(nl);
        return Ok(out);
    };
    if root.members().is_none() {
        return Err(EditError::NotAnObject("the document root".into()));
    }
    match root.get(container) {
        None => Ok(insert_member(
            src,
            &root,
            container,
            &Ordered::Obj(vec![(key.to_owned(), value.clone())]),
        )),
        Some(c) => {
            if c.value.members().is_none() {
                return Err(EditError::NotAnObject(format!("\"{container}\"")));
            }
            match c.value.get(key) {
                Some(existing) => {
                    let unit = detect_indent(src);
                    let nl = detect_newline(src);
                    let multiline = src[c.value.start..c.value.end].contains('\n');
                    let text = if multiline {
                        let indent = line_indent(src, existing.key_start).to_owned();
                        value.render(&unit, &indent, nl)
                    } else {
                        value.render_compact()
                    };
                    Ok(splice(src, existing.value.start, existing.value.end, &text))
                }
                None => Ok(insert_member(src, &c.value, key, value)),
            }
        }
    }
}

/// Remove every `root.<container>.<key>`; when the container becomes empty it is removed
/// too. `Ok(None)` when there was nothing to remove.
pub fn remove(src: &str, container: &str, key: &str) -> Result<Option<String>, EditError> {
    let mut cur = src.to_owned();
    let mut changed = false;
    while let Some(root) = parse(&cur)? {
        let Some(root_members) = root.members() else {
            return Err(EditError::NotAnObject("the document root".into()));
        };
        let Some(ci) = root_members.iter().rposition(|m| m.key == container) else {
            break;
        };
        let c = &root_members[ci];
        let Some(cm) = c.value.members() else {
            return Err(EditError::NotAnObject(format!("\"{container}\"")));
        };
        let Some(ki) = cm.iter().rposition(|m| m.key == key) else {
            break;
        };
        let m = &cm[ki];
        let m_end = m.comma.map(|x| x + 1).unwrap_or(m.value.end);
        let rest_blank = cm.len() == 1
            && cur[c.value.start + 1..m.key_start].trim().is_empty()
            && cur[m_end..c.value.end - 1].trim().is_empty();
        cur = if rest_blank {
            // the container only held our entry: remove the container as well
            remove_member(&cur, &root, ci)
        } else {
            remove_member(&cur, &c.value, ki)
        };
        changed = true;
    }
    Ok(changed.then_some(cur))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Ordered {
        Ordered::Obj(vec![
            ("command".into(), Ordered::Str("/usr/local/bin/aipass-mcp".into())),
            (
                "args".into(),
                Ordered::Arr(vec![
                    Ordered::Str("stdio".into()),
                    Ordered::Str("--connection".into()),
                    Ordered::Str("conn_01jbz3k6w8a7m2q4t5v9x0y1z4".into()),
                ]),
            ),
        ])
    }

    fn roundtrip(src: &str) -> String {
        let after = upsert(src, "mcpServers", "aipass", &entry()).unwrap();
        let v: serde_json::Value = parse(&after).unwrap().unwrap().to_value();
        assert_eq!(v["mcpServers"]["aipass"]["args"][0], "stdio", "{after}");
        let back = remove(&after, "mcpServers", "aipass").unwrap().unwrap();
        assert_eq!(back, src, "remove must restore the original exactly:\n{after}");
        after
    }

    #[test]
    fn parses_jsonc() {
        let src = "\u{FEFF}// top\n{\n  /* c */ \"a\": [1, 2,], // x\n  \"b\": {\"c\": \"\\u00e9\\ud83d\\ude00\"},\n}\n";
        let v = parse(src).unwrap().unwrap().to_value();
        assert_eq!(v["a"][1], 2);
        assert_eq!(v["b"]["c"], "é😀");
        assert!(parse("{\"a\": }").is_err());
        assert!(parse("{\"a\": 1} x").is_err());
        assert!(parse("{\"a\": \"x").is_err());
        assert!(parse("/* never closed").is_err());
        assert_eq!(parse("  // only a comment\n").unwrap(), None);
        let deep = "[".repeat(300) + &"]".repeat(300);
        assert!(parse(&deep).is_err());
        let e = parse("{\n  \"a\": nope\n}").unwrap_err();
        assert_eq!(e.line_col("{\n  \"a\": nope\n}"), (2, 8));
    }

    #[test]
    fn insert_into_existing_servers_preserves_everything_else() {
        let src = "{\n  \"numStartups\": 3,\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"x\"]\n    }\n  },\n  \"tail\": true\n}\n";
        let after = roundtrip(src);
        assert!(after.starts_with("{\n  \"numStartups\": 3,\n  \"mcpServers\": {\n    \"other\": {\n      \"command\": \"npx\",\n      \"args\": [\"-y\", \"x\"]\n    },\n    \"aipass\": {\n      \"command\": \"/usr/local/bin/aipass-mcp\",\n      \"args\": [\n        \"stdio\","));
        assert!(after.ends_with("  },\n  \"tail\": true\n}\n"));
    }

    #[test]
    fn container_missing_empty_root_blank_file() {
        roundtrip("{\n  \"theme\": \"dark\"\n}\n");
        roundtrip("{}");
        roundtrip("{\n  \"mcpServers\": {\"x\": {\"command\": \"y\"}}\n}");
        let after = upsert("", "mcpServers", "aipass", &entry()).unwrap();
        assert!(after.starts_with("{\n  \"mcpServers\": {\n    \"aipass\": {"));
        assert!(after.ends_with("}\n"));
        let back = remove(&after, "mcpServers", "aipass").unwrap().unwrap();
        assert_eq!(back, "{}\n");
    }

    #[test]
    fn jsonc_with_comments_tabs_trailing_commas_and_crlf() {
        roundtrip("{\r\n\t// my servers\r\n\t\"servers\": {\r\n\t\t\"a\": {\"type\": \"stdio\", \"command\": \"x\"}, // keep\r\n\t},\r\n}\r\n");
        let src = "{\r\n\t\"mcpServers\": {\r\n\t\t\"a\": {\"command\": \"x\"},\r\n\t},\r\n}\r\n";
        let after = roundtrip(src);
        assert!(after.contains("\r\n\t\t\"aipass\": {\r\n\t\t\t\"command\""), "{after:?}");
        roundtrip("{\n  \"mcpServers\": {\n    // nothing yet\n  }\n}\n");
    }

    #[test]
    fn update_existing_and_aipass_first_member() {
        let src = "{\n  \"mcpServers\": {\n    \"aipass\": {\"command\": \"/old\"},\n    \"b\": {}\n  }\n}\n";
        let after = upsert(src, "mcpServers", "aipass", &entry()).unwrap();
        assert!(!after.contains("/old"));
        assert!(after.contains("\"b\": {}"));
        let back = remove(&after, "mcpServers", "aipass").unwrap().unwrap();
        assert_eq!(back, "{\n  \"mcpServers\": {\n    \"b\": {}\n  }\n}\n");
        // idempotent upsert
        assert_eq!(upsert(&after, "mcpServers", "aipass", &entry()).unwrap(), after);
        // single-line container
        let one = "{\"mcpServers\": {\"b\": {}}}";
        let a = upsert(one, "mcpServers", "aipass", &entry()).unwrap();
        assert!(a.contains("\"b\": {}, \"aipass\": {\"command\": "));
        assert_eq!(remove(&a, "mcpServers", "aipass").unwrap().unwrap(), one);
        // duplicates are all removed
        let dup = "{\"mcpServers\": {\"aipass\": {}, \"x\": 1, \"aipass\": {}}}";
        let r = remove(dup, "mcpServers", "aipass").unwrap().unwrap();
        assert_eq!(parse(&r).unwrap().unwrap().to_value(), serde_json::json!({"mcpServers": {"x": 1}}));
        assert_eq!(remove("{\"x\": 1}", "mcpServers", "aipass").unwrap(), None);
    }

    #[test]
    fn refuses_non_objects() {
        assert!(matches!(
            upsert("[1]", "mcpServers", "aipass", &entry()),
            Err(EditError::NotAnObject(_))
        ));
        assert!(matches!(
            upsert("{\"mcpServers\": []}", "mcpServers", "aipass", &entry()),
            Err(EditError::NotAnObject(_))
        ));
        assert!(matches!(
            upsert("{\"mcpServers\": ", "mcpServers", "aipass", &entry()),
            Err(EditError::Parse(_))
        ));
    }

    #[test]
    fn get_member_reads_values() {
        let src = "{\"mcpServers\": {\"aipass\": {\"command\": \"/x\", \"args\": [\"stdio\"]}}}";
        let v = get_member(src, "mcpServers", "aipass").unwrap().unwrap();
        assert_eq!(v["command"], "/x");
        assert_eq!(get_member(src, "servers", "aipass").unwrap(), None);
        assert_eq!(get_member("", "servers", "aipass").unwrap(), None);
    }
}
