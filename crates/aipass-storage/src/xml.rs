// SPDX-License-Identifier: Apache-2.0
//! Minimal namespace-agnostic XML tree on top of `quick-xml`, used to read S3
//! ListObjectsV2 / error documents and WebDAV `multistatus` responses.
//!
//! Elements are matched by **local name** (prefixes such as `D:` / `d:` / `lp1:` are
//! ignored), which is how real WebDAV servers differ. DTDs and processing instructions are
//! ignored; only the five predefined entities and character references are resolved, so
//! entity-expansion attacks are not possible.

use quick_xml::Reader;
use quick_xml::events::Event;

/// Maximum nesting depth accepted.
const MAX_DEPTH: usize = 64;

/// An element: local name, child elements and concatenated text content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Element {
    pub name: String,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    /// First direct child with this local name.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All direct children with this local name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Trimmed text of the first direct child with this local name.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.trim())
    }
}

fn local(name: &str) -> String {
    match name.rsplit_once(':') {
        Some((_, l)) => l.to_owned(),
        None => name.to_owned(),
    }
}

fn resolve_entity(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "apos" => Some('\''),
        "quot" => Some('"'),
        _ => None,
    }
}

/// Parse a document into its root element.
pub(crate) fn parse(doc: &str) -> Result<Element, String> {
    let mut reader = Reader::from_str(doc);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                if stack.len() >= MAX_DEPTH {
                    return Err("xml nesting too deep".into());
                }
                stack.push(Element {
                    name: local(e.name().as_ref()),
                    ..Default::default()
                });
            }
            Ok(Event::Empty(e)) => {
                let el = Element {
                    name: local(e.name().as_ref()),
                    ..Default::default()
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => {
                        if root.is_none() {
                            root = Some(el);
                        }
                    }
                }
            }
            Ok(Event::End(_)) => {
                let el = stack.pop().ok_or("unbalanced xml")?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => {
                        if root.is_none() {
                            root = Some(el);
                        }
                    }
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(cur) = stack.last_mut() {
                    cur.text.push_str(&t.xml10_content());
                }
            }
            Ok(Event::CData(t)) => {
                if let Some(cur) = stack.last_mut() {
                    cur.text.push_str(&t.into_inner());
                }
            }
            Ok(Event::GeneralRef(r)) => {
                let ch = match r.resolve_char_ref() {
                    Ok(Some(c)) => c,
                    Ok(None) => resolve_entity(&r).ok_or("unknown xml entity")?,
                    Err(_) => return Err("invalid xml character reference".into()),
                };
                if let Some(cur) = stack.last_mut() {
                    cur.text.push(ch);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err("malformed xml".into()),
        }
    }
    if !stack.is_empty() {
        return Err("truncated xml".into());
    }
    root.ok_or_else(|| "empty xml document".into())
}

/// Escape text for inclusion in an XML element.
#[cfg(test)]
pub(crate) fn escape(s: &str) -> String {
    quick_xml::escape::escape(s).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_and_entities() {
        let doc = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:"><D:response><D:href>/a%20b/</D:href>
<D:propstat><D:prop><D:getetag>&quot;abc&#x22;</D:getetag><lp1:resourcetype xmlns:lp1="DAV:"><D:collection/></lp1:resourcetype></D:prop></D:propstat>
</D:response></D:multistatus>"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "multistatus");
        let r = root.child("response").unwrap();
        assert_eq!(r.child_text("href"), Some("/a%20b/"));
        let prop = r.child("propstat").unwrap().child("prop").unwrap();
        assert_eq!(prop.child_text("getetag"), Some("\"abc\""));
        assert!(
            prop.child("resourcetype")
                .unwrap()
                .child("collection")
                .is_some()
        );
        assert_eq!(escape("<&>"), "&lt;&amp;&gt;");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("").is_err());
        assert!(parse("<a>&unknown;</a>").is_err());
    }
}
