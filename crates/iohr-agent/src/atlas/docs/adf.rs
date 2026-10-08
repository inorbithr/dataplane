//! Atlassian Document Format (the JSON Confluence and Jira store rich text in) to
//! markdown, deterministically. Mentions keep the account id, never the display name;
//! links to other pages of the same site become mentions of their ids.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde_json::Value;

/// Markdown and what it points at.
#[derive(Debug, Default)]
pub struct Adf {
    /// The markdown.
    pub md: String,
    /// Absolute links outside the site's pages.
    pub links: BTreeSet<String>,
    /// Ids of pages of the same site it links to.
    pub mentions: BTreeSet<String>,
}

/// Most nesting followed; deeper content is skipped.
const MAX_DEPTH: usize = 32;

impl Adf {
    /// Renders an ADF document (the parsed `atlas_doc_format` value).
    #[must_use]
    pub fn render(doc: &Value) -> Self {
        let mut a = Self::default();
        a.blocks(doc, 0, "");
        a
    }

    fn content(v: &Value) -> &[Value] {
        v.get("content")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn attr<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
        v.get("attrs").and_then(|a| a.get(k))
    }

    fn blocks(&mut self, v: &Value, depth: usize, indent: &str) {
        if depth > MAX_DEPTH {
            return;
        }
        for n in Self::content(v) {
            self.block(n, depth, indent);
        }
    }

    fn block(&mut self, n: &Value, depth: usize, indent: &str) {
        let ty = n.get("type").and_then(Value::as_str).unwrap_or_default();
        match ty {
            "paragraph" => {
                let t = self.inline(n);
                if !t.trim().is_empty() {
                    let _ = write!(self.md, "{indent}{t}\n\n");
                }
            }
            "heading" => {
                let level = Self::attr(n, "level")
                    .and_then(Value::as_u64)
                    .unwrap_or(1)
                    .clamp(1, 5);
                // The page title is the one level-1 heading.
                let hashes = "#".repeat(usize::try_from(level).unwrap_or(1) + 1);
                let t = self.inline(n);
                let _ = write!(self.md, "{indent}{hashes} {t}\n\n");
            }
            "bulletList" | "orderedList" | "taskList" | "decisionList" => {
                for item in Self::content(n) {
                    let marker = match (ty, item.get("type").and_then(Value::as_str)) {
                        ("orderedList", _) => "1.".to_owned(),
                        (_, Some("taskItem")) => {
                            let done =
                                Self::attr(item, "state").and_then(Value::as_str) == Some("DONE");
                            format!("- [{}]", if done { "x" } else { " " })
                        }
                        (_, Some("decisionItem")) => "- Decision:".to_owned(),
                        _ => "-".to_owned(),
                    };
                    self.list_item(item, &marker, depth, indent);
                }
                if indent.is_empty() {
                    self.md.push('\n');
                }
            }
            "blockquote" | "panel" => {
                let mut inner = Self::default();
                inner.blocks(n, depth + 1, "");
                for line in inner.md.trim_end().lines() {
                    let _ = writeln!(self.md, "{indent}> {line}");
                }
                self.md.push('\n');
                self.links.extend(inner.links);
                self.mentions.extend(inner.mentions);
            }
            "codeBlock" => {
                let lang = Self::attr(n, "language")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let code: String = Self::content(n)
                    .iter()
                    .filter_map(|t| t.get("text").and_then(Value::as_str))
                    .collect();
                let _ = write!(self.md, "{indent}```{lang}\n{code}\n{indent}```\n\n");
            }
            "rule" => {
                let _ = write!(self.md, "{indent}---\n\n");
            }
            "expand" | "nestedExpand" => {
                let title = Self::attr(n, "title")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !title.is_empty() {
                    let _ = write!(self.md, "{indent}**{title}**\n\n");
                }
                self.blocks(n, depth + 1, indent);
            }
            "table" => self.table(n),
            "blockCard" | "embedCard" => {
                if let Some(u) = Self::attr(n, "url").and_then(Value::as_str) {
                    self.link(u);
                    let _ = write!(self.md, "{indent}<{u}>\n\n");
                }
            }
            // Containers and bodied macros: their content is the content.
            "layoutSection" | "layoutColumn" | "bodiedExtension" | "doc" => {
                self.blocks(n, depth + 1, indent);
            }
            // Media are listed as attachments; macros without a body and anything newer
            // than this renderer are skipped.
            _ => {}
        }
    }

    fn list_item(&mut self, item: &Value, marker: &str, depth: usize, indent: &str) {
        let mut first = true;
        let deeper = format!("{indent}  ");
        for child in Self::content(item) {
            let cty = child
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if first && cty == "paragraph" {
                let t = self.inline(child);
                let _ = writeln!(self.md, "{indent}{marker} {t}");
                first = false;
            } else if matches!(
                cty,
                "text" | "hardBreak" | "mention" | "inlineCard" | "emoji" | "status" | "date"
            ) {
                // A task or decision item holds inline nodes directly.
                let t = self.inline_one(child);
                if first {
                    let _ = write!(self.md, "{indent}{marker} {t}");
                    first = false;
                } else {
                    self.md.push_str(&t);
                }
            } else {
                if first {
                    let _ = writeln!(self.md, "{indent}{marker}");
                    first = false;
                }
                self.block(child, depth + 1, &deeper);
            }
        }
        if first {
            let _ = writeln!(self.md, "{indent}{marker}");
        } else if !self.md.ends_with('\n') {
            self.md.push('\n');
        }
    }

    fn table(&mut self, n: &Value) {
        let mut wrote_header = false;
        for row in Self::content(n) {
            let cells: Vec<String> = Self::content(row)
                .iter()
                .map(|c| {
                    let mut inner = Self::default();
                    inner.blocks(c, 1, "");
                    self.links.extend(inner.links);
                    self.mentions.extend(inner.mentions);
                    super::markdown::cell(inner.md.trim())
                })
                .collect();
            let _ = writeln!(self.md, "| {} |", cells.join(" | "));
            if !wrote_header {
                let _ = writeln!(self.md, "|{}", "---|".repeat(cells.len().max(1)));
                wrote_header = true;
            }
        }
        self.md.push('\n');
    }

    fn inline(&mut self, n: &Value) -> String {
        let mut s = String::new();
        for t in Self::content(n) {
            s.push_str(&self.inline_one(t));
        }
        s
    }

    fn inline_one(&mut self, t: &Value) -> String {
        match t.get("type").and_then(Value::as_str).unwrap_or_default() {
            "text" => {
                let mut text = t
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let mut href = None;
                for m in t
                    .get("marks")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                {
                    match m.get("type").and_then(Value::as_str).unwrap_or_default() {
                        "code" => text = format!("`{text}`"),
                        "strong" => text = format!("**{text}**"),
                        "em" => text = format!("*{text}*"),
                        "strike" => text = format!("~~{text}~~"),
                        "link" => {
                            href = m
                                .get("attrs")
                                .and_then(|a| a.get("href"))
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                        }
                        _ => {}
                    }
                }
                if let Some(h) = href {
                    self.link(&h);
                    text = format!("[{text}]({h})");
                }
                text
            }
            "hardBreak" => "\n".to_owned(),
            // The account id only: a display name is personal data and changes.
            "mention" => Self::attr(t, "id")
                .and_then(Value::as_str)
                .map(|id| format!("@user:{id}"))
                .unwrap_or_default(),
            "emoji" => Self::attr(t, "text")
                .or_else(|| Self::attr(t, "shortName"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            "inlineCard" => match Self::attr(t, "url").and_then(Value::as_str) {
                Some(u) => {
                    self.link(u);
                    format!("<{u}>")
                }
                None => String::new(),
            },
            "status" => Self::attr(t, "text")
                .and_then(Value::as_str)
                .map(|s| format!("[{s}]"))
                .unwrap_or_default(),
            "date" => Self::attr(t, "timestamp")
                .and_then(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .or_else(|| v.as_i64().map(|i| i.to_string()))
                })
                .and_then(|ms| ms.parse::<i64>().ok())
                .and_then(chrono::DateTime::from_timestamp_millis)
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Records a link: a page of a Confluence site becomes a mention of its id.
    fn link(&mut self, u: &str) {
        if !(u.starts_with("https://") || u.starts_with("http://")) {
            return;
        }
        if let Some(id) = confluence_page_id(u) {
            self.mentions.insert(id);
        } else {
            self.links.insert(u.to_owned());
        }
    }
}

/// The page id in a Confluence page link (`.../wiki/spaces/ENG/pages/12345/Title`).
#[must_use]
pub fn confluence_page_id(u: &str) -> Option<String> {
    if !u.contains("/wiki/") {
        return None;
    }
    let rest = u.split_once("/pages/")?.1;
    let id: String = rest.chars().take_while(char::is_ascii_digit).collect();
    (!id.is_empty()).then_some(id)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn text(t: &str) -> Value {
        json!({"type": "text", "text": t})
    }

    #[test]
    fn a_document_renders_to_markdown() {
        let doc = json!({"type": "doc", "version": 1, "content": [
            {"type": "heading", "attrs": {"level": 1}, "content": [text("Deploy")]},
            {"type": "paragraph", "content": [
                text("Ask "),
                {"type": "mention", "attrs": {"id": "5b10a2844c20165700abc21g", "text": "@Jane Doe"}},
                text(" or see "),
                {"type": "text", "text": "the runbook", "marks": [{"type": "link", "attrs": {"href": "https://acme.atlassian.net/wiki/spaces/ENG/pages/98765/Runbook"}}]},
                text(" and "),
                {"type": "text", "text": "Grafana", "marks": [{"type": "strong"}, {"type": "link", "attrs": {"href": "https://grafana.acme.example/d/x"}}]}
            ]},
            {"type": "bulletList", "content": [
                {"type": "listItem", "content": [{"type": "paragraph", "content": [text("one")]},
                    {"type": "bulletList", "content": [{"type": "listItem", "content": [{"type": "paragraph", "content": [text("nested")]}]}]}]},
                {"type": "listItem", "content": [{"type": "paragraph", "content": [text("two")]}]}
            ]},
            {"type": "taskList", "content": [{"type": "taskItem", "attrs": {"state": "DONE"}, "content": [text("tag the release")]}]},
            {"type": "codeBlock", "attrs": {"language": "sh"}, "content": [text("make deploy")]},
            {"type": "panel", "attrs": {"panelType": "warning"}, "content": [{"type": "paragraph", "content": [text("Freeze on Fridays.")]}]},
            {"type": "table", "content": [
                {"type": "tableRow", "content": [
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [text("Env")]}]},
                    {"type": "tableHeader", "content": [{"type": "paragraph", "content": [text("Gate")]}]}]},
                {"type": "tableRow", "content": [
                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [text("prod")]}]},
                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [text("a|b")]}]}]}
            ]},
            {"type": "extension", "attrs": {"extensionKey": "toc"}}
        ]});
        let a = Adf::render(&doc);
        let md = super::super::markdown::normalize(&a.md);
        assert_eq!(
            md,
            "## Deploy\n\nAsk @user:5b10a2844c20165700abc21g or see [the runbook](https://acme.atlassian.net/wiki/spaces/ENG/pages/98765/Runbook) and [**Grafana**](https://grafana.acme.example/d/x)\n\n- one\n  - nested\n- two\n\n- [x] tag the release\n\n```sh\nmake deploy\n```\n\n> Freeze on Fridays.\n\n| Env | Gate |\n|---|---|\n| prod | a\\|b |\n"
        );
        assert!(!md.contains("Jane"), "display names are not kept");
        assert_eq!(a.mentions.iter().collect::<Vec<_>>(), ["98765"]);
        assert_eq!(
            a.links.iter().collect::<Vec<_>>(),
            ["https://grafana.acme.example/d/x"]
        );
    }

    #[test]
    fn page_links_are_recognised() {
        assert_eq!(
            confluence_page_id("https://x.atlassian.net/wiki/spaces/E/pages/123/T").as_deref(),
            Some("123")
        );
        assert_eq!(confluence_page_id("https://x.example/pages/123"), None);
    }

    #[test]
    fn nesting_is_bounded() {
        let mut v = json!({"type": "paragraph", "content": [text("deep")]});
        for _ in 0..100 {
            v = json!({"type": "layoutSection", "content": [v]});
        }
        let a = Adf::render(&json!({"type": "doc", "content": [v]}));
        assert!(!a.md.contains("deep"));
    }
}
