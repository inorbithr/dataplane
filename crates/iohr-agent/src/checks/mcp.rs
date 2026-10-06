//! `mcp`: the Model Context Protocol over streamable HTTP. `initialize`, the `initialized`
//! notification, `tools/list` (at least `min_tools` tools, default 1) and, when the check
//! names one, a `tools/call` of that tool. A tool is called only when `tools/list`
//! annotates it `readOnlyHint: true`, or when the local entry says
//! `allow_side_effects = true`; anything else is a refusal decided here, before the call.
//!
//! An answer is JSON or an event stream; either is read bounded, parsed in memory and
//! dropped. A JSON-RPC error, a tool's `isError` or a missing tool is the class `answer`;
//! no message, tool output or tool list ever leaves the agent.

use std::time::Instant;

use serde_json::{Value, json};

use super::http::{classify, client, expiry, read_bounded, with_auth};
use super::{CheckDetail, ErrorClass, Prepared, judged, status_ok};
use crate::tls::TlsContext;

/// The protocol version the agent offers.
const PROTOCOL_VERSION: &str = "2025-11-25";

/// Where one MCP conversation is.
struct Conversation<'a> {
    client: reqwest::Client,
    url: url::Url,
    p: &'a Prepared<'a>,
    session: Option<String>,
    version: Option<String>,
    next_id: u64,
    expires: Option<String>,
}

/// One step's failure: the class and the HTTP status that came with it, if any.
type Failed = (ErrorClass, Option<u16>);

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> Result<CheckDetail, String> {
    let started = Instant::now();
    let Some(url) = p.endpoint.url.clone() else {
        return Ok(CheckDetail::failed(ErrorClass::Connect, started));
    };
    let client = match client(tls, p) {
        Ok(c) => c,
        Err(class) => return Ok(CheckDetail::failed(class, started)),
    };
    let mut c = Conversation {
        client,
        url,
        p,
        session: None,
        version: None,
        next_id: 1,
        expires: None,
    };
    let outcome = c.run().await?;
    let (status, outcome) = match outcome {
        Ok(status) => (Some(status), Ok(())),
        Err((class, status)) => (status, Err(class)),
    };
    let mut d = judged(started, status, outcome);
    d.tls_expires_at = c.expires;
    Ok(d)
}

impl Conversation<'_> {
    /// The steps; `Ok(Ok(status of initialize))`, `Ok(Err(..))` for a failed check,
    /// `Err(reason)` for a refusal.
    async fn run(&mut self) -> Result<Result<u16, Failed>, String> {
        let init = self
            .call(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "iohr-agent", "version": env!("CARGO_PKG_VERSION")},
                }),
                true,
            )
            .await;
        let (status, result) = match init {
            Ok(v) => v,
            Err(f) => return Ok(Err(f)),
        };
        self.version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .filter(|v| v.len() <= 32 && v.bytes().all(|b| b.is_ascii_graphic()))
            .map(str::to_owned);
        if let Err(f) = self.notify("notifications/initialized").await {
            return Ok(Err(f));
        }
        let tools = match self.call("tools/list", json!({}), false).await {
            Ok((_, r)) => r,
            Err(f) => return Ok(Err(f)),
        };
        let Some(tools) = tools.get("tools").and_then(Value::as_array) else {
            return Ok(Err((ErrorClass::Answer, None)));
        };
        let min = u64::from(self.p.spec.params.min_tools.unwrap_or(1));
        if (tools.len() as u64) < min {
            return Ok(Err((ErrorClass::Answer, None)));
        }
        let Some(name) = self.p.spec.params.tool.clone() else {
            return Ok(Ok(status));
        };
        let Some(tool) = tools
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(name.as_str()))
        else {
            return Ok(Err((ErrorClass::Answer, None)));
        };
        let read_only = tool
            .pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            == Some(true);
        if !read_only && !self.p.spec.params.allow_side_effects {
            // The tool's name stays on this machine, like the rest of the request.
            return Err(
                "the MCP tool this check names is not annotated read-only; it is called only with allow_side_effects = true in checks.toml"
                    .into(),
            );
        }
        let args = self.p.spec.params.body.clone().unwrap_or_else(|| json!({}));
        match self
            .call(
                "tools/call",
                json!({"name": name, "arguments": args}),
                false,
            )
            .await
        {
            Ok((_, r)) if r.get("isError").and_then(Value::as_bool) == Some(true) => {
                Ok(Err((ErrorClass::Answer, None)))
            }
            Ok(_) => Ok(Ok(status)),
            Err(f) => Ok(Err(f)),
        }
    }

    fn request(&self, body: &Value) -> Result<reqwest::RequestBuilder, Failed> {
        let mut req = self
            .client
            .post(self.url.clone())
            .header("accept", "application/json, text/event-stream")
            .json(body);
        if let Some(s) = &self.session {
            req = req.header("mcp-session-id", s.as_str());
        }
        if let Some(v) = &self.version {
            req = req.header("mcp-protocol-version", v.as_str());
        }
        with_auth(req, self.p).map_err(|c| (c, None))
    }

    /// A request and its `result`, with the HTTP status.
    async fn call(
        &mut self,
        method: &str,
        params: Value,
        first: bool,
    ) -> Result<(u16, Value), Failed> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let resp = self
            .request(&body)?
            .send()
            .await
            .map_err(|e| (classify(&e), None))?;
        let status = resp.status().as_u16();
        if first {
            self.expires = expiry(&resp);
            self.session = resp
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .filter(|v| (1..=256).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_graphic()))
                .map(str::to_owned);
        }
        let ok = if first {
            status_ok(&self.p.spec.expect, status)
        } else {
            (200..300).contains(&status)
        };
        if !ok {
            return Err((ErrorClass::Status, Some(status)));
        }
        let stream = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim_start().starts_with("text/event-stream"));
        let bytes = read_bounded(resp).await.map_err(|c| (c, Some(status)))?;
        let answer = if stream {
            from_events(&bytes, id)
        } else {
            serde_json::from_slice::<Value>(&bytes).ok()
        };
        match answer {
            Some(v) if v.get("id").and_then(Value::as_u64) == Some(id) => match v.get("result") {
                Some(r) if r.is_object() => Ok((status, r.clone())),
                _ => Err((ErrorClass::Answer, Some(status))),
            },
            _ => Err((ErrorClass::Answer, Some(status))),
        }
    }

    /// A notification: no answer but a 2xx status.
    async fn notify(&mut self, method: &str) -> Result<(), Failed> {
        let body = json!({"jsonrpc": "2.0", "method": method});
        let resp = self
            .request(&body)?
            .send()
            .await
            .map_err(|e| (classify(&e), None))?;
        let status = resp.status().as_u16();
        drop(resp);
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err((ErrorClass::Status, Some(status)))
        }
    }
}

/// The JSON-RPC message answering `id` in an event stream's `data` fields.
fn from_events(bytes: &[u8], id: u64) -> Option<Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut data = String::new();
    for line in text.split('\n').map(|l| l.trim_end_matches('\r')) {
        if line.is_empty() {
            if let Ok(v) = serde_json::from_str::<Value>(&data)
                && v.get("id").and_then(Value::as_u64) == Some(id)
            {
                return Some(v);
            }
            data.clear();
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    serde_json::from_str::<Value>(&data)
        .ok()
        .filter(|v| v.get("id").and_then(Value::as_u64) == Some(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_answer_is_found_among_events() {
        let s = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n";
        assert_eq!(from_events(s, 2).unwrap()["id"], 2);
        assert!(from_events(s, 3).is_none());
        assert_eq!(
            from_events(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", 1).unwrap()["id"],
            1,
            "an unterminated last event still counts"
        );
    }
}
