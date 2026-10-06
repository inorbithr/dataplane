//! `graphql`: `POST` the check's query (and variables) as JSON; healthy when the status is
//! as expected and the answer is an object with `data` and no `errors`. The answer is
//! parsed in memory and dropped: neither `data` nor an error's message is ever reported.

use std::time::Instant;

use serde_json::{Value, json};

use super::http::{classify, client, expiry, read_bounded, with_auth};
use super::{CheckDetail, ErrorClass, Prepared, judged, status_ok};
use crate::tls::TlsContext;

/// The query when the check names none: answered by every GraphQL server.
pub(crate) const DEFAULT_QUERY: &str = "{ __typename }";

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let Some(url) = p.endpoint.url.clone() else {
        return CheckDetail::failed(ErrorClass::Connect, started);
    };
    let client = match client(tls, p) {
        Ok(c) => c,
        Err(class) => return CheckDetail::failed(class, started),
    };
    let mut body = json!({"query": p.spec.params.query.as_deref().unwrap_or(DEFAULT_QUERY)});
    if let Some(v) = &p.spec.params.body {
        body["variables"] = v.clone();
    }
    let req = client
        .post(url)
        .header(
            "accept",
            "application/graphql-response+json, application/json",
        )
        .json(&body);
    let req = match with_auth(req, p) {
        Ok(r) => r,
        Err(class) => return CheckDetail::failed(class, started),
    };
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return CheckDetail::failed(classify(&e), started),
    };
    let status = resp.status().as_u16();
    let expires = expiry(&resp);
    let outcome = if status_ok(&p.spec.expect, status) {
        match read_bounded(resp).await {
            Ok(bytes) => judge(&bytes),
            Err(class) => Err(class),
        }
    } else {
        Err(ErrorClass::Status)
    };
    let mut d = judged(started, Some(status), outcome);
    d.tls_expires_at = expires;
    d
}

/// An answer with `data` and without `errors` (an empty `errors` list counts as none).
fn judge(bytes: &[u8]) -> Result<(), ErrorClass> {
    let v: Value = serde_json::from_slice(bytes).map_err(|_| ErrorClass::Answer)?;
    let errors = v
        .get("errors")
        .is_some_and(|e| !e.is_null() && e.as_array().is_none_or(|a| !a.is_empty()));
    if v.get("data").is_some_and(|d| !d.is_null()) && !errors {
        Ok(())
    } else {
        Err(ErrorClass::Answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_without_errors_passes() {
        assert!(judge(br#"{"data":{"__typename":"Query"}}"#).is_ok());
        assert!(judge(br#"{"data":{"a":1},"errors":[]}"#).is_ok());
        assert_eq!(
            judge(br#"{"data":null,"errors":[{"message":"x"}]}"#),
            Err(ErrorClass::Answer)
        );
        assert_eq!(
            judge(br#"{"data":{"a":null},"errors":[{"message":"x"}]}"#),
            Err(ErrorClass::Answer)
        );
        assert_eq!(judge(b"<html>"), Err(ErrorClass::Answer));
        assert_eq!(judge(b"{}"), Err(ErrorClass::Answer));
    }
}
