//! Protocol recognition (layer 2) from the first bytes of a flow. Each recogniser looks at
//! a contiguous prefix of one side of a flow and answers [`Detect::Yes`] with what it
//! found, [`Detect::NeedMore`] when the prefix is too short to tell, or [`Detect::No`].
//! Recognisers never allocate more than their result and never panic on any input (the
//! tests feed them truncations of real captures and random bytes).

pub(crate) mod dns;
pub(crate) mod hpack;
pub(crate) mod http1;
pub(crate) mod http2;
pub(crate) mod huffman;
pub(crate) mod postgres;
pub(crate) mod redis;
pub(crate) mod tls;

/// What a recogniser decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Detect<T> {
    Yes(T),
    NeedMore,
    No,
}

/// A protocol event, the unit the aggregates count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    Http1Request(http1::Request),
    Http1Response { status: u16 },
    TlsClientHello(tls::ClientHello),
    DnsQuery(dns::Query),
    DnsResponse { rcode: u8 },
    Http2(http2::Connection),
    Redis { command: String },
    Postgres(postgres::Message),
}

/// The route template of a request target: one rule set for every recogniser
/// ([`crate::route`], RFC 0070).
pub(crate) fn path_template(target: &str) -> String {
    crate::route::template(target)
}

/// Lower-cased host without a port, only if it looks like a host name or address.
pub(crate) fn clean_host(raw: &str) -> Option<String> {
    let h = raw.trim();
    let h = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        h.rsplit_once(':')
            .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
            .map_or(h, |(n, _)| n)
    };
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b':');
    ok.then(|| h.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates() {
        assert_eq!(path_template("/users/123/orders?x=1"), "/users/{id}/orders");
        assert_eq!(
            path_template("/o/3f2a9c1e-7b4d-4c1a-9e2f-0a1b2c3d4e5f"),
            "/o/{id}"
        );
        assert_eq!(path_template("/static/app.js#top"), "/static/app.js");
        assert_eq!(path_template("http://example.com/a/42"), "/a/{id}");
        assert_eq!(path_template("/v1/healthz"), "/v1/healthz");
        assert_eq!(path_template("/u/someone@example.com"), "/u/{id}");
        assert_eq!(path_template("*"), "*");
    }

    #[test]
    fn hosts() {
        assert_eq!(
            clean_host("Web.E2E.test:8080").as_deref(),
            Some("web.e2e.test")
        );
        assert_eq!(clean_host("[::1]:80").as_deref(), Some("::1"));
        assert_eq!(clean_host("bad host"), None);
        assert_eq!(clean_host(""), None);
    }
}
