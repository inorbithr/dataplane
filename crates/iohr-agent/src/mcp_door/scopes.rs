//! The scopes a sign-in asks for are read at sign-in time, never hardcoded: what the MCP
//! resource advertises (RFC 9728 `scopes_supported`, every scope a tool needs) and what the
//! sign-in can grant (RFC 8414 `scopes_supported`). Asking for a scope the sign-in cannot
//! grant fails the whole sign-in, so a scope is asked for only when both lists name it. A
//! hardcoded list left the approvals, coordinator, schedules, dns, infra and incidents tools
//! out (2026-10-17, the Python bridge's PR inorbit-desktop#336, which this ports).

use std::time::Duration;

use serde_json::Value;

/// Stands in for a list that cannot be read: accounts' `[oauth]` scopes on core main,
/// 2026-10-17 (`configs/accounts/base.toml`), without `openid`, which the door does not use.
pub const KNOWN_SCOPES: [&str; 23] = [
    "mcp:read",
    "mcp:write",
    "mcp:generate",
    "decisions:read",
    "decisions:write",
    "connections:read",
    "connections:use",
    "incidents:read",
    "extensions:read",
    "account:read",
    "summaries:read",
    "usage:read",
    "trail:read",
    "coordinator:read",
    "coordinator:write",
    "approvals:read",
    "approvals:write",
    "atlas-signals:read",
    "schedules:read",
    "dns:read",
    "dns:write",
    "infra:read",
    "infra:run",
];

/// The metadata document's `scopes_supported`, or `None` when it cannot be read.
pub async fn scopes_supported(http: &reqwest::Client, url: &str) -> Option<Vec<String>> {
    let r = http
        .get(url)
        .header("Accept", "application/json")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    if !r.status().is_success() {
        return None;
    }
    let v: Value = r.json().await.ok()?;
    let list: Vec<String> = v
        .get("scopes_supported")?
        .as_array()?
        .iter()
        .filter_map(|s| s.as_str().filter(|s| !s.is_empty()).map(String::from))
        .collect();
    (!list.is_empty()).then_some(list)
}

/// The scope string and where it came from: the resource's scopes that the sign-in can
/// grant, plus `offline_access` for the refresh token. A list that cannot be read is
/// replaced by [`KNOWN_SCOPES`], so the request never names a scope that neither the live
/// server nor the pinned set knows.
#[must_use]
pub fn wanted_scopes(
    resource: Option<Vec<String>>,
    grantable: Option<Vec<String>>,
) -> (String, String) {
    let source = format!(
        "resource {}, sign-in {}",
        if resource.is_some() { "live" } else { "pinned" },
        if grantable.is_some() {
            "live"
        } else {
            "pinned"
        }
    );
    let pinned = || KNOWN_SCOPES.map(String::from).to_vec();
    let want = resource.unwrap_or_else(pinned);
    let can = grantable.unwrap_or_else(pinned);
    let mut out: Vec<String> = Vec::new();
    for s in want {
        if can.contains(&s) && s != "openid" && s != "offline_access" && !out.contains(&s) {
            out.push(s);
        }
    }
    out.push("offline_access".into());
    (out.join(" "), source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps)]
    fn v(a: &[&str]) -> Option<Vec<String>> {
        Some(a.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn asks_for_what_the_resource_advertises_and_the_sign_in_grants() {
        let (scope, source) = wanted_scopes(
            v(&["mcp:read", "approvals:read", "approvals:write"]),
            v(&["mcp:read", "approvals:read", "approvals:write", "openid"]),
        );
        assert_eq!(
            scope,
            "mcp:read approvals:read approvals:write offline_access"
        );
        assert_eq!(source, "resource live, sign-in live");
    }

    #[test]
    fn never_asks_for_a_scope_the_sign_in_cannot_grant() {
        let (scope, _) = wanted_scopes(
            v(&["mcp:read", "brand-new:write"]),
            v(&["mcp:read", "offline_access"]),
        );
        assert_eq!(scope, "mcp:read offline_access");
    }

    #[test]
    fn the_pinned_list_stands_in_when_neither_can_be_read_and_has_approvals() {
        let (scope, source) = wanted_scopes(None, None);
        let got: Vec<&str> = scope.split(' ').collect();
        let mut want: Vec<&str> = KNOWN_SCOPES.to_vec();
        want.push("offline_access");
        assert_eq!(got, want);
        assert!(got.contains(&"approvals:read") && got.contains(&"approvals:write"));
        assert_eq!(source, "resource pinned, sign-in pinned");
    }

    #[test]
    fn an_unreadable_sign_in_list_is_the_pinned_one() {
        let (scope, _) = wanted_scopes(v(&["approvals:read", "unknown:x"]), None);
        assert_eq!(scope, "approvals:read offline_access");
    }

    #[test]
    fn duplicates_and_the_reserved_scopes_are_dropped() {
        let (scope, _) = wanted_scopes(
            v(&["offline_access", "mcp:read", "mcp:read", "openid"]),
            v(&["mcp:read", "offline_access", "openid"]),
        );
        assert_eq!(scope, "mcp:read offline_access");
    }
}
