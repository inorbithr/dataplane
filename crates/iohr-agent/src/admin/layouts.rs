//! Dashboard layouts on this machine (PRD 0024): the platform's layouts API, answered from
//! the trial store, so the console's own editor arranges the local console's boxes and the
//! layout never leaves the machine.
//!
//! | Route | Public operation |
//! |---|---|
//! | `GET /v1/accounts/orgs/{org}/layouts` | `AccountsService.ListLayouts` |
//! | `GET /v1/accounts/orgs/{org}/layouts/{page}` | `AccountsService.GetLayout` |
//! | `PUT /v1/accounts/orgs/{org}/layouts/{page}` | `AccountsService.SetLayout` |
//! | `POST /v1/accounts/orgs/{org}/layouts/{page}/reset` | `AccountsService.ResetLayout` |
//!
//! The same rules as the platform: a person (any role) keeps their own layout; an admin or
//! the owner keeps the agent's default (`scope: account`); a save names the version it was
//! made from and a newer one is a conflict (409), never overwritten. The service checks the
//! shape (ids, widths, no widget twice, at most [`MAX_WIDGETS`]), never which ids a page
//! has. Without the trial store there is nowhere to keep one: 501, and the console hides
//! its editor.

use serde_json::{Value, json};

use super::api::{Answer, error, forbidden, ok};
use super::auth::Person;
use crate::policy::Role;
use crate::store::{LayoutRow, Store};

/// Widgets one layout may hold.
pub(super) const MAX_WIDGETS: usize = 48;
/// The longest page or widget id.
const MAX_ID: usize = 64;

/// A page or widget id: a lowercase letter, then lowercase letters, digits, `-`, `_`, `.`.
fn is_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_ID
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.".contains(c))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Placed {
    widget: String,
    #[serde(default)]
    span: i32,
    #[serde(default)]
    hidden: bool,
}

#[derive(Debug, Default, serde::Deserialize)]
struct SetBody {
    #[serde(default)]
    scope: String,
    #[serde(default)]
    widgets: Vec<Placed>,
    /// int64 travels as a string on the public API; a number is taken too.
    #[serde(default)]
    base_version: Value,
}

#[derive(Debug, Default, serde::Deserialize)]
struct ResetBody {
    #[serde(default)]
    scope: String,
}

fn invalid(msg: &str) -> Answer {
    error(400, "invalid_argument", msg)
}

fn checked(widgets: &[Placed]) -> Result<Vec<Placed>, Answer> {
    if widgets.len() > MAX_WIDGETS {
        return Err(invalid(&format!("widgets: at most {MAX_WIDGETS}")));
    }
    let mut out: Vec<Placed> = Vec::with_capacity(widgets.len());
    for (i, w) in widgets.iter().enumerate() {
        let id = w.widget.trim();
        if !is_id(id) {
            return Err(invalid(&format!(
                "widgets[{i}].widget: 1 to 64 lowercase letters, digits, '-', '_' or '.', starting with a letter"
            )));
        }
        if !(0..=12).contains(&w.span) {
            return Err(invalid(&format!(
                "widgets[{i}].span: 0 (the widget's own width) or 1 to 12 columns"
            )));
        }
        if out.iter().any(|o| o.widget == id) {
            return Err(invalid(&format!(
                "widgets[{i}].widget: {id} is on the page twice"
            )));
        }
        out.push(Placed {
            widget: id.to_owned(),
            span: w.span,
            hidden: w.hidden,
        });
    }
    Ok(out)
}

fn page_of(raw: &str) -> Result<&str, Answer> {
    if is_id(raw) {
        Ok(raw)
    } else {
        Err(invalid(
            "page: 1 to 64 lowercase letters, digits, '-', '_' or '.', starting with a letter",
        ))
    }
}

/// `"person"` (also when empty) or `"account"` (this agent's default).
fn scope_of(raw: &str) -> Result<&'static str, Answer> {
    match raw.trim() {
        "" | "person" => Ok("person"),
        "account" => Ok("account"),
        _ => Err(invalid("scope: person or account")),
    }
}

fn base_of(v: &Value) -> Result<i64, Answer> {
    let n = match v {
        Value::Null => Some(0),
        Value::Number(n) => n.as_i64(),
        Value::String(s) if s.trim().is_empty() => Some(0),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    };
    n.filter(|n| *n >= 0)
        .ok_or_else(|| invalid("base_version: the version read, or 0"))
}

fn may_set_default(person: &Person) -> bool {
    person.role >= Role::Admin
}

fn view(r: &LayoutRow) -> Value {
    let widgets: Vec<Placed> = serde_json::from_str(&r.widgets).unwrap_or_default();
    json!({
        "page": r.page,
        "scope": if r.who.is_empty() { "account" } else { "person" },
        "widgets": widgets,
        "version": r.version.to_string(),
        "updated_at": r.updated_at,
        "updated_by": r.updated_by,
    })
}

fn now(store: &Store, person: &Person, page: &str) -> Result<Value, Answer> {
    let fail = |e: crate::error::Error| error(500, "internal", &e.to_string());
    let default = store.layout(page, "").map_err(fail)?;
    let own = store.layout(page, &person.who).map_err(fail)?;
    let (layout, origin) = match (&own, &default) {
        (Some(r), _) => (view(r), "person"),
        (None, Some(r)) => (view(r), "account"),
        (None, None) => (
            json!({"page": page, "scope": "", "widgets": [], "version": "0", "updated_at": "", "updated_by": ""}),
            "default",
        ),
    };
    Ok(json!({
        "layout": layout,
        "origin": origin,
        "account_default": default.as_ref().map(view),
        "can_set_default": may_set_default(person),
        "where": "agent",
    }))
}

/// Without the trial store there is nowhere to keep a layout.
pub(super) fn no_store() -> Answer {
    error(
        501,
        "unimplemented",
        "layouts are kept in this agent's trial store, which is off ([local] store)",
    )
}

/// `GET …/layouts`.
pub(super) fn list(store: &Store, person: &Person) -> Answer {
    match store.layouts(&person.who) {
        Ok(rows) => {
            let (account, mine): (Vec<&LayoutRow>, Vec<&LayoutRow>) =
                rows.iter().partition(|r| r.who.is_empty());
            ok(&json!({
                "mine": mine.into_iter().map(view).collect::<Vec<_>>(),
                "account": account.into_iter().map(view).collect::<Vec<_>>(),
                "where": "agent",
            }))
        }
        Err(e) => error(500, "internal", &e.to_string()),
    }
}

/// `GET …/layouts/{page}`.
pub(super) fn get(store: &Store, person: &Person, page: &str) -> Answer {
    match page_of(page).and_then(|p| now(store, person, p)) {
        Ok(v) => ok(&v),
        Err(a) => a,
    }
}

/// What a write did, for the audit log: the action, the target and the outcome.
pub(super) type Done = (Answer, Option<(String, String, String)>);

/// `PUT …/layouts/{page}`.
pub(super) fn set(store: &Store, person: &Person, page: &str, body: &[u8]) -> Done {
    let run = || -> Result<(Answer, String), Answer> {
        let page = page_of(page)?;
        let b: SetBody = serde_json::from_slice(body).map_err(|_| {
            invalid("send {\"scope\": …, \"widgets\": [{\"widget\", \"span\", \"hidden\"}], \"base_version\": …}")
        })?;
        let scope = scope_of(&b.scope)?;
        let widgets = checked(&b.widgets)?;
        let base = base_of(&b.base_version)?;
        if scope == "account" && !may_set_default(person) {
            return Err(forbidden(
                "changing this agent's default layout needs the admin role",
            ));
        }
        let who = if scope == "account" {
            ""
        } else {
            person.who.as_str()
        };
        let text = serde_json::to_string(&widgets).unwrap_or_else(|_| "[]".into());
        match store.set_layout(page, who, &text, base, &person.who) {
            Ok(Ok(row)) => Ok((
                ok(&json!({"layout": view(&row), "where": "agent"})),
                format!("{page} ({scope})"),
            )),
            Ok(Err(current)) => Err(error(
                409,
                "aborted",
                &format!(
                    "someone saved this layout since (version {current}); read it again and save on that"
                ),
            )),
            Err(e) => Err(error(500, "internal", &e.to_string())),
        }
    };
    match run() {
        Ok((a, target)) => (a, Some(("layout.set".into(), target, "ok".into()))),
        Err(a) => {
            let outcome = format!("refused ({})", a.0);
            (a, Some(("layout.set".into(), page.into(), outcome)))
        }
    }
}

/// `POST …/layouts/{page}/reset`.
pub(super) fn reset(store: &Store, person: &Person, page: &str, body: &[u8]) -> Done {
    let run = || -> Result<(Answer, String), Answer> {
        let page = page_of(page)?;
        let b: ResetBody = serde_json::from_slice(body).unwrap_or_default();
        let scope = scope_of(&b.scope)?;
        if scope == "account" && !may_set_default(person) {
            return Err(forbidden(
                "changing this agent's default layout needs the admin role",
            ));
        }
        let who = if scope == "account" {
            ""
        } else {
            person.who.as_str()
        };
        store
            .reset_layout(page, who)
            .map_err(|e| error(500, "internal", &e.to_string()))?;
        let v = now(store, person, page)?;
        Ok((
            ok(&json!({"now": v, "where": "agent"})),
            format!("{page} ({scope})"),
        ))
    };
    match run() {
        Ok((a, target)) => (a, Some(("layout.reset".into(), target, "ok".into()))),
        Err(a) => {
            let outcome = format!("refused ({})", a.0);
            (a, Some(("layout.reset".into(), page.into(), outcome)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(who: &str, role: Role) -> Person {
        Person {
            who: who.into(),
            name: who.into(),
            role,
            mode: "oidc",
        }
    }

    fn body(a: &Answer) -> Value {
        serde_json::from_str(&a.1).unwrap()
    }

    fn put(widgets: &str, scope: &str, base: &str) -> Vec<u8> {
        format!(r#"{{"scope":"{scope}","widgets":{widgets},"base_version":"{base}"}}"#).into_bytes()
    }

    #[test]
    fn people_keep_their_own_and_admins_keep_the_default() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::open(d.path(), 30).unwrap();
        let ana = person("u-ana", Role::Viewer);
        let boss = person("u-boss", Role::Admin);
        let page = "local.overview";

        // Nothing saved: the page's own.
        let v = body(&get(&store, &ana, page));
        assert_eq!(v["origin"], "default");
        assert_eq!(v["can_set_default"], false);
        assert_eq!(v["where"], "agent");

        // A viewer arranges their own page.
        let mine = r#"[{"widget":"sent","span":6,"hidden":false},{"widget":"numbers","span":0,"hidden":true}]"#;
        let (a, audit) = set(&store, &ana, page, &put(mine, "person", "0"));
        assert_eq!(a.0, 200, "{}", a.1);
        assert_eq!(body(&a)["layout"]["version"], "1");
        assert_eq!(audit.unwrap().0, "layout.set");
        let v = body(&get(&store, &ana, page));
        assert_eq!(v["origin"], "person");
        assert_eq!(v["layout"]["widgets"][0]["widget"], "sent");

        // A stale save is a conflict.
        let (a, _) = set(&store, &ana, page, &put("[]", "person", "0"));
        assert_eq!(a.0, 409);

        // A viewer can't set the default; an admin can, and others see it.
        let (a, _) = set(&store, &ana, page, &put(mine, "account", "0"));
        assert_eq!(a.0, 403);
        let (a, _) = set(&store, &boss, page, &put(mine, "account", "0"));
        assert_eq!(a.0, 200);
        let v = body(&get(&store, &boss, page));
        assert_eq!(
            (v["origin"].as_str(), v["can_set_default"].as_bool()),
            (Some("account"), Some(true))
        );
        let v = body(&list(&store, &ana));
        assert_eq!(v["mine"].as_array().map(Vec::len), Some(1));
        assert_eq!(v["account"].as_array().map(Vec::len), Some(1));

        // Reset goes back to the default.
        let (a, _) = reset(&store, &ana, page, br#"{"scope":"person"}"#);
        assert_eq!(body(&a)["now"]["origin"], "account");
        let (a, _) = reset(&store, &ana, page, br#"{"scope":"account"}"#);
        assert_eq!(a.0, 403);
    }

    #[test]
    fn each_field_is_checked_by_name() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::open(d.path(), 30).unwrap();
        let p = person("u-x", Role::Owner);
        for (widgets, field) in [
            (r#"[{"widget":"Numbers"}]"#, "widgets[0].widget"),
            (r#"[{"widget":"numbers","span":13}]"#, "widgets[0].span"),
            (r#"[{"widget":"a"},{"widget":"a"}]"#, "twice"),
        ] {
            let (a, _) = set(&store, &p, "local.overview", &put(widgets, "person", "0"));
            assert_eq!(a.0, 400);
            assert!(a.1.contains(field), "{}", a.1);
        }
        assert_eq!(get(&store, &p, "../x").0, 400);
        let (a, _) = set(&store, &p, "local.overview", &put("[]", "team", "0"));
        assert!(a.1.contains("scope"));
        let many: Vec<String> = (0..=MAX_WIDGETS)
            .map(|i| format!(r#"{{"widget":"w{i}"}}"#))
            .collect();
        let (a, _) = set(
            &store,
            &p,
            "local.overview",
            &put(&format!("[{}]", many.join(",")), "person", "0"),
        );
        assert_eq!(a.0, 400);
    }
}
