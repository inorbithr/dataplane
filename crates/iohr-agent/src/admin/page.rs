//! The page's HTML and JSON. Server-rendered, no script at all; one stylesheet, allowed
//! by its hash. Every value is escaped, and every body is redacted again on its way out.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::OnceLock;

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::Context;
use crate::checks::{Surface, Target};
use crate::checks_file::{self, DeclaredCheck, Kind, RefuseBy};
use crate::state::{JobRecord, Snapshot};

/// The tab icon: the InOrbit mark, its body amber.
pub(super) const FAVICON: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none"><style>.i{stroke:#0a0a0a;fill:#0a0a0a}@media(prefers-color-scheme:dark){.i{stroke:#fafafa;fill:#fafafa}}</style><circle class="i" cx="18.8" cy="17.3" r="8.7" stroke-width="2.6" fill="none"/><rect class="i" x="3.7" y="9.8" width="2.8" height="17.5" rx="1.4" stroke="none"/><circle cx="5.1" cy="6.8" r="1.9" fill="#ff9e1b"/></svg>"##;

const LOGO: &str = r##"<svg class="mark" viewBox="0 0 32 32" fill="none" aria-hidden="true"><circle cx="18.8" cy="17.3" r="8.7" stroke="currentColor" stroke-width="2.6"/><rect x="3.7" y="9.8" width="2.8" height="17.5" rx="1.4" fill="currentColor"/><circle cx="5.1" cy="6.8" r="1.9" fill="#ff9e1b"/></svg>"##;

/// The one stylesheet (allowed by its hash in the CSP).
const CSS: &str = r#"
:root{color-scheme:light dark;--bg:#fafafa;--surface:#fff;--raised:#f4f4f5;--ink:#0a0a0a;--muted:#5f5f5f;--line:#e5e5e5;--amber:#ff9e1b;--ok:#008b45;--alert:#e7000b;--warn:#a35f00;--none:#a3a3a3;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--surface:#141414;--raised:#1c1c1c;--ink:#f2f2f2;--muted:#a3a3a3;--line:#262626;--ok:#34c47c;--alert:#ff5a5f;--warn:#ffb54d;--none:#5c5c5c}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:inherit;text-underline-offset:2px}
time{white-space:nowrap}
code,pre,.mono{font-family:var(--mono);font-size:12.5px}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 24px;border-bottom:1px solid var(--line);background:var(--surface);flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;letter-spacing:-.01em}
.mark{width:22px;height:22px}
.brand small{font-weight:400;color:var(--muted)}
.who{display:flex;align-items:center;gap:10px;min-width:0}
.who b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
nav{display:flex;gap:2px;padding:0 16px;border-bottom:1px solid var(--line);background:var(--surface);overflow-x:auto;scrollbar-width:none}
nav a{padding:10px 10px;text-decoration:none;color:var(--muted);border-bottom:2px solid transparent;white-space:nowrap}
nav a:hover{color:var(--ink)}
nav a[aria-current=page]{color:var(--ink);border-bottom-color:var(--amber)}
main{max-width:1120px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:15px;margin:28px 0 10px}
h3{font-size:13px;margin:0 0 8px;color:var(--muted);font-weight:500;text-transform:uppercase;letter-spacing:.04em}
.lede{color:var(--muted);margin:0 0 20px;max-width:72ch}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px;min-width:0}
.card.wide{grid-column:1/-1}
.stat{font-size:24px;font-weight:600;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat small{font-size:13px;font-weight:400;color:var(--muted)}
.muted{color:var(--muted)}
.kv{width:100%;border-collapse:collapse}
.kv th{text-align:left;font-weight:400;color:var(--muted);padding:5px 12px 5px 0;vertical-align:top;white-space:nowrap;width:1%}
.kv td{padding:5px 0;overflow-wrap:anywhere}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--surface)}
table.t{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
.t th{text-align:left;font-weight:500;color:var(--muted);font-size:12px;padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap;background:var(--raised)}
.t td{padding:7px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.t tr:last-child td{border-bottom:0}
.t td.n{text-align:right;white-space:nowrap}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 9px;border-radius:999px;border:1px solid var(--line);font-size:12px;white-space:nowrap;background:var(--surface)}
.pill::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--none)}
.pill.ok::before{background:var(--ok)}.pill.bad::before{background:var(--alert)}.pill.warn::before{background:var(--warn)}.pill.amber::before{background:var(--amber)}
.badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:.03em;text-transform:uppercase;border:1px solid currentColor;white-space:nowrap}
.badge.ok{color:var(--ok)}.badge.part{color:var(--warn)}.badge.no{color:var(--muted)}.badge.bad{color:var(--alert)}
.promises{list-style:none;margin:0;padding:0}
.promises li{display:grid;grid-template-columns:1fr auto;gap:4px 12px;padding:12px 0;border-bottom:1px solid var(--line)}
.promises li:last-child{border-bottom:0}
.promises b{font-weight:600}
.promises p{grid-column:1/-1;margin:0;color:var(--muted)}
.list{margin:0;padding-left:18px}.list li{margin:4px 0}
.never li{margin:6px 0}
.checks{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}
.check .head{display:flex;justify-content:space-between;gap:8px;align-items:flex-start}
.check .name{font-weight:600;overflow-wrap:anywhere}
.check .meta{color:var(--muted);font-size:12.5px;margin:2px 0 8px}
.check .target{font-family:var(--mono);font-size:12px;overflow-wrap:anywhere;margin:0 0 10px}
.nums{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:0 0 10px}
.nums div{min-width:0}.nums span{display:block;color:var(--muted);font-size:11.5px}.nums b{font-weight:500;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.spark{display:block;width:100%;height:28px}
.spark .ok{fill:var(--ok)}.spark .bad{fill:var(--alert)}.spark .ref{fill:var(--warn)}.spark .none{fill:var(--line)}
.meter{display:block;width:100%;height:8px;margin:8px 0 2px}
.meter .bg{fill:var(--raised)}.meter .fg{fill:var(--ink)}.meter .hot{fill:var(--alert)}
.note.ok{border-left-color:var(--ok)}.note.bad{border-left-color:var(--alert)}
.share{display:grid;gap:12px;margin:0 0 8px}
.share fieldset{border:0;margin:0;padding:0;min-width:0}
.share legend{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin:0 0 8px}
.opts{display:grid;gap:8px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}
.opt,.switch{display:flex;gap:10px;align-items:flex-start;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--surface);cursor:pointer}
.opt:has(input:checked){border-color:var(--amber);box-shadow:inset 0 0 0 1px var(--amber)}
.opt input,.switch input{margin-top:3px;accent-color:var(--amber)}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
button{font:inherit;padding:8px 16px;border-radius:8px;border:1px solid var(--line);background:var(--surface);color:var(--ink);cursor:pointer}
button.primary{background:var(--ink);color:var(--bg);border-color:var(--ink)}
button:focus-visible,.opt:focus-within,.switch:focus-within{outline:2px solid var(--amber);outline-offset:2px}
.gap{margin-top:20px}
details summary{cursor:pointer;color:var(--muted);margin:0 0 8px}
.note{border-left:3px solid var(--amber);padding:10px 14px;background:var(--surface);border-radius:0 8px 8px 0;margin:16px 0;color:var(--ink)}
pre{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px;overflow-x:auto;margin:0;white-space:pre}
.logs td{font-family:var(--mono);font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere}
.lv-WARN{color:var(--warn)}.lv-ERROR{color:var(--alert)}
footer{max-width:1120px;margin:0 auto;padding:8px 24px 40px;color:var(--muted);font-size:12px}
@media (max-width:600px){.top{padding:12px 16px}main{padding:16px}nav{padding:0 8px}.nums{grid-template-columns:repeat(2,minmax(0,1fr))}.checks{grid-template-columns:1fr}footer{padding:8px 16px 32px}.hide-sm{display:none}}
"#;

const NAV: [(&str, &str); 7] = [
    ("/", "Overview"),
    ("/checks", "Checks"),
    ("/policy", "Policy"),
    ("/ledger", "What left"),
    ("/jobs", "Jobs"),
    ("/host", "Host"),
    ("/logs", "Logs"),
];

/// The JSON twin of each section.
const API: [(&str, &str); 7] = [
    ("/api/v1/overview.json", "overview"),
    ("/api/v1/checks.json", "checks"),
    ("/api/v1/policy.json", "policy"),
    ("/api/v1/ledger.json", "ledger"),
    ("/api/v1/jobs.json", "jobs"),
    ("/api/v1/host.json", "host"),
    ("/api/v1/logs.json", "logs"),
];

/// The Content-Security-Policy: nothing but this page's own stylesheet and icon.
pub(super) fn csp() -> &'static str {
    static CSP: OnceLock<String> = OnceLock::new();
    CSP.get_or_init(|| {
        let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(CSS));
        format!(
            "default-src 'none'; style-src 'sha256-{hash}'; img-src 'self'; script-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
    })
}

pub(super) fn is_html_route(path: &str) -> bool {
    NAV.iter().any(|(p, _)| *p == path)
}

/// What a request brings to a page beyond its path.
#[derive(Debug, Default)]
pub(super) struct View {
    /// The query string (the policy page's preview choice, `applied=1`).
    pub query: String,
    /// The form token, when the request is signed in.
    pub csrf: Option<String>,
    /// The request carries a valid session.
    pub signed_in: bool,
    /// Changes are possible from this client: both ends on loopback and a supervisor.
    pub can_change: bool,
    /// The outcome of a change, to show at the top.
    pub flash: Option<(bool, String)>,
}

/// The body for a path, with its content type.
pub(super) fn route(
    ctx: &Context,
    path: &str,
    local: Option<SocketAddr>,
    view: &View,
) -> Option<(&'static str, String)> {
    const HTML: &str = "text/html; charset=utf-8";
    const JSON: &str = "application/json";
    let s = ctx.state.snapshot();
    let html = |active: &str, body: String| layout(ctx, &s, active, &body, local);
    Some(match path {
        "/" => (HTML, html("/", overview(ctx, &s))),
        "/checks" => (HTML, html("/checks", checks(ctx))),
        "/policy" => (HTML, html("/policy", policy(ctx, view))),
        "/ledger" => (HTML, html("/ledger", ledger(ctx))),
        "/jobs" => (HTML, html("/jobs", jobs(&s))),
        "/host" => (HTML, html("/host", host(ctx, &s))),
        "/logs" => (HTML, html("/logs", logs())),
        "/status.json" => (JSON, serde_json::to_string_pretty(&s).unwrap_or_default()),
        p => {
            let (_, name) = API.iter().find(|(a, _)| *a == p)?;
            let v = api(ctx, &s, name);
            (JSON, serde_json::to_string_pretty(&v).unwrap_or_default())
        }
    })
}

/// Every page and every JSON answer, concatenated, for tests that search all of it.
#[must_use]
pub fn render_all(ctx: &Context) -> String {
    let mut out = String::new();
    for p in NAV
        .iter()
        .map(|(p, _)| *p)
        .chain(API.iter().map(|(p, _)| *p))
        .chain(["/status.json"])
    {
        if let Some((_, body)) = route(ctx, p, None, &View::default()) {
            out.push_str(&crate::redact::redact(&body));
            out.push('\n');
        }
    }
    out.push_str(&locked(ctx));
    out
}

/// The page when it asks for its token.
pub(super) fn locked(ctx: &Context) -> String {
    format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>Agent page · locked</title><link rel=icon href=/favicon.svg><style>{CSS}</style><body><header class=top><div class=brand>{LOGO}<span>InOrbit agent</span></div></header><main><h1>This page asks for its token</h1><p class=lede>On the machine the agent runs on, run <code>iohr agent page --open</code>. It reads the token from <code>{}/admin.token</code> (readable only by the agent's user) and opens this page signed in.</p></main></body></html>",
        esc(&ctx.state_dir)
    )
}

// ---------------------------------------------------------------- helpers

pub(super) fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn parse_time(t: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).ok()
}

/// `12 s ago`, `4 min ago`, `3 h ago`, `2 d ago`.
fn ago(t: &str) -> String {
    let Some(at) = parse_time(t) else {
        return String::new();
    };
    let secs = (time::OffsetDateTime::now_utc() - at)
        .whole_seconds()
        .max(0);
    match secs {
        0..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86_400),
    }
}

/// `<time>` with the exact time as its title.
fn when(t: &str) -> String {
    if t.is_empty() {
        return "—".into();
    }
    format!(
        "<time datetime=\"{0}\" title=\"{0}\">{1}</time>",
        esc(t),
        esc(&ago(t))
    )
}

fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m} min"),
        (0, _) => format!("{h} h {m} min"),
        _ => format!("{d} d {h} h"),
    }
}

/// A hash shortened for a table, whole in its title.
fn short(h: &str) -> String {
    let tail = h.strip_prefix("sha256:").unwrap_or(h);
    format!(
        "<code title=\"{}\">{}…</code>",
        esc(h),
        esc(tail.get(..12).unwrap_or(tail))
    )
}

fn pill(class: &str, text: &str) -> String {
    format!("<span class=\"pill {class}\">{}</span>", esc(text))
}

fn badge(status: Status) -> String {
    let (c, t) = match status {
        Status::InPlace => ("ok", "in place"),
        Status::Partial => ("part", "partial"),
        Status::NotBuilt => ("no", "not built"),
        Status::Off => ("bad", "off"),
    };
    format!("<span class=\"badge {c}\">{t}</span>")
}

#[derive(Debug, Clone, Copy)]
enum Status {
    InPlace,
    Partial,
    NotBuilt,
    Off,
}

fn verdict_pill(v: &str) -> String {
    match v {
        "ok" => pill("ok", "ok"),
        "failed" => pill("bad", "failed"),
        "refused" => pill("warn", "refused"),
        other => pill("", other),
    }
}

fn kv(rows: &[(&str, String)]) -> String {
    let mut h = String::from("<table class=kv>");
    for (k, v) in rows {
        let _ = write!(h, "<tr><th>{}</th><td>{v}</td></tr>", esc(k));
    }
    h.push_str("</table>");
    h
}

fn layout(
    ctx: &Context,
    s: &Snapshot,
    active: &str,
    body: &str,
    local: Option<SocketAddr>,
) -> String {
    let title = NAV
        .iter()
        .find(|(p, _)| *p == active)
        .map_or("Agent", |(_, t)| t);
    let conn = connection_pill(s);
    let mut nav = String::new();
    for (p, t) in NAV {
        let cur = if p == active {
            " aria-current=page"
        } else {
            ""
        };
        let _ = write!(nav, "<a href=\"{p}\"{cur}>{t}</a>");
    }
    // The JSON twin sits at the same index as its section.
    let api = NAV
        .iter()
        .position(|(p, _)| *p == active)
        .and_then(|i| API.get(i))
        .map_or("/status.json", |(p, _)| p);
    let served = local.map_or_else(String::new, |l| format!(" on {l}"));
    let _ = ctx;
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta name=referrer content=same-origin><title>{title} · {name} · InOrbit agent</title><link rel=icon href=/favicon.svg type=\"image/svg+xml\"><style>{CSS}</style></head><body>\
<header class=top><div class=brand>{LOGO}<span>InOrbit agent <small>local page</small></span></div><div class=who><b>{name}</b>{conn}</div></header>\
<nav aria-label=Sections>{nav}</nav><main>{body}</main>\
<footer>Served by this agent{served}; read-only but for <a href=\"/policy#share\">What InOrbit sees</a>, changed only on this machine. Nothing on this page is sent anywhere; secrets are redacted before it is shown. This section as JSON: <a href=\"{api}\">{api}</a>.</footer></body></html>",
        name = esc(&s.agent.name),
    )
}

fn connection_pill(s: &Snapshot) -> String {
    if s.revoked {
        pill("bad", "revoked")
    } else if s.connected {
        pill("ok", "connected")
    } else {
        pill("warn", "not connected")
    }
}

/// A horizontal meter: `value` of `max`.
fn meter(value: u64, max: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let frac = if max == 0 {
        0.0
    } else {
        (value as f64 / max as f64).min(1.0)
    };
    let class = if frac >= 0.9 { "hot" } else { "fg" };
    format!(
        "<svg class=meter viewBox=\"0 0 100 8\" preserveAspectRatio=none role=img aria-label=\"{value} of {max}\"><rect class=bg width=100 height=8 rx=4 /><rect class={class} width=\"{:.1}\" height=8 rx=4 /></svg>",
        (frac * 100.0).max(if value > 0 { 2.0 } else { 0.0 })
    )
}

// ---------------------------------------------------------------- overview

fn promises(ctx: &Context, s: &Snapshot) -> Vec<(&'static str, Status, String, &'static str)> {
    let p = &ctx.policy;
    let ledger = match &ctx.ledger {
        Some(l) => {
            let (seq, _) = l.head();
            (
                Status::Partial,
                format!(
                    "Phase 1: {seq} messages recorded on this machine before they left, hash-chained, metadata only. The platform's receipts and the daily reconciliation are not built yet."
                ),
            )
        }
        None => (
            Status::Off,
            "Turned off in agent.toml ([ledger] enabled = false): what leaves is not recorded here.".into(),
        ),
    };
    vec![
        (
            "The agent is read-only by default",
            if p.work.load || p.work.faults {
                Status::Partial
            } else {
                Status::InPlace
            },
            format!(
                "Checks only connect and read a bounded answer. Load is {}, faults are {} (and this version refuses both). The one thing this page changes is what InOrbit sees, and only from this machine.",
                if p.work.load { "on" } else { "off" },
                if p.work.faults { "on" } else { "off" }
            ),
            "/policy",
        ),
        (
            "Your policy file decides",
            Status::InPlace,
            format!(
                "Every job is admitted against {} ({}) before anything is resolved or connected; {} refused so far. The platform cannot change the file.",
                esc(&s.policy.path),
                short(&s.policy.hash),
                s.sent.results_refused
            ),
            "/policy",
        ),
        (
            "Only what the policy allows leaves",
            Status::InPlace,
            "Hello, heartbeats and results: versions, hashes, timings, status codes, error classes. Never request or response bodies, header values or secrets.".into(),
            "/ledger",
        ),
        ("A ledger of every byte that left", ledger.0, ledger.1, "/ledger"),
        (
            "Code is read inside your network",
            Status::NotBuilt,
            "This agent version has no code-reading path: it reads no repository at all. When Atlas reads code, it will happen here, under a [read] policy (RFC 0097.2).".into(),
            "/policy",
        ),
        (
            "Changes wait for approval",
            Status::NotBuilt,
            "This agent changes nothing, so nothing waits yet. Approval comes with the first kind of work that changes something.".into(),
            "/jobs",
        ),
    ]
}

#[allow(clippy::too_many_lines)] // the page, card by card
fn overview(ctx: &Context, s: &Snapshot) -> String {
    let p = &ctx.policy;
    let mut h = String::new();
    ignored_warning(ctx, &mut h);
    let _ = write!(
        h,
        "<h1>{}</h1><p class=lede>{} in <b>{}</b>, talking to {}. This page is how you check what it does without taking our word for it.</p>",
        esc(&s.agent.name),
        esc(s.agent.agent_id.as_deref().unwrap_or("not enrolled")),
        esc(&s.agent.environment),
        esc(&ctx.api)
    );
    h.push_str("<div class=grid>");
    let since = s
        .connected_since
        .as_deref()
        .map_or_else(|| "—".into(), when);
    let _ = write!(
        h,
        "<div class=card><h3>Connection</h3>{}{}</div>",
        connection_pill(s),
        kv(&[
            ("Platform", format!("<code>{}</code>", esc(&ctx.api))),
            ("Since", since),
            (
                "Last heartbeat",
                s.last_heartbeat_at
                    .as_deref()
                    .map_or_else(|| "—".into(), when)
            ),
            (
                "Last error",
                s.last_error.as_deref().map_or_else(|| "none".into(), esc)
            ),
        ])
    );
    let _ = write!(
        h,
        "<div class=card><h3>Identity</h3>{}</div>",
        kv(&[
            (
                "Agent id",
                format!(
                    "<code>{}</code>",
                    esc(s.agent.agent_id.as_deref().unwrap_or("not enrolled"))
                )
            ),
            ("Name", esc(&s.agent.name)),
            ("Environment", esc(&s.agent.environment)),
            ("Version", esc(&s.agent.version)),
            (
                "Up",
                format!(
                    "{} <span class=muted>(pid {})</span>",
                    duration(s.uptime_secs),
                    s.agent.pid
                )
            ),
        ])
    );
    let _ = write!(
        h,
        "<div class=card><h3>What binds it</h3>{}</div>",
        kv(&[
            ("Policy", short(&s.policy.hash)),
            (
                "Checks",
                s.policy.checks_hash.as_deref().map_or_else(
                    || "none declared".into(),
                    |c| format!(
                        "{} <span class=muted>({} declared)</span>",
                        short(c),
                        s.policy.checks
                    )
                )
            ),
            (
                "Accepts",
                if s.policy.capabilities.is_empty() {
                    "nothing".into()
                } else {
                    esc(&s.policy.capabilities.join(", "))
                }
            ),
            (
                "Ledger head",
                ctx.ledger.as_ref().map_or_else(
                    || "off".into(),
                    |l| {
                        let (seq, head) = l.head();
                        format!("{} <span class=muted>(entry {seq})</span>", short(&head))
                    }
                )
            ),
        ])
    );
    h.push_str("</div><div class=grid>");
    let c = &p.ceilings;
    let _ = write!(
        h,
        "<div class=card><h3>Jobs in the last minute</h3><div class=stat>{} <small>of {} allowed</small></div>{}<div class=muted>[ceilings] max_jobs_per_minute</div></div>",
        s.jobs_last_minute,
        c.max_jobs_per_minute,
        meter(s.jobs_last_minute, u64::from(c.max_jobs_per_minute))
    );
    let _ = write!(
        h,
        "<div class=card><h3>Running now</h3><div class=stat>{} <small>of {} at once</small></div>{}<div class=muted>[ceilings] max_concurrent_jobs; each at most {} s</div></div>",
        s.running_jobs,
        c.max_concurrent_jobs,
        meter(s.running_jobs, u64::from(c.max_concurrent_jobs)),
        c.max_job_ms / 1000
    );
    let _ = write!(
        h,
        "<div class=card><h3>Since start</h3>{}</div>",
        kv(&[
            ("Jobs received", s.received.jobs.to_string()),
            (
                "Results",
                format!(
                    "{} ok, {} failed, {} refused",
                    s.sent.results_ok, s.sent.results_failed, s.sent.results_refused
                )
            ),
            ("Heartbeats", s.sent.heartbeat.to_string()),
            ("Sessions", s.received.sessions.to_string()),
        ])
    );
    h.push_str(
        "</div><h2>What we promise, and where it stands</h2><div class=card><ul class=promises>",
    );
    for (title, status, text, link) in promises(ctx, s) {
        let _ = write!(
            h,
            "<li><b><a href=\"{link}\">{}</a></b>{}<p>{text}</p></li>",
            esc(title),
            badge(status)
        );
    }
    let _ = write!(
        h,
        "</ul></div><h2>How to stop it</h2><p class=lede>{}</p>",
        esc(&s.stop)
    );
    h
}

// ---------------------------------------------------------------- checks

fn target_text(t: &Target) -> String {
    match t {
        Target::Url { url } => url.to_string(),
        Target::HostPort { host, port, .. } => format!("{host}:{port}"),
        Target::Sensor { sensor } => format!("sensor {sensor}"),
    }
}

fn every_text(secs: u64) -> String {
    if secs.is_multiple_of(3600) {
        format!("every {} h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("every {} min", secs / 60)
    } else {
        format!("every {secs} s")
    }
}

fn kind_text(c: &DeclaredCheck) -> &'static str {
    match (c.kind, c.refuse_by) {
        (Kind::Check, _) => "check",
        (Kind::Refuse, Some(RefuseBy::Policy)) => "refusal by this policy",
        (Kind::Refuse, Some(RefuseBy::Platform)) => "refusal by the platform",
        (Kind::Refuse, _) => "refusal by the target",
    }
}

/// Whether a run counts as a pass for this entry.
fn passed(c: &DeclaredCheck, r: &JobRecord) -> bool {
    match (c.kind, c.refuse_by) {
        (Kind::Refuse, Some(RefuseBy::Policy)) => r.verdict == "refused",
        _ => r.verdict == "ok",
    }
}

/// The local view of `fail_after`: up, failing (n of `fail_after`), down, no runs.
fn local_state(c: &DeclaredCheck, runs: &[JobRecord]) -> (String, &'static str) {
    if c.refuse_by == Some(RefuseBy::Platform) {
        return ("platform refuses".into(), "");
    }
    if runs.is_empty() {
        return ("no runs yet".into(), "");
    }
    let failing = runs.iter().rev().take_while(|r| !passed(c, r)).count();
    if failing == 0 {
        ("up".into(), "ok")
    } else if failing >= usize::from(c.fail_after) {
        ("down".into(), "bad")
    } else {
        (format!("failing {failing} of {}", c.fail_after), "warn")
    }
}

fn sparkline(c: &DeclaredCheck, runs: &[JobRecord]) -> String {
    let n = crate::state::CHECK_HISTORY;
    let max = runs.iter().map(|r| r.latency_ms).max().unwrap_or(0).max(1);
    let mut h = format!(
        "<svg class=spark viewBox=\"0 0 {} 28\" preserveAspectRatio=none role=img aria-label=\"last {} runs\">",
        n * 4,
        runs.len()
    );
    let pad = n - runs.len().min(n);
    for i in 0..pad {
        let _ = write!(
            h,
            "<rect class=none x=\"{}\" y=\"26\" width=\"3\" height=\"2\" rx=\"1\" />",
            i * 4
        );
    }
    for (i, r) in runs.iter().enumerate() {
        let class = if r.verdict == "refused" && !passed(c, r) {
            "ref"
        } else if passed(c, r) {
            "ok"
        } else {
            "bad"
        };
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let height = ((r.latency_ms as f64 / max as f64) * 24.0).round().max(4.0) as u64;
        let _ = write!(
            h,
            "<rect class={class} x=\"{}\" y=\"{}\" width=\"3\" height=\"{height}\" rx=\"1\"><title>{} · {} · {} ms</title></rect>",
            (pad + i) * 4,
            28 - height,
            esc(&r.at),
            esc(&r.verdict),
            r.latency_ms
        );
    }
    h.push_str("</svg>");
    h
}

fn cert_days(r: &JobRecord) -> Option<i64> {
    let t = parse_time(r.tls_expires_at.as_deref()?)?;
    Some((t - time::OffsetDateTime::now_utc()).whole_days())
}

fn refusal_note(ctx: &Context, c: &DeclaredCheck) -> Option<String> {
    match c.refuse_by? {
        RefuseBy::Policy => Some(match checks_file::lint_offline(c, &ctx.policy) {
            checks_file::Verdict::Ok | checks_file::Verdict::Warning(_) => {
                "Refused by policy: this agent's policy refuses it, so a run passes when it comes back refused.".into()
            }
            checks_file::Verdict::Error(e) => format!("Guard open: {e}"),
            checks_file::Verdict::NeedsResolve { .. } => {
                "Refused by policy, decided by what the name resolves to (iohr agent checks lint --resolve).".into()
            }
        }),
        RefuseBy::Platform => Some(
            "Refused by the platform: the job never reaches this agent, so there is nothing to run here. The console shows the refusal."
                .into(),
        ),
        RefuseBy::Answer => Some("Refused by the target: passes when the answer is the one expected.".into()),
    }
}

fn checks(ctx: &Context) -> String {
    let mut h = String::from("<h1>Checks</h1>");
    let Some(declared) = &ctx.checks else {
        let _ = write!(
            h,
            "<p class=lede>No checks.toml: this agent declares no checks. The platform can still send it jobs, which the policy decides on (<a href=/jobs>Jobs</a>).</p><p class=muted>{}</p>",
            esc(&ctx.state.snapshot().policy.checks_path)
        );
        return h;
    };
    let runs = ctx.state.check_runs();
    let empty = Vec::new();
    let states: Vec<(String, &str)> = declared
        .entries
        .iter()
        .map(|c| local_state(c, runs.get(&c.key).unwrap_or(&empty)))
        .collect();
    let count = |cls: &str| states.iter().filter(|(_, c)| *c == cls).count();
    let _ = write!(
        h,
        "<p class=lede>{} declared in <code>{}</code> ({}). Each becomes a monitor in the console; this is the same view from this machine, judged on the last {} runs the agent kept. The console decides; this is what the agent saw.</p>",
        declared.entries.len(),
        esc(&declared.path.display().to_string()),
        short(&declared.hash),
        crate::state::CHECK_HISTORY
    );
    let _ = write!(
        h,
        "<div class=grid><div class=card><h3>Up</h3><div class=stat>{}</div></div><div class=card><h3>Failing</h3><div class=stat>{}</div></div><div class=card><h3>Down</h3><div class=stat>{}</div></div><div class=card><h3>No runs yet</h3><div class=stat>{}</div></div></div><h2>Declared</h2><div class=checks>",
        count("ok"),
        count("warn"),
        count("bad"),
        states.iter().filter(|(t, _)| t == "no runs yet").count()
    );
    for (c, (state, cls)) in declared.entries.iter().zip(&states) {
        let r = runs.get(&c.key).unwrap_or(&empty);
        let last = r.last();
        let mut meta = vec![
            kind_text(c).to_owned(),
            c.spec.surface.as_str().to_owned(),
            every_text(c.every_secs),
        ];
        meta.push(format!("down after {}", c.fail_after));
        if let Some(cat) = &c.category {
            meta.push(cat.clone());
        }
        if c.spec.auth.is_some() {
            meta.push("sends a header from a secret (not shown)".into());
        }
        let cert = last.and_then(cert_days).map_or_else(
            || {
                if c.spec.surface == Surface::Tls || c.valid_for_days.is_some() {
                    "—".into()
                } else {
                    "n/a".into()
                }
            },
            |d| format!("{d} d"),
        );
        let _ = write!(
            h,
            "<div class=\"card check\"><div class=head><span class=name>{}</span>{}</div><div class=meta>{}</div><p class=target>{}</p><div class=nums><div><span>Last</span><b>{}</b></div><div><span>Latency</span><b>{}</b></div><div><span>Status</span><b>{}</b></div><div><span>Cert</span><b>{}</b></div></div>{}",
            esc(&c.key),
            pill(cls, state),
            esc(&meta.join(" · ")),
            esc(&target_text(&c.spec.target)),
            last.map_or_else(
                || "—".into(),
                |l| format!("{} · {}", esc(&l.verdict), when(&l.at))
            ),
            last.map_or_else(|| "—".into(), |l| format!("{} ms", l.latency_ms)),
            last.and_then(|l| l.status_code).map_or_else(
                || last
                    .and_then(|l| l.error_class.clone())
                    .map_or_else(|| "—".into(), |e| esc(&e)),
                |s| s.to_string()
            ),
            cert,
            sparkline(c, r)
        );
        if let Some(note) = refusal_note(ctx, c) {
            let _ = write!(h, "<p class=muted>{}</p>", esc(&note));
        }
        h.push_str("</div>");
    }
    h.push_str("</div>");
    h
}

// ---------------------------------------------------------------- policy

/// What this agent can never do: what this version has no code for, and what this
/// policy turns off.
pub(super) fn never(ctx: &Context) -> Vec<(String, &'static str)> {
    let p = &ctx.policy;
    let mut out: Vec<(String, &'static str)> = vec![
        ("Accept a connection from the platform: it only dials out, one WebSocket.".into(), "this version"),
        ("Run a command, a script or code the platform sends: there is no path for it.".into(), "this version"),
        ("Change its own policy, or widen it: the file is read at start and only you edit it.".into(), "this version"),
        ("Send a request or response body, a header value or a secret to the platform.".into(), "this version"),
        ("Read a repository or a document for the platform: this version has no code-reading path.".into(), "this version"),
        (format!(
            "Go past the hard ceilings: {} jobs at once, {} s per job, {} jobs a minute, whatever the policy says.",
            crate::policy::limits::MAX_CONCURRENT_JOBS,
            crate::policy::limits::MAX_JOB_MS / 1000,
            crate::policy::limits::MAX_JOBS_PER_MINUTE
        ), "this version"),
    ];
    if !p.networks.deny.is_empty() {
        out.push((
            format!(
                "Connect to {}, even when allowed.",
                p.networks.deny.join(", ")
            ),
            "[networks] deny",
        ));
    }
    out.push((
        "Connect to a host that is neither in [networks] allow nor inside a bound domain; such a name is not even looked up.".into(),
        "[networks] allow",
    ));
    if !p.work.checks {
        out.push(("Run any check.".into(), "[work] checks = false"));
    }
    let sh = p.share();
    if sh.targets != crate::policy::TargetShare::Full {
        out.push((
            "Tell the platform a declared check's URL, host or address (except a refusal the platform itself must make).".into(),
            if sh.targets == crate::policy::TargetShare::Hash { "[share] targets = \"hash\"" } else { "[share] targets = \"label\"" },
        ));
    }
    if !sh.hostname {
        out.push((
            "Tell the platform this machine's host name.".into(),
            "[share] hostname = false",
        ));
    }
    if !p.work.load {
        out.push(("Generate load.".into(), "[work] load = false"));
    }
    if !p.work.faults {
        out.push(("Inject faults.".into(), "[work] faults = false"));
    }
    let off: Vec<&str> = Surface::ALL
        .iter()
        .filter(|s| !p.surface_allowed(**s))
        .map(|s| s.as_str())
        .collect();
    if !off.is_empty() {
        out.push((format!("Run {} checks.", off.join(", ")), "[work] surfaces"));
    }
    if p.secrets.allow.is_empty() {
        out.push((
            "Use any secret: no job may name one.".into(),
            "[secrets] allow = []",
        ));
    }
    if !p.work.capture {
        out.push((
            "Read traffic counts from the capture companion.".into(),
            "[work] capture = false",
        ));
    }
    if p.work.capture {
        out.push((
            "Receive a packet: the capture companion keeps them for root on this host.".into(),
            "this version",
        ));
    }
    match p.host() {
        None => out.push((
            "Read this machine's sensors, PCI, storage or boots.".into(),
            "[work] host = false",
        )),
        Some(hp) if !hp.journal => out.push((
            "Run journalctl (the only program the host observers can run).".into(),
            "[host] journal = false",
        )),
        Some(_) => {}
    }
    out
}

/// A loud note when the policy has sections this version ignored.
fn ignored_warning(ctx: &Context, h: &mut String) {
    let ignored = ctx.policy.ignored_sections();
    if ignored.is_empty() {
        return;
    }
    let names: Vec<String> = ignored.iter().map(|s| format!("[{s}]")).collect();
    let _ = write!(
        h,
        "<div class=\"note bad\"><b>The policy has sections this agent version does not know, and ignores: {}.</b> They were written for a later version. Upgrade the agent to have them apply, or remove them from <code>{}</code>.</div>",
        esc(&names.join(", ")),
        esc(&ctx.policy_path.display().to_string())
    );
}

/// The choice the policy page shows: the one asked to preview, else the policy's own.
fn chosen(ctx: &Context, view: &View) -> crate::policy::SharePolicy {
    use crate::policy::{SharePolicy, TargetShare};
    let q: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(view.query.as_bytes())
            .into_owned()
            .collect();
    let current = ctx.policy.share();
    let targets = match q.get("targets").map(String::as_str) {
        Some("full") => TargetShare::Full,
        Some("hash") => TargetShare::Hash,
        Some("label") => TargetShare::Label,
        _ => return current,
    };
    SharePolicy {
        targets,
        hostname: matches!(
            q.get("hostname").map(String::as_str),
            Some("on" | "true" | "1")
        ),
        host: current.host,
    }
}

/// "What InOrbit sees": the `[share]` choice, the form that changes it (on this machine,
/// signed in), and a preview of exactly what the next hello would carry.
#[allow(clippy::too_many_lines)] // the form, then the preview
fn share(ctx: &Context, view: &View, h: &mut String) {
    use crate::policy::TargetShare;
    let current = ctx.policy.share();
    let pick = chosen(ctx, view);
    let previewing = pick != current;
    let _ = write!(
        h,
        "<h2 id=share>What InOrbit sees</h2><p class=lede>How much the platform learns about your checks and this machine. Chosen here or with <code>iohr agent share</code>, written to <code>[share]</code> in the policy{}. Whatever you choose, every message that leaves is in the <a href=/ledger>ledger</a>.</p>",
        if ctx.policy.share.is_some() {
            ""
        } else {
            " (not set yet: these are the defaults)"
        }
    );
    match &view.flash {
        Some((true, m)) => {
            let _ = write!(h, "<div class=\"note ok\">{}</div>", esc(m));
        }
        Some((false, m)) => {
            let _ = write!(h, "<div class=\"note bad\">{}</div>", esc(m));
        }
        None if view.query.contains("applied=1") => {
            h.push_str("<div class=\"note ok\">Applied. The agent reloaded its policy and opened a new session; the change is in the ledger.</div>");
        }
        None => {}
    }
    let opts = [
        (
            TargetShare::Full,
            "Everything",
            "full",
            "Each check's URL, or host and port, as you wrote it.",
        ),
        (
            TargetShare::Hash,
            "Fingerprint",
            "hash",
            "A label and a keyed hash: InOrbit sees when a target changes, never what it is. The default.",
        ),
        (
            TargetShare::Label,
            "Label only",
            "label",
            "Only the label you gave each check. Nothing derived from its target leaves.",
        ),
    ];
    h.push_str("<form class=share method=get action=\"/policy#share\"><fieldset><legend>Check targets</legend><div class=opts>");
    for (level, title, value, what) in opts {
        let _ = write!(
            h,
            "<label class=opt><input type=radio name=targets value={value}{}><span><b>{title}</b>{}<br><span class=muted>{what}</span></span></label>",
            if pick.targets == level {
                " checked"
            } else {
                ""
            },
            if current.targets == level {
                " <span class=muted>(now)</span>"
            } else {
                ""
            }
        );
    }
    let host = crate::host::sysfs::host_name();
    let _ = write!(
        h,
        "</div></fieldset><label class=switch><input type=checkbox name=hostname value=on{}><span><b>Send host name</b> <span class=muted>({}; off, the console shows the agent's name, now {})</span></span></label>",
        if pick.hostname { " checked" } else { "" },
        esc(&host),
        if current.hostname { "on" } else { "off" }
    );
    if let Some(c) = &view.csrf {
        let _ = write!(h, "<input type=hidden name=csrf value=\"{}\">", esc(c));
    }
    h.push_str("<div class=actions><button type=submit>Preview</button>");
    if view.can_change && view.signed_in {
        h.push_str("<button class=primary type=submit formmethod=post formaction=/policy/share>Apply</button><span class=muted>Rewrites only <code>[share]</code> in the policy file (comments kept), reloads the agent and records the change in the ledger.</span>");
    } else if view.can_change {
        h.push_str("<span class=muted>To change it, open this page signed in: <code>iohr agent page --open</code> on this machine. Or run <code>iohr agent share full|hash|label</code>.</span>");
    } else {
        h.push_str("<span class=muted>Changed only on the agent's own machine: <code>iohr agent share full|hash|label</code>, or this page opened there.</span>");
    }
    h.push_str("</div></form>");

    // The preview: exactly what the next hello would carry.
    let preview = crate::share::preview(ctx.checks.as_deref(), &pick, &ctx.share_key);
    let _ = write!(
        h,
        "<h3 class=gap>{}</h3>",
        if previewing {
            "Preview: the next hello, if you apply this"
        } else {
            "The next hello carries"
        }
    );
    if let Some(declared) = &ctx.checks {
        h.push_str("<div class=scroll><table class=t><tr><th>Check</th><th>Shown as</th><th>InOrbit gets</th></tr>");
        for c in &declared.entries {
            let l = crate::share::level_for(c, pick.targets);
            let gets = match l {
                TargetShare::Full if l != pick.targets => format!(
                    "{} <span class=muted>(a refusal the platform must make needs its target)</span>",
                    esc(&target_text(&c.spec.target))
                ),
                TargetShare::Full => esc(&target_text(&c.spec.target)),
                TargetShare::Hash => "a keyed hash; the target stays on this agent".into(),
                TargetShare::Label => "the label only; the target stays on this agent".into(),
            };
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{gets}</td></tr>",
                esc(&c.key),
                esc(crate::share::label(c))
            );
        }
        h.push_str("</table></div>");
    } else {
        h.push_str("<p class=muted>No checks.toml: the hello declares no checks.</p>");
    }
    let _ = write!(
        h,
        "<details class=gap><summary>The JSON itself ({} bytes)</summary><pre>{}</pre></details><p class=muted>Metadata: the reported part of agent.toml's <code>[metadata]</code> (site, country, owner team, data classes, trust domain), only what devops wrote there; <code>[metadata] report = false</code> sends none.</p>",
        serde_json::to_string(&preview).unwrap_or_default().len(),
        esc(&serde_json::to_string_pretty(&preview).unwrap_or_default())
    );
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        return "<span class=muted>none</span>".into();
    }
    let mut h = String::from("<ul class=list>");
    for i in items {
        let _ = write!(h, "<li><code>{}</code></li>", esc(i));
    }
    h.push_str("</ul>");
    h
}

fn on_off(b: bool) -> String {
    if b { pill("ok", "on") } else { pill("", "off") }
}

fn policy(ctx: &Context, view: &View) -> String {
    let p = &ctx.policy;
    let s = ctx.state.snapshot();
    let mut h = String::new();
    ignored_warning(ctx, &mut h);
    let _ = write!(
        h,
        "<h1>Policy</h1><p class=lede>The file on this machine that decides what this agent may reach and do. The platform cannot change it; work outside it is refused here and the refusal is shown in the console.</p><div class=grid><div class=card>{}</div></div>",
        kv(&[
            ("File", format!("<code>{}</code>", esc(&s.policy.path))),
            (
                "Hash",
                format!("<code class=mono>{}</code>", esc(&s.policy.hash))
            ),
            ("Environment", esc(&p.environment)),
        ])
    );
    share(ctx, view, &mut h);
    h.push_str("<h2>What this agent can never do</h2><div class=card><ul class=\"list never\">");
    for (what, why) in never(ctx) {
        let _ = write!(
            h,
            "<li>{} <span class=muted>({})</span></li>",
            esc(&what),
            esc(why)
        );
    }
    h.push_str("</ul></div>");
    let _ = write!(
        h,
        "<h2>What it may reach</h2><div class=grid><div class=card><h3>Allowed networks and hosts</h3>{}</div><div class=card><h3>Bound domains</h3>{}</div><div class=card><h3>Never reached</h3>{}</div></div>",
        list(&p.networks.allow),
        list(&p.domains.bound),
        list(&p.networks.deny)
    );
    let mut surfaces = String::from("<table class=kv>");
    for sfc in Surface::ALL {
        let _ = write!(
            surfaces,
            "<tr><th>{}</th><td>{}</td></tr>",
            sfc.as_str(),
            on_off(p.surface_allowed(sfc))
        );
    }
    surfaces.push_str("</table>");
    let _ = write!(
        h,
        "<h2>Which work is on</h2><div class=grid><div class=card><h3>Kinds of work</h3>{}</div><div class=card><h3>Check surfaces</h3>{surfaces}</div><div class=card><h3>Ceilings</h3>{}</div><div class=card><h3>Secrets a job may name</h3>{}<p class=muted>References only; values are read on this machine at the moment of a check and never shown or sent.</p></div></div>",
        kv(&[
            ("checks", on_off(p.work.checks)),
            ("load", on_off(p.work.load)),
            ("faults", on_off(p.work.faults)),
            ("capture", on_off(p.work.capture)),
            ("host", on_off(p.work.host)),
        ]),
        kv(&[
            (
                "At once",
                format!(
                    "{} <span class=muted>(hard limit {})</span>",
                    p.ceilings.max_concurrent_jobs,
                    crate::policy::limits::MAX_CONCURRENT_JOBS
                )
            ),
            (
                "Per job",
                format!(
                    "{} ms <span class=muted>(hard limit {})</span>",
                    p.ceilings.max_job_ms,
                    crate::policy::limits::MAX_JOB_MS
                )
            ),
            (
                "Per minute",
                format!(
                    "{} <span class=muted>(hard limit {})</span>",
                    p.ceilings.max_jobs_per_minute,
                    crate::policy::limits::MAX_JOBS_PER_MINUTE
                )
            ),
        ]),
        list(&p.secrets.allow)
    );
    let _ = write!(
        h,
        "<h2>The effective policy</h2><p class=lede>Defaults filled in, as the agent hashes it.</p><pre>{}</pre>",
        esc(&p.to_toml().unwrap_or_default())
    );
    h
}

// ---------------------------------------------------------------- ledger

fn ledger(ctx: &Context) -> String {
    let mut h = String::from("<h1>What left this machine</h1>");
    let Some(l) = &ctx.ledger else {
        h.push_str("<p class=lede>The egress ledger is off (<code>[ledger] enabled = false</code> in agent.toml). Messages to the platform are not recorded on this machine.</p>");
        return h;
    };
    let (seq, head) = l.head();
    let files = l.files();
    let size: u64 = files.iter().map(|(_, _, n)| n).sum();
    let _ = write!(
        h,
        "<p class=lede>Before the agent sends the platform anything, it writes one line here: when, what kind, how many bytes, the SHA-256 of the exact bytes, the policy and rule that allowed it, and where it went. Each line carries the hash of the one before, so a removed or edited line breaks the chain. Check it yourself with <code>iohr agent ledger verify</code>.</p>"
    );
    let cfg = l.config();
    let _ = write!(
        h,
        "<div class=grid><div class=card><h3>Chain</h3>{}</div><div class=card><h3>Files</h3>{}</div>",
        kv(&[
            ("Entries", seq.to_string()),
            ("Head", short(&head)),
            (
                "Writes",
                l.problem().map_or_else(
                    || pill("ok", "recording"),
                    |p| format!("{} {}", pill("bad", "failing: nothing is sent"), esc(&p))
                )
            ),
        ]),
        kv(&[
            (
                "Where",
                format!("<code>{}</code>", esc(&l.dir().display().to_string()))
            ),
            (
                "Kept",
                format!("{} days, at most {} MB", cfg.retain_days, cfg.max_mb)
            ),
            (
                "Now",
                format!("{} files, {} KB", files.len(), size.div_ceil(1024))
            ),
            (
                "Export",
                "<a href=/ledger.jsonl>ledger.jsonl</a> · <code>iohr agent ledger export</code>"
                    .into()
            ),
        ])
    );
    let totals = l.totals();
    let mut t = String::new();
    for (kind, tot) in &totals {
        let _ = write!(
            t,
            "<tr><th>{}</th><td>{} message{}, {} bytes</td></tr>",
            esc(kind),
            tot.messages,
            if tot.messages == 1 { "" } else { "s" },
            tot.bytes
        );
    }
    if t.is_empty() {
        t.push_str("<tr><td class=muted>nothing yet</td></tr>");
    }
    let _ = write!(
        h,
        "<div class=card><h3>Since start</h3><table class=kv>{t}</table></div></div>"
    );
    let _ = write!(
        h,
        "<div class=note><b>Built</b>: metadata of every message (session open, token request, hello, heartbeat, result), chained, rotated, exportable, verifiable. <b>Not built yet</b>: keeping the payloads themselves for a few days (<code>keep_payload_days</code>), the platform's receipts with the same hashes, the daily reconciliation of both, and the chain head in the heartbeat (ADR 0049). The ledger is as trustworthy as this machine: someone who can rewrite these files can rewrite the whole chain; the platform's receipts will be the outside check.</div>"
    );
    h.push_str("<h2>Latest 50</h2><p class=muted>Every entry: <a href=/ledger.jsonl>ledger.jsonl</a>.</p><div class=scroll><table class=t><tr><th>#</th><th>When</th><th>Kind</th><th>Bytes</th><th>SHA-256</th><th>Allowed by</th><th class=hide-sm>Job</th><th class=hide-sm>To</th></tr>");
    for e in l.recent(50) {
        let _ = write!(
            h,
            "<tr><td class=n>{}</td><td>{}</td><td>{}</td><td class=n>{}</td><td>{}</td><td><code>{}</code></td><td class=hide-sm><code>{}</code></td><td class=hide-sm><code>{}</code></td></tr>",
            e.seq,
            when(&e.at),
            esc(&e.kind),
            e.bytes,
            short(&e.sha256),
            esc(&e.rule),
            esc(e.job_id.as_deref().unwrap_or("")),
            esc(&e.destination)
        );
    }
    h.push_str("</table></div>");
    h
}

// ---------------------------------------------------------------- jobs

fn jobs(s: &Snapshot) -> String {
    let mut h = String::from(
        "<h1>Jobs and refusals</h1><p class=lede>What the platform asked this agent to do in the last day, and what the agent said. A refused job never resolved a name or opened a connection.</p>",
    );
    let _ = write!(
        h,
        "<div class=grid><div class=card><h3>Received</h3><div class=stat>{}</div></div><div class=card><h3>Ok</h3><div class=stat>{}</div></div><div class=card><h3>Failed</h3><div class=stat>{}</div></div><div class=card><h3>Refused</h3><div class=stat>{}</div></div></div>",
        s.received.jobs, s.sent.results_ok, s.sent.results_failed, s.sent.results_refused
    );
    let refused: Vec<&JobRecord> = s
        .recent_jobs
        .iter()
        .rev()
        .filter(|j| j.verdict == "refused")
        .take(50)
        .collect();
    h.push_str("<h2>Refusals</h2>");
    if refused.is_empty() {
        h.push_str("<p class=muted>None in the last day.</p>");
    } else {
        h.push_str("<div class=scroll><table class=t><tr><th>When</th><th>Kind</th><th>Check</th><th>Why</th></tr>");
        for j in refused {
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                when(&j.at),
                esc(&j.kind),
                esc(j.key.as_deref().unwrap_or("—")),
                esc(j.reason.as_deref().unwrap_or("refused by the local policy"))
            );
        }
        h.push_str("</table></div>");
    }
    let _ = write!(
        h,
        "<h2>Latest jobs</h2><p class=muted>The newest 50 of {} in the last day; all of them: <a href=/api/v1/jobs.json>jobs.json</a>.</p>",
        s.recent_jobs.len()
    );
    if s.recent_jobs.is_empty() {
        h.push_str("<p class=muted>No job in the last day. The platform sends jobs for the declared checks on their schedule.</p>");
        return h;
    }
    h.push_str("<div class=scroll><table class=t><tr><th>Finished</th><th>Verdict</th><th>Check</th><th>Surface</th><th class=hide-sm>Target host</th><th>ms</th><th class=hide-sm>Detail</th><th class=hide-sm>Job</th></tr>");
    for j in s.recent_jobs.iter().rev().take(50) {
        let detail = j
            .reason
            .clone()
            .or_else(|| j.status_code.map(|c| format!("HTTP {c}")))
            .or_else(|| j.error_class.clone())
            .unwrap_or_default();
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=hide-sm>{}</td><td class=n>{}</td><td class=hide-sm>{}</td><td class=hide-sm><code>{}</code></td></tr>",
            when(&j.at),
            verdict_pill(&j.verdict),
            esc(j.key.as_deref().unwrap_or("—")),
            esc(j.surface.as_deref().unwrap_or(&j.kind)),
            esc(j.target_host.as_deref().unwrap_or("")),
            j.latency_ms,
            esc(&detail),
            esc(j.job_id.as_deref().unwrap_or(""))
        );
    }
    h.push_str("</table></div>");
    h
}

// ---------------------------------------------------------------- host

fn host(ctx: &Context, s: &Snapshot) -> String {
    let mut h = String::from("<h1>This host</h1>");
    match ctx.policy.host() {
        None => {
            let _ = write!(
                h,
                "<p class=lede>Host observation is {} by policy (<code>[work] host = false</code>): the agent does not read this machine's sensors, PCI topology, storage, pressure or boots.</p>",
                pill("", "off")
            );
        }
        Some(hp) => {
            let _ = write!(
                h,
                "<p class=lede>Read from /sys and /proc on this machine, read-only, every {} s. Only the results of declared hwmon checks leave it; the rest stays here.</p>",
                hp.sample_secs
            );
            if !cfg!(target_os = "linux") {
                h.push_str("<div class=note>This is not Linux: the host observers read /sys and /proc, which this system does not have, so they find nothing here.</div>");
            }
            if let Some(x) = &s.host {
                let _ = write!(
                    h,
                    "<div class=grid><div class=card><h3>Sampler</h3>{}</div></div>",
                    kv(&[
                        ("Sensors", x.sensors.to_string()),
                        ("Samples in the window", x.samples.to_string()),
                        (
                            "Last sample",
                            format!(
                                "{} ({} µs, slowest {} µs)",
                                when(&x.last_sample_at),
                                x.last_cost_us,
                                x.max_cost_us
                            )
                        ),
                        (
                            "Chipset",
                            x.chipset_millicelsius.map_or_else(
                                || "—".into(),
                                |c| format!("{}.{} °C", c / 1000, (c % 1000).abs() / 100)
                            )
                        ),
                    ])
                );
            }
            match &s.host_report {
                None => h.push_str("<p class=muted>The first reading is on its way.</p>"),
                Some(r) => {
                    let _ = write!(
                        h,
                        "<h2>Findings</h2><p class=muted>Read {}. Each finding names its verdict: supported, not supported, or unknown when the readings do not decide it.</p>",
                        when(&r.at)
                    );
                    if r.findings.is_empty() {
                        h.push_str("<p class=muted>No finding.</p>");
                    } else {
                        h.push_str("<div class=scroll><table class=t><tr><th>Finding</th><th>About</th><th>Verdict</th><th>Why</th></tr>");
                        for f in &r.findings {
                            let v = match f.verdict.as_str() {
                                "supported" => pill("warn", "supported"),
                                "not_supported" => pill("ok", "not supported"),
                                _ => pill("", "unknown"),
                            };
                            let _ = write!(
                                h,
                                "<tr><td>{}</td><td><code>{}</code></td><td>{v}</td><td>{}</td></tr>",
                                esc(&f.check),
                                esc(&f.subject),
                                esc(&f.reason)
                            );
                        }
                        h.push_str("</table></div>");
                    }
                    let _ = write!(
                        h,
                        "<h2>Sensors, PCIe and storage</h2><pre>{}</pre>",
                        esc(&r.text)
                    );
                }
            }
        }
    }
    h.push_str("<h2>Traffic</h2>");
    match &s.capture {
        None => {
            let _ = write!(
                h,
                "<p class=lede>Capture is {} by policy (<code>[work] capture = false</code>): the agent reads no traffic counts.</p>",
                pill("", "off")
            );
        }
        Some(t) => traffic(&mut h, t),
    }
    h
}

/// The capture companion's counts. None of it is sent (only the `capture:*` strings in
/// the hello).
fn traffic(h: &mut String, t: &crate::capture::TrafficInfo) {
    let mut rows: Vec<(&str, String)> = vec![("Companion", esc(&t.state))];
    if let Some(r) = &t.reason {
        rows.push(("Why", esc(r)));
    }
    rows.push((
        "Announced",
        if t.capabilities.is_empty() {
            "nothing".into()
        } else {
            esc(&t.capabilities.join(", "))
        },
    ));
    if let Some(a) = t.age_secs {
        rows.push(("Numbers from", format!("{a} s ago")));
    }
    if let Some(c) = &t.counts {
        rows.push((
            "Ingress",
            format!(
                "{} skb, {} bytes",
                c.headers.ingress.packets, c.headers.ingress.bytes
            ),
        ));
        rows.push((
            "Egress",
            format!(
                "{} skb, {} bytes",
                c.headers.egress.packets, c.headers.egress.bytes
            ),
        ));
        rows.push((
            "Drops",
            format!(
                "{} rate limited, {} ring buffer full, {} flows evicted",
                c.drops.rate_limited, c.drops.ring_buffer_full, c.drops.flows_evicted
            ),
        ));
        rows.push((
            "Flows",
            format!(
                "{} seen, {} active, {} recognised",
                c.flows.seen, c.flows.active, c.flows.recognised
            ),
        ));
        rows.push(("HTTP/1 requests", c.protocols.http1_requests.to_string()));
        rows.push(("TLS handshakes", c.protocols.tls_client_hellos.to_string()));
        rows.push(("DNS queries", c.protocols.dns_queries.to_string()));
        rows.push((
            "HTTP/2 connections (gRPC calls)",
            format!(
                "{} ({})",
                c.protocols.http2_connections, c.protocols.grpc_calls
            ),
        ));
        rows.push((
            "Owners",
            format!(
                "{} sockets, {} owners, {} flows owned, {} unowned",
                c.owners.sockets, c.owners.owners, c.owners.flows_owned, c.owners.flows_unowned
            ),
        ));
        rows.push(("Request timing", format!(
            "{} requests, {} answered ({} 2xx, {} 4xx, {} 5xx), {} unanswered, {} connections out of sync",
            c.timing.requests, c.timing.responses, c.timing.status_classes.c2xx, c.timing.status_classes.c4xx, c.timing.status_classes.c5xx, c.timing.unanswered, c.timing.unsynced
        )));
        rows.push(("Whole packets", if c.packets.enabled {
            format!("on: {} copied, {} rate limited, {} ring buffer full, {} pcap files made by root on this host", c.packets.copied, c.packets.rate_limited, c.packets.ring_buffer_full, c.packets.pcaps_written)
        } else {
            "off".into()
        }));
        rows.push(("TCP", format!(
            "{} established, {} listening, {} retransmits, {} resets in, {} out, {} listen overflows",
            c.tcp.established, c.tcp.listening, c.tcp.retransmits_sampled, c.tcp.resets_in, c.tcp.resets_out, c.tcp.host.listen_overflows
        )));
    }
    let _ = write!(
        h,
        "<p class=lede>Counted by iohr-capture on this host. Counts only; they stay on this machine. The platform learns only which capture layers this host offers.</p><div class=card>{}</div><p class=muted>Names, routes, paths and addresses: <code>iohr agent capture status --tables</code> on this host. Packets never reach the agent.</p>",
        kv(&rows)
    );
}

// ---------------------------------------------------------------- logs

fn logs() -> String {
    let lines = crate::logbuf::tail(300);
    let mut h = format!(
        "<h1>Logs</h1><p class=lede>The agent's own last {} lines (info and above), kept in memory only and redacted before they were stored. The full log is where the agent's service writes it (journal, launchd log, container log).</p>",
        lines.len()
    );
    if lines.is_empty() {
        h.push_str("<p class=muted>Nothing yet.</p>");
        return h;
    }
    h.push_str("<div class=scroll><table class=\"t logs\"><tr><th>When</th><th>Level</th><th>Message</th></tr>");
    for l in lines.iter().rev() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td class=\"lv-{}\">{}</td><td>{}</td></tr>",
            when(&l.at),
            esc(&l.level),
            esc(&l.level),
            esc(&l.text)
        );
    }
    h.push_str("</table></div>");
    h
}

// ---------------------------------------------------------------- JSON

fn api(ctx: &Context, s: &Snapshot, name: &str) -> Value {
    match name {
        "overview" => json!({
            "agent": s.agent,
            "api": ctx.api,
            "connected": s.connected,
            "connected_since": s.connected_since,
            "revoked": s.revoked,
            "last_error": s.last_error,
            "last_heartbeat_at": s.last_heartbeat_at,
            "started_at": s.started_at,
            "uptime_secs": s.uptime_secs,
            "policy_hash": s.policy.hash,
            "checks_hash": s.policy.checks_hash,
            "jobs_last_minute": s.jobs_last_minute,
            "running_jobs": s.running_jobs,
            "ceilings": {
                "max_jobs_per_minute": ctx.policy.ceilings.max_jobs_per_minute,
                "max_concurrent_jobs": ctx.policy.ceilings.max_concurrent_jobs,
                "max_job_ms": ctx.policy.ceilings.max_job_ms,
            },
            "sent": s.sent,
            "received": s.received,
            "ledger_head": ctx.ledger.as_ref().map(|l| { let (seq, hash) = l.head(); json!({"seq": seq, "hash": hash}) }),
            "promises": promises(ctx, s).into_iter().map(|(t, st, _, _)| json!({"promise": t, "status": match st {
                Status::InPlace => "in_place", Status::Partial => "partial", Status::NotBuilt => "not_built", Status::Off => "off" }})).collect::<Vec<_>>(),
        }),
        "checks" => {
            let runs = ctx.state.check_runs();
            let empty = Vec::new();
            json!({
                "hash": ctx.checks.as_ref().map(|c| c.hash.clone()),
                "checks": ctx.checks.as_ref().map(|d| d.entries.iter().map(|c| {
                    let r = runs.get(&c.key).unwrap_or(&empty);
                    let (state, _) = local_state(c, r);
                    let mut w = c.to_wire();
                    if let Some(o) = w.as_object_mut() {
                        // The reference a header is read from stays on this page's side.
                        if o.remove("auth").is_some() {
                            o.insert("auth".into(), json!("secret reference (not shown)"));
                        }
                        o.insert("local_state".into(), json!(state));
                        o.insert("runs".into(), json!(r));
                    }
                    w
                }).collect::<Vec<_>>()),
            })
        }
        "policy" => json!({
            "path": s.policy.path,
            "hash": s.policy.hash,
            "policy": serde_json::to_value(&*ctx.policy).unwrap_or_default(),
            "share": ctx.policy.share(),
            "share_set": ctx.policy.share.is_some(),
            "ignored_sections": ctx.policy.ignored_sections(),
            "never": never(ctx).into_iter().map(|(what, why)| json!({"what": what, "because": why})).collect::<Vec<_>>(),
        }),
        "ledger" => match &ctx.ledger {
            None => json!({"enabled": false}),
            Some(l) => {
                let (seq, head) = l.head();
                json!({
                    "enabled": true,
                    "dir": l.dir(),
                    "retain_days": l.config().retain_days,
                    "max_mb": l.config().max_mb,
                    "seq": seq,
                    "head": head,
                    "problem": l.problem(),
                    "totals": l.totals(),
                    "recent": l.recent(200),
                })
            }
        },
        "jobs" => json!({ "received": s.received, "sent": s.sent, "jobs": s.recent_jobs }),
        "host" => json!({
            "enabled": ctx.policy.host().is_some(),
            "sampler": s.host,
            "report": s.host_report,
            "capture": s.capture,
        }),
        "logs" => json!({ "lines": crate::logbuf::tail(300) }),
        _ => Value::Null,
    }
}
