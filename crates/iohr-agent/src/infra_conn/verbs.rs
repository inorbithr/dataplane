//! The verb tables: which argv each connection kind accepts, in which class.
//!
//! The caller's argv is parsed against a table, never passed along. A verb names its
//! leading words, its positionals and the flags it knows, each with a validator for the
//! value; anything else is refused before a process starts. What runs is then *built*
//! from the parsed words in a fixed order, so two spellings of one request build the same
//! argv, and a plan's apply form can be compared with the apply that is asked for.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::Kind;

/// What a verb may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Looks; runs freely, audited.
    Read,
    /// Works out a change and saves a plan artifact; the artifact's sha256 is the plan hash.
    Plan,
    /// Changes something; runs only on an approval pinned to a saved plan's hash.
    Apply,
}

impl Class {
    /// The word used in audit lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Plan => "plan",
            Self::Apply => "apply",
        }
    }
}

/// One word of the argv that is run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum Arg {
    /// Passed as it is.
    Lit(String),
    /// A file in the connection's working directory, by relative path. The plan snapshots
    /// it; what runs is the snapshot.
    File(String),
    /// Where `tofu plan` writes its plan file.
    PlanOut,
    /// The saved plan file `tofu apply` reads.
    PlanIn,
}

impl Arg {
    fn lit(s: &str) -> Self {
        Self::Lit(s.to_owned())
    }
}

/// Why an argv was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub String);

fn no<T>(why: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(why.into()))
}

/// A parsed, allowed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// Its kind.
    pub kind: Kind,
    /// Its class.
    pub class: Class,
    /// The verb's name (`get`, `diff`, `state list`).
    pub verb: &'static str,
    /// Which binary: the connection's `bin` or its `aux_bin`.
    pub aux: bool,
    /// What follows the connection's fixed prefix.
    pub args: Vec<Arg>,
    /// Exit codes that mean the command did its job (`diff` exits 1 when there is a diff).
    pub ok_codes: &'static [i32],
    /// For a plan: the apply it makes possible.
    pub apply: Option<Vec<Arg>>,
}

/// How a value is checked.
#[derive(Debug, Clone, Copy)]
enum V {
    /// A name: letters, digits and `. _ - : / =`, at most 253, not starting with `-`.
    Name,
    /// Resources: names joined by `,` or `/`; never a secret.
    Res,
    /// A label or field selector.
    Sel,
    /// A whole number up to the bound.
    Int(u32),
    /// `json`, `yaml`, `name`, `wide` (and `table` for helm).
    Out,
    /// A duration such as `5m`.
    Dur,
    /// A file below the working directory.
    File,
    /// A helm chart reference.
    Chart,
    /// A chart version.
    Ver,
    /// A systemd unit.
    Unit,
    /// One of these.
    One(&'static [&'static str]),
    /// A host pattern, tag list or tofu address.
    Pat,
}

fn name_chars(s: &str, extra: &[u8], max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('-')
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') || extra.contains(&b)
        })
}

impl V {
    fn check(self, s: &str) -> Result<(), Refused> {
        let ok = match self {
            Self::Name => name_chars(s, b":/=", 253),
            Self::Res => {
                name_chars(s, b",/:", 253)
                    && !s.split([',', '/']).any(|p| {
                        let p = p.to_ascii_lowercase();
                        p == "secret" || p == "secrets" || p.starts_with("secret.")
                    })
            }
            Self::Sel => name_chars(s, b",=!()/: ", 253) && !s.starts_with(' '),
            Self::Int(max) => s.parse::<u32>().is_ok_and(|n| n >= 1 && n <= max),
            Self::Out => matches!(s, "json" | "yaml" | "name" | "wide" | "table"),
            Self::Dur => {
                s.len() <= 10
                    && s.ends_with(['s', 'm', 'h'])
                    && s[..s.len() - 1].bytes().all(|b| b.is_ascii_digit())
                    && s.len() > 1
            }
            Self::File => rel_path(s),
            Self::Chart => name_chars(s, b"/:", 253) && !s.contains(".."),
            Self::Ver => name_chars(s, b"+", 64),
            Self::Unit => name_chars(s, b"@:", 128),
            Self::One(set) => set.contains(&s),
            Self::Pat => name_chars(s, b",:!&[]*", 253),
        };
        if ok {
            Ok(())
        } else {
            no(format!("value {s:?} is not allowed here"))
        }
    }
}

/// A relative path with plain components: no `..`, no absolute start, no shell-ish byte.
fn rel_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 240
        && !s.starts_with(['/', '-'])
        && s.split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && name_chars(c, b"", 128))
}

struct F {
    names: &'static [&'static str],
    canon: &'static str,
    v: V,
}
struct B {
    names: &'static [&'static str],
    canon: &'static str,
}

struct Verb {
    kind: Kind,
    /// The verb's name, also the apply verb's name a plan points to.
    id: &'static str,
    class: Class,
    /// Leading words of the caller's argv.
    words: &'static [&'static str],
    aux: bool,
    /// Always emitted after the words.
    fixed: &'static [Fx],
    pos: &'static [V],
    min_pos: usize,
    flags: &'static [F],
    bools: &'static [B],
    /// Flags that must be present.
    need: &'static [&'static str],
    /// Bools accepted and not emitted (`fixed` carries them).
    swallow: &'static [&'static str],
    /// A flag put in when the caller gave none.
    default: &'static [(&'static str, &'static str)],
    ok: &'static [i32],
    /// The apply verb a plan leads to.
    apply_id: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum Fx {
    L(&'static str),
    PlanOut,
    PlanIn,
}

const NS: F = F {
    names: &["-n", "--namespace"],
    canon: "--namespace",
    v: V::Name,
};
const OUT: F = F {
    names: &["-o", "--output"],
    canon: "--output",
    v: V::Out,
};
const SEL: F = F {
    names: &["-l", "--selector"],
    canon: "--selector",
    v: V::Sel,
};
const FILE: F = F {
    names: &["-f", "--filename"],
    canon: "--filename",
    v: V::File,
};
const VALUES: F = F {
    names: &["-f", "--values"],
    canon: "--values",
    v: V::File,
};
const VERSION: F = F {
    names: &["--version"],
    canon: "--version",
    v: V::Ver,
};
const LIMIT: F = F {
    names: &["-l", "--limit"],
    canon: "--limit",
    v: V::Pat,
};
const TAGS: F = F {
    names: &["-t", "--tags"],
    canon: "--tags",
    v: V::Pat,
};
const SKIP: F = F {
    names: &["--skip-tags"],
    canon: "--skip-tags",
    v: V::Pat,
};

const NONE_F: &[F] = &[];
const NONE_B: &[B] = &[];
const NONE_S: &[&str] = &[];
const NONE_D: &[(&str, &str)] = &[];

#[allow(clippy::too_many_lines)] // a table
const VERBS: &[Verb] = &[
    // kubectl: read
    Verb {
        kind: Kind::Kubectl,
        id: "get",
        class: Class::Read,
        words: &["get"],
        aux: false,
        fixed: &[],
        pos: &[V::Res, V::Name],
        min_pos: 1,
        flags: &[
            NS,
            OUT,
            SEL,
            F {
                names: &["--field-selector"],
                canon: "--field-selector",
                v: V::Sel,
            },
        ],
        bools: &[
            B {
                names: &["--show-labels"],
                canon: "--show-labels",
            },
            B {
                names: &["--no-headers"],
                canon: "--no-headers",
            },
        ],
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Kubectl,
        id: "describe",
        class: Class::Read,
        words: &["describe"],
        aux: false,
        fixed: &[],
        pos: &[V::Res, V::Name],
        min_pos: 1,
        flags: &[NS, SEL],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Kubectl,
        id: "logs",
        class: Class::Read,
        words: &["logs"],
        aux: false,
        fixed: &[Fx::L("--limit-bytes=1048576")],
        pos: &[V::Name],
        min_pos: 1,
        flags: &[
            NS,
            F {
                names: &["-c", "--container"],
                canon: "--container",
                v: V::Name,
            },
            F {
                names: &["--tail"],
                canon: "--tail",
                v: V::Int(1000),
            },
            F {
                names: &["--since"],
                canon: "--since",
                v: V::Dur,
            },
        ],
        bools: &[
            B {
                names: &["-p", "--previous"],
                canon: "--previous",
            },
            B {
                names: &["--timestamps"],
                canon: "--timestamps",
            },
        ],
        need: &[],
        swallow: NONE_S,
        default: &[("--tail", "200")],
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Kubectl,
        id: "top",
        class: Class::Read,
        words: &["top"],
        aux: false,
        fixed: &[],
        pos: &[V::One(&["pods", "pod", "nodes", "node"])],
        min_pos: 1,
        flags: &[NS],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Kubectl,
        id: "api-resources",
        class: Class::Read,
        words: &["api-resources"],
        aux: false,
        fixed: &[],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Kubectl,
        id: "version",
        class: Class::Read,
        words: &["version"],
        aux: false,
        fixed: &[],
        pos: &[],
        min_pos: 0,
        flags: &[OUT],
        bools: &[B {
            names: &["--client"],
            canon: "--client",
        }],
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Kubectl,
        id: "auth can-i",
        class: Class::Read,
        words: &["auth", "can-i"],
        aux: false,
        fixed: &[],
        pos: &[V::Name, V::Res, V::Name],
        min_pos: 2,
        flags: &[NS],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0, 1],
        apply_id: None,
    },
    // kubectl: plan and apply
    Verb {
        kind: Kind::Kubectl,
        id: "diff",
        class: Class::Plan,
        words: &["diff"],
        aux: false,
        fixed: &[Fx::L("--server-side")],
        pos: &[],
        min_pos: 0,
        flags: &[FILE, NS],
        bools: NONE_B,
        need: &["--filename"],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0, 1],
        apply_id: Some("apply"),
    },
    Verb {
        kind: Kind::Kubectl,
        id: "apply",
        class: Class::Apply,
        words: &["apply"],
        aux: false,
        fixed: &[Fx::L("--server-side")],
        pos: &[],
        min_pos: 0,
        flags: &[FILE, NS],
        bools: NONE_B,
        need: &["--filename"],
        swallow: &["--server-side"],
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    // helm: read
    Verb {
        kind: Kind::Helm,
        id: "list",
        class: Class::Read,
        words: &["list"],
        aux: false,
        fixed: &[],
        pos: &[],
        min_pos: 0,
        flags: &[NS, OUT],
        bools: &[B {
            names: &["-A", "--all-namespaces"],
            canon: "--all-namespaces",
        }],
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Helm,
        id: "status",
        class: Class::Read,
        words: &["status"],
        aux: false,
        fixed: &[],
        pos: &[V::Name],
        min_pos: 1,
        flags: &[NS, OUT],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Helm,
        id: "history",
        class: Class::Read,
        words: &["history"],
        aux: false,
        fixed: &[],
        pos: &[V::Name],
        min_pos: 1,
        flags: &[NS, OUT],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Helm,
        id: "get values",
        class: Class::Read,
        words: &["get", "values"],
        aux: false,
        fixed: &[],
        pos: &[V::Name],
        min_pos: 1,
        flags: &[NS, OUT],
        bools: &[B {
            names: &["--all"],
            canon: "--all",
        }],
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    // helm: plan and apply
    Verb {
        kind: Kind::Helm,
        id: "template",
        class: Class::Plan,
        words: &["template"],
        aux: false,
        fixed: &[],
        pos: &[V::Name, V::Chart],
        min_pos: 2,
        flags: &[VALUES, VERSION, NS],
        bools: NONE_B,
        need: &["--version"],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: Some("upgrade"),
    },
    Verb {
        kind: Kind::Helm,
        id: "diff upgrade",
        class: Class::Plan,
        words: &["diff", "upgrade"],
        aux: false,
        fixed: &[Fx::L("--detailed-exitcode")],
        pos: &[V::Name, V::Chart],
        min_pos: 2,
        flags: &[VALUES, VERSION, NS],
        bools: NONE_B,
        need: &["--version"],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0, 2],
        apply_id: Some("upgrade"),
    },
    Verb {
        kind: Kind::Helm,
        id: "upgrade",
        class: Class::Apply,
        words: &["upgrade"],
        aux: false,
        fixed: &[Fx::L("--install")],
        pos: &[V::Name, V::Chart],
        min_pos: 2,
        flags: &[VALUES, VERSION, NS],
        bools: NONE_B,
        need: &["--version"],
        swallow: &["--install"],
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    // ansible
    Verb {
        kind: Kind::Ansible,
        id: "inventory",
        class: Class::Read,
        words: &["inventory"],
        aux: true,
        fixed: &[Fx::L("--list")],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: &["--list"],
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Ansible,
        id: "list-hosts",
        class: Class::Read,
        words: &[],
        aux: false,
        fixed: &[],
        pos: &[V::File],
        min_pos: 1,
        flags: &[LIMIT],
        bools: &[B {
            names: &["--list-hosts"],
            canon: "--list-hosts",
        }],
        need: &["--list-hosts"],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Ansible,
        id: "list-tasks",
        class: Class::Read,
        words: &[],
        aux: false,
        fixed: &[],
        pos: &[V::File],
        min_pos: 1,
        flags: &[LIMIT, TAGS, SKIP],
        bools: &[B {
            names: &["--list-tasks"],
            canon: "--list-tasks",
        }],
        need: &["--list-tasks"],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Ansible,
        id: "check",
        class: Class::Plan,
        words: &[],
        aux: false,
        fixed: &[],
        pos: &[V::File],
        min_pos: 1,
        flags: &[LIMIT, TAGS, SKIP],
        bools: &[
            B {
                names: &["-C", "--check"],
                canon: "--check",
            },
            B {
                names: &["-D", "--diff"],
                canon: "--diff",
            },
        ],
        need: &["--check", "--diff"],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: Some("run"),
    },
    Verb {
        kind: Kind::Ansible,
        id: "run",
        class: Class::Apply,
        words: &[],
        aux: false,
        fixed: &[],
        pos: &[V::File],
        min_pos: 1,
        flags: &[LIMIT, TAGS, SKIP],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    // tofu
    Verb {
        kind: Kind::Tofu,
        id: "show",
        class: Class::Read,
        words: &["show"],
        aux: false,
        fixed: &[Fx::L("-no-color")],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: &[B {
            names: &["-json"],
            canon: "-json",
        }],
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Tofu,
        id: "state list",
        class: Class::Read,
        words: &["state", "list"],
        aux: false,
        fixed: &[],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Tofu,
        id: "output",
        class: Class::Read,
        words: &["output"],
        aux: false,
        fixed: &[Fx::L("-no-color")],
        pos: &[V::Name],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Tofu,
        id: "validate",
        class: Class::Read,
        words: &["validate"],
        aux: false,
        fixed: &[Fx::L("-no-color")],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Tofu,
        id: "version",
        class: Class::Read,
        words: &["version"],
        aux: false,
        fixed: &[],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Tofu,
        id: "plan",
        class: Class::Plan,
        words: &["plan"],
        aux: false,
        fixed: &[
            Fx::L("-input=false"),
            Fx::L("-no-color"),
            Fx::L("-detailed-exitcode"),
            Fx::L("-out"),
            Fx::PlanOut,
        ],
        pos: &[],
        min_pos: 0,
        flags: &[F {
            names: &["-target"],
            canon: "-target",
            v: V::Pat,
        }],
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0, 2],
        apply_id: Some("apply"),
    },
    Verb {
        kind: Kind::Tofu,
        id: "apply",
        class: Class::Apply,
        words: &["apply"],
        aux: false,
        fixed: &[Fx::L("-input=false"), Fx::L("-no-color"), Fx::PlanIn],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    // ssh: a fixed list of read commands, nothing else
    Verb {
        kind: Kind::Ssh,
        id: "uptime",
        class: Class::Read,
        words: &["uptime"],
        aux: false,
        fixed: &[],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Ssh,
        id: "df",
        class: Class::Read,
        words: &["df"],
        aux: false,
        fixed: &[Fx::L("-h")],
        pos: &[],
        min_pos: 0,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0],
        apply_id: None,
    },
    Verb {
        kind: Kind::Ssh,
        id: "systemctl status",
        class: Class::Read,
        words: &["systemctl", "status"],
        aux: false,
        fixed: &[Fx::L("--no-pager")],
        pos: &[V::Unit],
        min_pos: 1,
        flags: NONE_F,
        bools: NONE_B,
        need: &[],
        swallow: NONE_S,
        default: NONE_D,
        ok: &[0, 3],
        apply_id: None,
    },
    Verb {
        kind: Kind::Ssh,
        id: "journalctl",
        class: Class::Read,
        words: &["journalctl"],
        aux: false,
        fixed: &[Fx::L("--no-pager")],
        pos: &[],
        min_pos: 0,
        flags: &[
            F {
                names: &["-u"],
                canon: "-u",
                v: V::Unit,
            },
            F {
                names: &["-n"],
                canon: "-n",
                v: V::Int(500),
            },
        ],
        bools: NONE_B,
        need: &["-u"],
        swallow: NONE_S,
        default: &[("-n", "100")],
        ok: &[0],
        apply_id: None,
    },
];

/// Every `(kind, verb, class)` in the tables, for docs and the console.
#[must_use]
pub fn table() -> Vec<(Kind, &'static str, Class)> {
    VERBS.iter().map(|v| (v.kind, v.id, v.class)).collect()
}

#[derive(Default)]
struct Parsed {
    pos: Vec<String>,
    vals: BTreeMap<&'static str, String>,
    bools: Vec<&'static str>,
}

fn find(kind: Kind, id: &str) -> Option<&'static Verb> {
    VERBS.iter().find(|v| v.kind == kind && v.id == id)
}

/// The verb an argv names: the longest leading-words match; ansible is told apart by its
/// flags, since `ansible-playbook` has no verbs.
fn select(kind: Kind, argv: &[String]) -> Result<&'static Verb, Refused> {
    let has = |a: &[&str]| argv.iter().any(|x| a.contains(&x.as_str()));
    if kind == Kind::Ansible {
        let id = if argv.first().is_some_and(|w| w == "inventory") {
            "inventory"
        } else if has(&["--list-hosts"]) {
            "list-hosts"
        } else if has(&["--list-tasks"]) {
            "list-tasks"
        } else if has(&["--check", "-C"]) {
            "check"
        } else {
            "run"
        };
        return find(kind, id).ok_or_else(|| Refused("no such verb".into()));
    }
    VERBS
        .iter()
        .filter(|v| {
            v.kind == kind
                && v.words.len() <= argv.len()
                && v.words.iter().zip(argv).all(|(w, a)| w == a)
        })
        .max_by_key(|v| v.words.len())
        .ok_or_else(|| {
            let first = argv.first().map_or("(none)", String::as_str);
            Refused(format!("{kind:?} does not allow {first:?}"))
        })
}

#[allow(clippy::many_single_char_names)] // v, p, i, a, f: the verb, the parse, the cursor
fn parse(v: &Verb, argv: &[String]) -> Result<Parsed, Refused> {
    let mut p = Parsed::default();
    let mut i = v.words.len();
    while i < argv.len() {
        let a = &argv[i];
        i += 1;
        if a == "--" || a.is_empty() || a.contains(['\0', '\n', '\r']) {
            return no(format!("argument {a:?} is not allowed"));
        }
        if a.starts_with('-') && a.len() > 1 {
            let (name, inline) = match a.split_once('=') {
                Some((n, val)) => (n, Some(val.to_owned())),
                None => (a.as_str(), None),
            };
            if let Some(f) = v.flags.iter().find(|f| f.names.contains(&name)) {
                let val = if let Some(x) = inline {
                    x
                } else {
                    let Some(x) = argv.get(i) else {
                        return no(format!("{name} needs a value"));
                    };
                    i += 1;
                    x.clone()
                };
                f.v.check(&val)
                    .map_err(|e| Refused(format!("{name}: {}", e.0)))?;
                if p.vals.insert(f.canon, val).is_some() {
                    return no(format!("{name} given twice"));
                }
            } else if let Some(b) = v
                .bools
                .iter()
                .find(|b| b.names.contains(&name))
                .filter(|_| inline.is_none())
            {
                if !p.bools.contains(&b.canon) {
                    p.bools.push(b.canon);
                }
            } else if let Some(s) = v
                .swallow
                .iter()
                .find(|s| **s == name)
                .filter(|_| inline.is_none())
            {
                if !p.bools.contains(s) {
                    p.bools.push(s);
                }
            } else {
                return no(format!("{name} is not allowed for {:?}", v.id));
            }
        } else {
            let Some(check) = v.pos.get(p.pos.len()) else {
                return no(format!(
                    "{:?} takes at most {} arguments",
                    v.id,
                    v.pos.len()
                ));
            };
            check.check(a)?;
            p.pos.push(a.clone());
        }
    }
    if p.pos.len() < v.min_pos {
        return no(format!("{:?} needs at least {} arguments", v.id, v.min_pos));
    }
    for n in v.need {
        if !p.vals.contains_key(n) && !p.bools.contains(n) {
            return no(format!("{:?} needs {n}", v.id));
        }
    }
    Ok(p)
}

/// The argv a parse builds for `v`, in the table's order.
fn emit(v: &Verb, p: &Parsed) -> Vec<Arg> {
    let mut out: Vec<Arg> = Vec::new();
    // The words are what the tool is called with; some verbs (ansible's) have none.
    if v.kind == Kind::Ssh {
        // The remote command is one word for the remote shell: built only from table
        // words and validated values, none of which holds a shell metacharacter.
        let mut cmd: Vec<String> = v.words.iter().map(|s| (*s).to_owned()).collect();
        for f in v.fixed {
            if let Fx::L(s) = f {
                cmd.push((*s).to_owned());
            }
        }
        for f in v.flags {
            let val = p.vals.get(f.canon).cloned().or_else(|| {
                v.default
                    .iter()
                    .find(|(k, _)| *k == f.canon)
                    .map(|(_, d)| (*d).to_owned())
            });
            if let Some(val) = val {
                cmd.push(f.canon.to_owned());
                cmd.push(val);
            }
        }
        cmd.extend(p.pos.iter().cloned());
        return vec![Arg::Lit(cmd.join(" "))];
    }
    let mut words: Vec<&str> = v.words.to_vec();
    if v.id == "apply" || v.id == "diff" || v.id == "upgrade" {
        // `diff`/`apply` are the one word; `diff upgrade` keeps both.
        words.truncate(words.len());
    }
    out.extend(words.iter().map(|w| Arg::lit(w)));
    for f in v.fixed {
        out.push(match f {
            Fx::L(s) => Arg::lit(s),
            Fx::PlanOut => Arg::PlanOut,
            Fx::PlanIn => Arg::PlanIn,
        });
    }
    for (i, val) in p.pos.iter().enumerate() {
        out.push(match v.pos.get(i) {
            Some(V::File) => Arg::File(val.clone()),
            _ => Arg::Lit(val.clone()),
        });
    }
    for f in v.flags {
        let val = p.vals.get(f.canon).cloned().or_else(|| {
            v.default
                .iter()
                .find(|(k, _)| *k == f.canon)
                .map(|(_, d)| (*d).to_owned())
        });
        if let Some(val) = val {
            out.push(Arg::lit(f.canon));
            out.push(if matches!(f.v, V::File) {
                Arg::File(val)
            } else {
                Arg::Lit(val)
            });
        }
    }
    for b in v.bools {
        if p.bools.contains(&b.canon) {
            out.push(Arg::lit(b.canon));
        }
    }
    out
}

/// Classifies and builds one argv for a connection kind.
///
/// # Errors
/// The argv names no verb in the table, or breaks the verb's rules.
pub fn classify(kind: Kind, argv: &[String]) -> Result<Command, Refused> {
    if argv.is_empty() {
        return no("an empty argv");
    }
    let v = select(kind, argv)?;
    let p = parse(v, argv)?;
    let built = emit(v, &p);
    let apply = v.apply_id.and_then(|id| find(kind, id)).map(|av| emit(av, &p));
    Ok(Command {
        kind,
        class: v.class,
        verb: v.id,
        aux: v.aux,
        args: built,
        ok_codes: v.ok,
        apply,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }
    fn class(kind: Kind, s: &str) -> Result<Class, Refused> {
        classify(kind, &a(s)).map(|c| c.class)
    }

    #[test]
    fn kubectl_classes() {
        assert_eq!(
            class(Kind::Kubectl, "get pods -n shop -o json").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(Kind::Kubectl, "describe deploy/web -n shop").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(Kind::Kubectl, "logs web-1 -n shop --tail 50").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(Kind::Kubectl, "auth can-i get pods -n shop").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(Kind::Kubectl, "diff -f m.yaml -n shop").unwrap(),
            Class::Plan
        );
        assert_eq!(
            class(Kind::Kubectl, "apply --server-side -f m.yaml").unwrap(),
            Class::Apply
        );
    }

    #[test]
    fn kubectl_refusals() {
        for bad in [
            "get secrets -n shop",
            "get secret/db -n shop",
            "get pods,secrets",
            "get pods --kubeconfig /etc/x",
            "get pods --raw /api",
            "get pods -o jsonpath={.items}",
            "logs web -f",
            "logs web --tail 100000",
            "exec web -- sh",
            "delete pod web",
            "apply -f ../../etc/passwd",
            "apply -f /etc/passwd",
            "diff",
            "get pods; rm -rf /",
            "get pods -n shop -n kube-system",
            "proxy",
            "port-forward web 80",
        ] {
            assert!(
                classify(Kind::Kubectl, &a(bad)).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn helm_ansible_tofu_ssh_classes() {
        assert_eq!(class(Kind::Helm, "list -A -o json").unwrap(), Class::Read);
        assert_eq!(
            class(Kind::Helm, "get values web -n shop").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(
                Kind::Helm,
                "template web repo/web --version 1.2.3 -f v.yaml"
            )
            .unwrap(),
            Class::Plan
        );
        assert_eq!(
            class(Kind::Helm, "diff upgrade web repo/web --version 1.2.3").unwrap(),
            Class::Plan
        );
        assert_eq!(
            class(Kind::Helm, "upgrade --install web repo/web --version 1.2.3").unwrap(),
            Class::Apply
        );
        assert!(
            class(Kind::Helm, "upgrade --install web repo/web").is_err(),
            "unpinned chart"
        );
        assert!(class(Kind::Helm, "uninstall web").is_err());
        assert!(class(Kind::Helm, "install web repo/web --set a=b").is_err());
        assert_eq!(
            class(Kind::Ansible, "--list-hosts site.yml").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(Kind::Ansible, "--check --diff site.yml").unwrap(),
            Class::Plan
        );
        assert!(
            class(Kind::Ansible, "--check site.yml").is_err(),
            "check without diff"
        );
        assert_eq!(
            class(Kind::Ansible, "site.yml --limit web").unwrap(),
            Class::Apply
        );
        assert!(class(Kind::Ansible, "-e cmd=x site.yml").is_err());
        assert!(class(Kind::Ansible, "-i /tmp/inv site.yml").is_err());
        assert_eq!(
            class(Kind::Ansible, "inventory --list").unwrap(),
            Class::Read
        );
        assert_eq!(class(Kind::Tofu, "state list").unwrap(), Class::Read);
        assert_eq!(class(Kind::Tofu, "show -json").unwrap(), Class::Read);
        assert_eq!(
            class(Kind::Tofu, "plan -target module.net").unwrap(),
            Class::Plan
        );
        assert_eq!(class(Kind::Tofu, "apply").unwrap(), Class::Apply);
        assert!(class(Kind::Tofu, "apply -auto-approve").is_err());
        assert!(class(Kind::Tofu, "plan -out /tmp/x").is_err());
        assert!(class(Kind::Tofu, "destroy").is_err());
        assert!(
            class(Kind::Tofu, "output -json").is_err(),
            "names only: no -json values"
        );
        assert_eq!(class(Kind::Ssh, "uptime").unwrap(), Class::Read);
        assert_eq!(
            class(Kind::Ssh, "systemctl status nginx.service").unwrap(),
            Class::Read
        );
        assert_eq!(
            class(Kind::Ssh, "journalctl -u nginx -n 50").unwrap(),
            Class::Read
        );
        for bad in [
            "rm -rf /",
            "systemctl restart nginx",
            "systemctl status nginx;reboot",
            "journalctl -u a&&b",
            "cat /etc/shadow",
            "systemctl status $(id)",
            "systemctl status `id`",
            "systemctl status a|b",
        ] {
            assert!(
                classify(Kind::Ssh, &a(bad)).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn plan_knows_its_apply_form_and_spellings_agree() {
        let plan = classify(Kind::Kubectl, &a("diff --filename m.yaml --namespace shop")).unwrap();
        let apply = classify(Kind::Kubectl, &a("apply -n shop -f m.yaml")).unwrap();
        assert_eq!(plan.apply.as_ref().unwrap(), &apply.args);
        let other = classify(Kind::Kubectl, &a("apply -n prod -f m.yaml")).unwrap();
        assert_ne!(plan.apply.as_ref().unwrap(), &other.args);
        let t = classify(Kind::Tofu, &a("plan")).unwrap();
        assert_eq!(
            t.apply.as_ref().unwrap(),
            &classify(Kind::Tofu, &a("apply")).unwrap().args
        );
        assert!(t.args.contains(&Arg::PlanOut));
        let p = classify(Kind::Ansible, &a("--check --diff --limit web site.yml")).unwrap();
        assert_eq!(
            p.apply.as_ref().unwrap(),
            &classify(Kind::Ansible, &a("--limit web site.yml"))
                .unwrap()
                .args
        );
        let h = classify(
            Kind::Helm,
            &a("diff upgrade web repo/web --version 1.0.0 -n shop"),
        )
        .unwrap();
        assert_eq!(
            h.apply.as_ref().unwrap(),
            &classify(
                Kind::Helm,
                &a("upgrade --install web repo/web --version 1.0.0 -n shop")
            )
            .unwrap()
            .args
        );
    }

    #[test]
    fn no_metacharacter_reaches_any_argument() {
        // Every accepted argv word, over the whole table's sample, is free of shell syntax.
        let ok = [
            (
                Kind::Kubectl,
                "get pods,svc -n shop -l app=web,tier!=db -o yaml",
            ),
            (Kind::Kubectl, "logs web -c app --since 5m"),
            (
                Kind::Helm,
                "template web oci://r.example/web --version 1.2.3+b -f values/prod.yaml",
            ),
            (Kind::Ssh, "journalctl -u nginx@1.service -n 20"),
        ];
        for (k, s) in ok {
            let c = classify(k, &a(s)).unwrap();
            for w in &c.args {
                if let Arg::Lit(x) | Arg::File(x) = w {
                    assert!(
                        !x.contains([
                            '$', '`', ';', '|', '&', '>', '<', '\\', '\'', '"', '\n', '*', '?',
                            '{', '}', '(', ')'
                        ]) || x.contains("!="),
                        "{x}"
                    );
                }
            }
        }
    }

    #[test]
    fn logs_are_bounded_by_default() {
        let c = classify(Kind::Kubectl, &a("logs web")).unwrap();
        assert!(
            c.args
                .windows(2)
                .any(|w| w[0] == Arg::lit("--tail") && w[1] == Arg::lit("200"))
        );
        assert!(c.args.contains(&Arg::lit("--limit-bytes=1048576")));
    }

    #[test]
    fn table_lists_every_class_for_every_kind_but_ssh() {
        let t = table();
        for k in [Kind::Kubectl, Kind::Helm, Kind::Ansible, Kind::Tofu] {
            for c in [Class::Read, Class::Plan, Class::Apply] {
                assert!(t.iter().any(|(x, _, y)| *x == k && *y == c), "{k:?} {c:?}");
            }
        }
        assert!(
            t.iter()
                .all(|(k, _, c)| *k != Kind::Ssh || *c == Class::Read)
        );
    }
}
