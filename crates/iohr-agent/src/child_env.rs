//! The environment a child process starts with.
//!
//! Every program the agent starts begins from an empty environment: the agent's own
//! settings (its enrolment token, a Vault token, whatever its service manager set) never
//! reach a child. Only the names a caller lists are passed on from this process, and only
//! the values it sets are added.

use std::ffi::OsStr;

/// What an ordinary program needs to find its tools and home and to print text: the names
/// passed on to a command an operator configured (an examples set, a browser).
pub const BASE: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TERM",
];

/// Names a policy may never pass on: the agent's own settings and credentials.
#[must_use]
pub fn reserved(name: &str) -> bool {
    name.starts_with("IOHR_AGENT_") || name.starts_with("VAULT_")
}

/// Clears `cmd`'s environment, passes on from this process only the names in `pass` that
/// are set and not [`reserved`], then sets `set`.
pub fn isolate<K, V>(
    cmd: &mut std::process::Command,
    pass: &[&str],
    set: impl IntoIterator<Item = (K, V)>,
) where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    cmd.env_clear();
    for name in pass.iter().filter(|n| !reserved(n)) {
        if let Some(v) = std::env::var_os(name) {
            cmd.env(name, v);
        }
    }
    cmd.envs(set);
}

/// The same for a tokio command.
pub fn isolate_tokio<K, V>(
    cmd: &mut tokio::process::Command,
    pass: &[&str],
    set: impl IntoIterator<Item = (K, V)>,
) where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    isolate(cmd.as_std_mut(), pass, set);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_SET: [(&str, &str); 0] = [];

    fn envs(cmd: &std::process::Command) -> Vec<(String, Option<String>)> {
        cmd.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    #[test]
    fn only_listed_names_are_passed_and_reserved_ones_never() {
        let mut cmd = std::process::Command::new("true");
        isolate(
            &mut cmd,
            &["PATH", "IOHR_AGENT_ENROLLMENT_TOKEN", "VAULT_TOKEN"],
            NO_SET,
        );
        let got = envs(&cmd);
        assert!(got.iter().all(|(k, _)| k == "PATH"), "{got:?}");
        isolate(&mut cmd, &[], [("LC_ALL", "C")]);
        assert_eq!(envs(&cmd), vec![("LC_ALL".into(), Some("C".into()))]);
    }

    /// Run in a child the test below starts with the agent's credentials set: prints the
    /// environment a program started through [`isolate`] sees.
    #[test]
    fn print_isolated_child_env() {
        if std::env::var_os("IOHR_CHILD_ENV_PROBE").is_none() {
            return;
        }
        let mut cmd = std::process::Command::new("env");
        isolate(&mut cmd, BASE, NO_SET);
        let out = cmd.output().expect("env runs");
        println!("<<{}>>", String::from_utf8_lossy(&out.stdout));
    }

    #[cfg(unix)]
    #[test]
    fn a_child_never_sees_the_agent_credentials() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "child_env::tests::print_isolated_child_env",
                "--exact",
                "--nocapture",
            ])
            .env("IOHR_CHILD_ENV_PROBE", "1")
            .env("IOHR_AGENT_ENROLLMENT_TOKEN", "sentinel-enrol")
            .env("VAULT_TOKEN", "sentinel-vault")
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let Some((seen, _)) = text.split_once("<<").and_then(|(_, r)| r.split_once(">>")) else {
            panic!("no probe output: {text}");
        };
        assert!(seen.contains("PATH="), "{seen}");
        assert!(!seen.contains("sentinel"), "{seen}");
        assert!(!seen.contains("IOHR_AGENT_ENROLLMENT_TOKEN"), "{seen}");
        assert!(!seen.contains("VAULT_TOKEN"), "{seen}");
        assert!(!seen.contains("IOHR_CHILD_ENV_PROBE"), "{seen}");
    }
}
