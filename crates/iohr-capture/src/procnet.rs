//! Host-wide TCP counters from `/proc/net/netstat` and `/proc/net/snmp` (layer 5): listen
//! queue overflows and drops, retransmitted segments, resets. They count for the whole
//! network namespace, not per port; the companion reports how much they grew since it
//! started.

use std::collections::HashMap;

/// The counters used, as `(table, name)`.
pub(crate) const USED: [(&str, &str); 7] = [
    ("TcpExt", "ListenOverflows"),
    ("TcpExt", "ListenDrops"),
    ("TcpExt", "TCPTimeouts"),
    ("Tcp", "RetransSegs"),
    ("Tcp", "EstabResets"),
    ("Tcp", "OutRsts"),
    ("Tcp", "AttemptFails"),
];

/// Parses the `Name: k1 k2 ...` / `Name: v1 v2 ...` line pairs of those files.
pub(crate) fn parse(text: &str) -> HashMap<(String, String), u64> {
    let mut out = HashMap::new();
    let mut lines = text.lines();
    while let (Some(names), Some(values)) = (lines.next(), lines.next()) {
        let (Some((table, names)), Some((table2, values))) =
            (names.split_once(':'), values.split_once(':'))
        else {
            break;
        };
        if table != table2 {
            break;
        }
        for (n, v) in names.split_whitespace().zip(values.split_whitespace()) {
            if USED.iter().any(|(t, k)| *t == table && *k == n)
                && let Ok(v) = v.parse::<i64>()
            {
                out.insert((table.to_owned(), n.to_owned()), v.max(0).unsigned_abs());
            }
        }
    }
    out
}

/// Reads both files under `proc_root` (`/proc` on a host).
pub(crate) fn read(proc_root: &std::path::Path) -> HashMap<(String, String), u64> {
    let mut all = HashMap::new();
    for f in ["net/netstat", "net/snmp"] {
        if let Ok(text) = std::fs::read_to_string(proc_root.join(f)) {
            all.extend(parse(&text));
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstat_and_snmp() {
        let netstat = "TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPTimeouts\nTcpExt: 0 12 14 3\nIpExt: InNoRoutes\nIpExt: 0\n";
        let snmp = "Ip: Forwarding\nIp: 1\nTcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts\nTcp: 1 200 120000 -1 10 20 2 5 3 100 120 7 0 9\n";
        let a = parse(netstat);
        assert_eq!(
            a.get(&("TcpExt".into(), "ListenOverflows".into())),
            Some(&12)
        );
        assert_eq!(a.get(&("TcpExt".into(), "ListenDrops".into())), Some(&14));
        let b = parse(snmp);
        assert_eq!(b.get(&("Tcp".into(), "RetransSegs".into())), Some(&7));
        assert_eq!(b.get(&("Tcp".into(), "OutRsts".into())), Some(&9));
        assert_eq!(b.get(&("Tcp".into(), "MaxConn".into())), None);
        assert!(parse("garbage\n").is_empty());
    }
}
