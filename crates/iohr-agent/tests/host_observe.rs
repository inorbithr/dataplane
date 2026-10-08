//! `atlas observe host` end to end over the tree captured read-only from a real TRX40
//! host on 2026-10-08 (`tests/fixtures/host/trx40/`: values copied, links kept relative,
//! no serial numbers, mountinfo limited to block devices; PCI config space is the first
//! 256 bytes, read as root). The facts asserted here are the ones found by hand that day
//! with `sensors`, `lspci -tv`, `lspci -vv` and `/proc/mdstat`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use iohr_agent::atlas::record::Record;
use iohr_agent::atlas::{HostRequest, ObserveRequest, observe};
use iohr_agent::error::Error;
use iohr_agent::policy::Policy;
use iohr_evidence::vocabulary::Value;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40")
}

fn request(samples: u32) -> ObserveRequest {
    ObserveRequest {
        host: Some(HostRequest {
            root: Some(fixture().join("root")),
            pci_ids: Some(fixture().join("pci.ids")),
            samples,
            interval: Duration::from_millis(10),
            chipset_warn: 100_000,
        }),
        ..ObserveRequest::default()
    }
}

/// `(subject key, predicate)` → values as text.
fn facts(records: &[Record]) -> BTreeMap<(String, String), Vec<String>> {
    let keys: BTreeMap<_, _> = records
        .iter()
        .filter_map(|r| match r {
            Record::Entity { id, key } => Some((*id, key.clone())),
            _ => None,
        })
        .collect();
    let mut out: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for r in records {
        if let Record::Observation(o) = r {
            let s = o.statement();
            let v = match &s.value {
                Value::Entity(e) => keys[e].clone(),
                Value::Text(t) => t.clone(),
                Value::Int(i) => i.to_string(),
                Value::Bool(b) => b.to_string(),
                other => format!("{other:?}"),
            };
            out.entry((
                keys[&s.subject].clone(),
                s.predicate.name.as_str().to_owned(),
            ))
            .or_default()
            .push(v);
        }
    }
    out
}

fn one(f: &BTreeMap<(String, String), Vec<String>>, subject: &str, predicate: &str) -> String {
    f.get(&(subject.to_owned(), predicate.to_owned()))
        .unwrap_or_else(|| panic!("no {predicate} on {subject}"))
        .join(",")
}

#[tokio::test]
async fn the_host_is_never_read_without_a_policy_that_allows_it() {
    let e = observe(&request(1), None).await.unwrap_err();
    assert!(matches!(e, Error::Policy(_)), "{e}");
    let off = Policy::from_toml("environment = \"production\"\n").unwrap();
    let e = observe(&request(1), Some(&off)).await.unwrap_err();
    assert!(e.to_string().contains("[work] host"), "{e}");
}

#[tokio::test]
async fn the_trx40_reading_says_what_was_found_by_hand() {
    let policy = Policy::from_toml("environment = \"production\"\n[work]\nhost = true\n").unwrap();
    let (sink, summary) = observe(&request(3), Some(&policy)).await.unwrap();
    let records = sink.records();
    let Record::Run(run) = &records[0] else {
        panic!("the run record comes first")
    };
    let host = run.host.as_ref().unwrap();
    assert_eq!((host.name.as_str(), host.samples), ("fixture", 3));
    let f = facts(records);

    // Chipset 107 °C (the manual reading that day was 105 to 107).
    assert_eq!(
        one(
            &f,
            "hwmon/fixture/asusec/temp/Chipset",
            "host.temp.millicelsius"
        ),
        "107000"
    );
    // nvme5 (root), nvme8 (/mnt/development), nvme6 (md1) and the AQC107 behind 41:00.0.
    for (pci, what) in [
        ("0000:43:00.0", "nvme5"),
        ("0000:44:00.0", "nvme8"),
        ("0000:45:00.0", "nvme6"),
        ("0000:46:00.0", "AQC107"),
    ] {
        assert_eq!(
            one(&f, &format!("pci/fixture/{pci}"), "host.pci.behind_chipset"),
            "pci/fixture/0000:41:00.0",
            "{what}"
        );
    }
    assert_eq!(
        one(&f, "nvme/fixture/nvme5", "host.nvme.on_pci"),
        "pci/fixture/0000:43:00.0"
    );
    assert_eq!(
        one(&f, "mount/fixture:/", "host.mount.role"),
        "root,journal"
    );
    assert_eq!(
        one(&f, "net/fixture/enp70s0", "host.net.link_speed_mbps"),
        "1000"
    );
    // ASPM: the policy is `default` and every link with a PCIe capability has it off.
    assert_eq!(one(&f, "host/fixture", "host.pcie.aspm_policy"), "default");
    let aspm: Vec<&String> = f
        .iter()
        .filter(|((_, p), _)| p == "host.pcie.aspm_enabled")
        .flat_map(|(_, v)| v)
        .collect();
    assert!(!aspm.is_empty() && aspm.iter().all(|v| *v == "disabled"));
    // nvme7 on a CPU lane, unused.
    assert!(!f.contains_key(&(
        "pci/fixture/0000:4e:00.0".to_owned(),
        "host.pci.behind_chipset".to_owned()
    )));
    assert_eq!(
        one(&f, "nvme/fixture/nvme7", "host.derived.idle_cpu_lane_drive"),
        "supported"
    );
    // The derived findings, with honest verdicts.
    assert_eq!(
        one(
            &f,
            "mount/fixture:/mnt/development",
            "host.derived.behind_hot_component"
        ),
        "supported"
    );
    assert_eq!(
        one(&f, "pci/fixture/0000:41:00.0", "host.derived.shared_uplink"),
        "supported"
    );
    // Three samples of an unchanging tree: no correlation can be claimed.
    assert_eq!(
        one(
            &f,
            "block/fixture/nvme8n1",
            "host.derived.io_temp_correlation"
        ),
        "unknown"
    );
    // What was not read is said, not guessed.
    let not_observed = one(&f, "host/fixture", "host.not_observed");
    assert!(not_observed.contains("journal"), "{not_observed}");
    assert!(one(&f, "nvme/fixture/nvme5", "host.not_observed").contains("smart"));
    let report = summary.host_report.unwrap();
    assert!(report.contains("chipset uplink 0000:41:00.0"), "{report}");
    assert!(report.contains("enp70s0 at 1000 Mb/s"), "{report}");
}
