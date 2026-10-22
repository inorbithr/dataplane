//! The host against hand-written components (WAT): what the host links, what it
//! refuses and where it stops a call. No wasm toolchain needed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::format_push_string
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use iohr_ext_host::package::sign;
use iohr_ext_host::{
    Capability, Error, Event, Host, Limits, LimitsHandle, Package, Reading, Sensors, Trail, Trust,
};

#[derive(Default)]
struct Sink(Mutex<Vec<(String, Event)>>);

impl Trail for Sink {
    fn emit(&self, ext: &str, event: Event) {
        self.0.lock().unwrap().push((ext.to_owned(), event));
    }
}

struct Fixed;

impl Sensors for Fixed {
    fn read(&self, name: &str) -> Option<Reading> {
        (name == "cpu.load").then(|| Reading {
            name: name.into(),
            value: 0.5,
            unit: "ratio".into(),
            at_ms: 1,
        })
    }

    fn list(&self) -> Vec<String> {
        vec!["cpu.load".into()]
    }
}

/// One host interface a test component imports: its WIT instance type, and the core
/// import it lowers to.
struct Imp {
    cap: &'static str,
    func: &'static str,
    ty: &'static str,
    core: &'static str,
}

const LOG: Imp = Imp {
    cap: "log",
    func: "write",
    ty: r#"(type $lv (enum "trace" "debug" "info" "warn" "error"))
           (export "level" (type $level (eq $lv)))
           (export "write" (func (param "level" $level) (param "message" string)))"#,
    core: "(param i32 i32 i32)",
};
const TIMER: Imp = Imp {
    cap: "timer",
    func: "set-interval",
    ty: r#"(export "set-interval" (func (param "ms" u32) (result u32)))"#,
    core: "(param i32) (result i32)",
};
const SENSOR: Imp = Imp {
    cap: "sensor",
    func: "list",
    ty: r#"(export "list" (func (result (list string))))"#,
    core: "(param i32)",
};
const TRAIL: Imp = Imp {
    cap: "trail",
    func: "emit",
    ty: r#"(type $ev (record (field "name" string) (field "attrs" (list (tuple string string)))))
           (export "event" (type $event (eq $ev)))
           (export "emit" (func (param "event" $event) (result bool)))"#,
    core: "(param i32 i32 i32 i32) (result i32)",
};

/// A component importing `imps`; `init` and `tick` are core function bodies returning
/// the address of a `result<_, string>` in memory (zeroed memory is `ok`). The core
/// functions are `$log`, `$set_interval`, `$list` and `$emit`; memory is the first
/// 2 KiB, which `data` may fill; `cabi_realloc` is a bump allocator above it.
fn component(imps: &[&Imp], init: &str, tick: &str, data: &str, pages: u32) -> Vec<u8> {
    let mut imports = String::new();
    let mut lowers = String::new();
    let mut core_imports = String::new();
    let mut with = String::new();
    for i in imps {
        let (cap, func) = (i.cap, i.func);
        let core_name = match cap {
            "log" => "log",
            "timer" => "set_interval",
            "sensor" => "list",
            _ => "emit",
        };
        imports += &format!(
            "(import \"iohr:ext/{cap}@0.1.0\" (instance ${cap} {}))\n",
            i.ty
        );
        lowers += &format!(
            "(alias export ${cap} \"{func}\" (func $a_{cap}))
             (core func $f_{cap} (canon lower (func $a_{cap}) (memory (core memory $mem)) (realloc (core func $realloc))))
             (core instance $h_{cap} (export \"{func}\" (func $f_{cap})))\n"
        );
        core_imports += &format!(
            "(import \"{cap}\" \"{func}\" (func ${core_name} {}))\n",
            i.core
        );
        with += &format!("(with \"{cap}\" (instance $h_{cap}))\n");
    }
    let wat = format!(
        r#"(component
  {imports}
  (core module $libc
    (memory (export "memory") {pages})
    (global $bump (mut i32) (i32.const 4096))
    (data (i32.const 256) "{data}")
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
      (local $p i32)
      (local.set $p (i32.and (i32.add (global.get $bump) (i32.const 7)) (i32.const -8)))
      (global.set $bump (i32.add (local.get $p) (local.get 3)))
      (local.get $p)))
  (core instance $libc (instantiate $libc))
  (alias core export $libc "memory" (core memory $mem))
  (alias core export $libc "cabi_realloc" (core func $realloc))
  {lowers}
  (core module $m
    {core_imports}
    (import "libc" "memory" (memory 1))
    (func (export "init") (result i32) {init})
    (func (export "tick") (result i32) {tick}))
  (core instance $i (instantiate $m (with "libc" (instance $libc)) {with}))
  (alias core export $i "init" (core func $init_c))
  (alias core export $i "tick" (core func $tick_c))
  (func $init (result (result (error string)))
    (canon lift (core func $init_c) (memory (core memory $mem)) (realloc (core func $realloc))))
  (func $tick (result (result (error string)))
    (canon lift (core func $tick_c) (memory (core memory $mem)) (realloc (core func $realloc))))
  (export "init" (func $init))
  (export "tick" (func $tick)))"#
    );
    wat::parse_str(wat).unwrap()
}

const OK: &str = "(i32.const 128)";
const MANIFEST: &str = "id = \"acme/probe\"\nname = \"Probe\"\nversion = \"1.0.0\"\ncapabilities = [\"log\", \"timer\", \"sensor\", \"trail\"]\n[config]\nk = \"v\"\n";

fn package(manifest: &str, wasm: Vec<u8>) -> Package {
    let key = SigningKey::from_bytes(&[7; 32]);
    let sig = serde_json::to_vec(&sign(&key, manifest.as_bytes(), &wasm)).unwrap();
    let trust = Trust::new().with("acme", key.verifying_key());
    Package::verify(manifest.as_bytes(), wasm, &sig, &trust).unwrap()
}

fn all() -> BTreeSet<Capability> {
    Capability::ALL.into_iter().collect()
}

fn host(limits: Limits) -> (Host, Arc<Sink>) {
    let sink = Arc::new(Sink::default());
    let h = Host::new(LimitsHandle::new(limits), Arc::new(Fixed), sink.clone()).unwrap();
    (h, sink)
}

fn load(h: &Host, p: &Package) -> Result<iohr_ext_host::Loaded, Error> {
    h.load(p, &all(), &BTreeMap::new())
}

#[test]
fn a_component_reads_sensors_emits_events_and_sets_its_interval() {
    let wasm = component(
        &[&LOG, &TIMER, &SENSOR, &TRAIL],
        // Asks for 10 ms; the host clamps it to the 1 s minimum.
        "(call $log (i32.const 2) (i32.const 256) (i32.const 5))
         (drop (call $set_interval (i32.const 10))) (i32.const 128)",
        // list(retptr 64): [64] = list ptr, [68] = len; the first name goes to the trail.
        "(call $list (i32.const 64))
         (drop (call $emit
           (i32.load (i32.load (i32.const 64)))
           (i32.load offset=4 (i32.load (i32.const 64)))
           (i32.const 0) (i32.const 0)))
         (i32.const 128)",
        "hello",
        1,
    );
    let (h, sink) = host(Limits::default());
    let mut x = load(&h, &package(MANIFEST, wasm)).unwrap();
    x.init().unwrap();
    assert_eq!(x.interval_ms(), 1_000);
    x.tick().unwrap();
    x.tick().unwrap();
    let got = sink.0.lock().unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, "acme/probe");
    assert_eq!(got[0].1.name, "cpu.load");
}

#[test]
fn an_import_the_manifest_or_the_policy_does_not_allow_is_refused() {
    let wasm = component(&[&TRAIL], OK, OK, "", 1);
    let (h, _) = host(Limits::default());
    // Declared in the manifest, not granted by the policy.
    let p = package(MANIFEST, wasm.clone());
    let only_log: BTreeSet<_> = [Capability::Log].into();
    let e = h.load(&p, &only_log, &BTreeMap::new()).unwrap_err();
    assert!(matches!(e, Error::Capability(_)), "{e:?}");
    // Granted, not declared: the signature pins the manifest, so widening is not possible.
    let narrow = "id = \"acme/probe\"\nname = \"Probe\"\nversion = \"1.0.0\"\n";
    let e = load(&h, &package(narrow, wasm)).unwrap_err();
    assert!(matches!(e, Error::Capability(_)), "{e:?}");
}

#[test]
fn an_unknown_import_and_a_broken_component_are_refused() {
    let (h, _) = host(Limits::default());
    let alien = wat::parse_str(
        r#"(component (import "acme:net/http@1.0.0" (instance (export "f" (func)))))"#,
    )
    .unwrap();
    let e = load(&h, &package(MANIFEST, alien)).unwrap_err();
    assert!(matches!(e, Error::Component(_)), "{e:?}");
    let e = load(&h, &package(MANIFEST, b"not wasm".to_vec())).unwrap_err();
    assert!(matches!(e, Error::Component(_)), "{e:?}");
}

#[test]
fn a_guest_error_refuses_the_start_without_stopping_the_host() {
    // result::err("boom") at 128: discriminant 1, string ptr 256, len 4.
    let init = "(i32.store8 (i32.const 128) (i32.const 1))
                (i32.store (i32.const 132) (i32.const 256))
                (i32.store (i32.const 136) (i32.const 4))
                (i32.const 128)";
    let wasm = component(&[], init, "(i32.const 512)", "boom", 1);
    let (h, _) = host(Limits::default());
    let mut x = load(&h, &package(MANIFEST, wasm)).unwrap();
    assert_eq!(x.init(), Err(Error::Guest("boom".into())));
    assert!(!x.is_stopped());
    x.tick().unwrap();
}

#[test]
fn fuel_and_the_deadline_stop_a_runaway_call_and_the_extension_with_it() {
    let spin = "(loop $l (br $l)) (i32.const 128)";
    let wasm = component(&[], OK, spin, "", 1);
    let p = package(MANIFEST, wasm);

    let (h, _) = host(Limits {
        fuel: 100_000,
        ..Limits::default()
    });
    let mut x = load(&h, &p).unwrap();
    x.init().unwrap();
    assert_eq!(x.tick(), Err(Error::Limit("fuel")));
    assert!(x.is_stopped());
    assert!(matches!(x.tick(), Err(Error::Trap(_))));

    let (h, _) = host(Limits {
        fuel: u64::MAX / 2,
        deadline_ms: 50,
        ..Limits::default()
    });
    let mut x = load(&h, &p).unwrap();
    assert_eq!(x.tick(), Err(Error::Limit("deadline")));
}

#[test]
fn memory_over_the_limit_is_refused_and_limits_change_live() {
    // 4 pages = 256 KiB.
    let wasm = component(&[], OK, OK, "", 4);
    let p = package(MANIFEST, wasm);
    let (h, _) = host(Limits {
        memory_bytes: 64 * 1024,
        ..Limits::default()
    });
    assert!(load(&h, &p).is_err());

    let limits = LimitsHandle::new(Limits::default());
    let h = Host::new(limits.clone(), Arc::new(Fixed), Arc::new(Sink::default())).unwrap();
    let mut x = load(
        &h,
        &package(
            MANIFEST,
            component(&[], OK, "(loop $l (br $l)) (i32.const 128)", "", 1),
        ),
    )
    .unwrap();
    limits.set(Limits {
        fuel: 1_000,
        ..Limits::default()
    });
    assert_eq!(x.tick(), Err(Error::Limit("fuel")));
}
