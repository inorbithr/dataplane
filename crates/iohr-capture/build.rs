//! Compiles the eBPF programs in `crates/iohr-capture-ebpf` for the BPF target with the
//! nightly named in that crate's `rust-toolchain.toml` (and `bpf-linker`), through
//! aya-build. The object lands in `OUT_DIR` and is embedded by `src/capture.rs`.
//!
//! Needs: `rustup`, the pinned nightly with `rust-src`, and `bpf-linker` on `PATH`
//! (`mise install` provides all three). Not built for non-Linux targets.

use std::{env, fs, io::Write as _, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        writeln!(
            out,
            "cargo:warning=iohr-capture runs on Linux only; eBPF build skipped"
        )?;
        return Ok(());
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let ebpf_dir = manifest.join("../iohr-capture-ebpf").canonicalize()?;
    let toolchain_file = ebpf_dir.join("rust-toolchain.toml");
    writeln!(out, "cargo:rerun-if-changed={}", toolchain_file.display())?;
    writeln!(
        out,
        "cargo:rerun-if-changed={}",
        manifest.join("../iohr-capture-common").display()
    )?;
    let toolchain = channel(&fs::read_to_string(&toolchain_file)?)
        .ok_or("no `channel = \"...\"` in crates/iohr-capture-ebpf/rust-toolchain.toml")?;
    let root_dir = ebpf_dir.to_str().ok_or("non UTF-8 path")?;
    // aya-build runs `cargo build --package iohr-capture-ebpf` in our working directory.
    // The eBPF crate is not a workspace member (it has its own Cargo.lock and toolchain),
    // so run that cargo from the crate's own directory.
    env::set_current_dir(&ebpf_dir)?;
    // aya-build prints from a second thread: release the stdout lock first.
    drop(out);
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "iohr-capture-ebpf",
            root_dir,
            ..Default::default()
        }],
        aya_build::Toolchain::Custom(&toolchain),
    )?;
    Ok(())
}

/// The `channel` value from a rust-toolchain.toml (a plain line scan; no TOML parser in
/// the build graph for one key).
fn channel(toml: &str) -> Option<String> {
    toml.lines().find_map(|line| {
        let rest = line
            .trim()
            .strip_prefix("channel")?
            .trim_start()
            .strip_prefix('=')?;
        Some(rest.trim().trim_matches('"').to_owned())
    })
}
