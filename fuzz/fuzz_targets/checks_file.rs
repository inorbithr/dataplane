//! The checks file is operator-written text the agent parses at start and on reload.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = iohr_agent::checks_file::parse(text);
});
