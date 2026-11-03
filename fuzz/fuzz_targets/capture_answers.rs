//! Answers from the capture companion are parsed by the agent; a companion is another
//! process, so its bytes are untrusted input.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|answer: &[u8]| {
    let _ = iohr_agent::capture::Counts::parse(answer);
    let _ = iohr_agent::capture::Lookup::parse(answer);
});
