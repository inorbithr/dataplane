//! The DER reader behind the TLS-expiry check reads whatever a server presents.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|der: &[u8]| {
    let _ = iohr_agent::x509::not_after(der);
});
