//! TC classifiers for ingress and egress. Phase 0: count socket buffers and bytes per
//! direction in a per-CPU array and always return `TC_ACT_OK`. They never drop, redirect
//! or change a packet.
#![no_std]
#![no_main]
// Small helpers are inlined on purpose: one flat program per hook keeps the verifier's
// job simple on old kernels.
#![allow(clippy::inline_always)]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};
use iohr_capture_common::{Counters, DIRECTIONS, EGRESS, INGRESS};

#[map(name = "IOHR_COUNTERS")]
static COUNTERS: PerCpuArray<Counters> = PerCpuArray::with_max_entries(DIRECTIONS, 0);

/// Attached to the interface's ingress hook. (`#[classifier]` hands the context by value.)
#[allow(clippy::needless_pass_by_value)]
#[classifier]
fn iohr_ingress(ctx: TcContext) -> i32 {
    count(&ctx, INGRESS);
    pass()
}

/// Attached to the interface's egress hook.
#[allow(clippy::needless_pass_by_value)]
#[classifier]
fn iohr_egress(ctx: TcContext) -> i32 {
    count(&ctx, EGRESS);
    pass()
}

#[inline(always)]
// The binding's integer type differs between aya-ebpf-bindings' per-arch files.
#[allow(clippy::cast_possible_wrap, clippy::unnecessary_cast)]
const fn pass() -> i32 {
    // TC_ACT_OK is 0: hand the packet on unchanged.
    TC_ACT_OK as i32
}

#[inline(always)]
fn count(ctx: &TcContext, direction: u32) {
    if let Some(slot) = COUNTERS.get_ptr_mut(direction) {
        // SAFETY: the pointer comes from a successful lookup in a per-CPU array, so it is
        // non-null, aligned and points at this CPU's own slot; TC programs do not migrate
        // between CPUs while they run, so no other writer touches it concurrently.
        unsafe {
            (*slot).packets = (*slot).packets.wrapping_add(1);
            (*slot).bytes = (*slot).bytes.wrapping_add(u64::from(ctx.len()));
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// GPL-compatible, as the kernel requires for programs that use GPL-only helpers.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
