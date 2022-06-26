//! Keccak512 implementation
//! 

use core::slice::{from_raw_parts};

use crate::ffi;

use sha3::{Digest, Keccak512};
use static_assertions::const_assert_eq;

/// C compatible keccak512 context
#[repr(C)]
pub struct Keccak512Ctx {
    inner: Keccak512,
}

// Ensure C keccak object and rust keccak object sizes match
// This is pretty gnarley, but, there doesn't seem to be a more
// reasonable way of exposing -sized- rust types to C..?
static_assertions::assert_eq_size!(
    Keccak512Ctx,
    ffi::keccak512_ctx_t
);

#[no_mangle]
pub extern "C" fn keccak512_init(ctx: *mut Keccak512Ctx) {
    let ctx = unsafe { &mut *ctx };

    ctx.inner = Keccak512::new();
}

#[no_mangle]
pub extern "C" fn keccak512_update(ctx: *mut Keccak512Ctx, data: *const u8, len: usize) {
    let (ctx, buff) = unsafe {(
        &mut *ctx,
        from_raw_parts(data, len),
    )};

    ctx.inner.update(buff);
}

#[no_mangle]
pub extern "C" fn keccak512_finalize(ctx: *mut Keccak512Ctx, hash: *mut [u8; 64]) {
    let (ctx, hash) = unsafe {( &mut *ctx, &mut *hash )};

    let h = ctx.inner.clone().finalize();
    hash.copy_from_slice(h.as_slice());
}

#[no_mangle]
pub extern "C" fn keccak512_hash(data: *const u8, len: usize, hash: *mut [u8; 64]) {
    let (buff, hash) = unsafe {(
        from_raw_parts(data, len),
        &mut *hash,
    )};

    let mut d = Keccak512::new();
    d.update(buff);
    let h = d.finalize();

    hash.copy_from_slice(h.as_slice());
}
