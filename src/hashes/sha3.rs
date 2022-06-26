//! Sha3512 implementation
//! 

use core::slice::{from_raw_parts};

use crate::ffi;

use sha3::{Digest, Sha3_512};
use static_assertions::const_assert_eq;

/// C compatible sha3_512 context
#[repr(C)]
pub struct Sha3_512Ctx {
    inner: Sha3_512,
}

// Ensure C sha3_ object and rust sha3_ object sizes match
// This is pretty gnarley, but, there doesn't seem to be a more
// reasonable way of exposing -sized- rust types to C..?
static_assertions::assert_eq_size!(
    Sha3_512Ctx,
    ffi::sha3_512_ctx_t
);

#[no_mangle]
pub extern "C" fn sha3_512_init(ctx: *mut Sha3_512Ctx) {
    let ctx = unsafe { &mut *ctx };

    ctx.inner = Sha3_512::new();
}

#[no_mangle]
pub extern "C" fn sha3_512_update(ctx: *mut Sha3_512Ctx, data: *const u8, len: usize) {
    let (ctx, buff) = unsafe {(
        &mut *ctx,
        from_raw_parts(data, len),
    )};

    ctx.inner.update(buff);
}

#[no_mangle]
pub extern "C" fn sha3_512_finalize(ctx: *mut Sha3_512Ctx, hash: *mut [u8; 64]) {
    let (ctx, hash) = unsafe {( &mut *ctx, &mut *hash )};

    let h = ctx.inner.clone().finalize();
    hash.copy_from_slice(h.as_slice());
}

#[no_mangle]
pub extern "C" fn sha3_512_hash(data: *const u8, len: usize, hash: *mut [u8; 64]) {
    let (buff, hash) = unsafe {(
        from_raw_parts(data, len),
        &mut *hash,
    )};

    let mut d = Sha3_512::new();
    d.update(buff);
    let h = d.finalize();

    hash.copy_from_slice(h.as_slice());
}
