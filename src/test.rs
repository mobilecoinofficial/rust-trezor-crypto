//! Helpers to ensure ABI compatibility for use when testing

/// Driver ABI for dalek or donna impls
pub struct Driver {
    pub publickey: unsafe extern "C" fn(*mut u8, *mut u8),
    pub sign_open: unsafe extern "C" fn(*const u8, u64, *mut u8, *mut u8) -> i32,
    pub sign: unsafe extern "C" fn(*const u8, u64, *mut u8, *mut u8, *mut u8),
    pub sign_open_batch: unsafe extern "C" fn(*mut *const u8, *mut u64, *mut *const u8, *mut *const u8, u64, *mut i32) -> i32,
}

/// Donna driver implementation (using FFI)
#[cfg(feature = "build_donna")]
pub const DONNA: Driver = Driver {
    publickey: crate::ffi::ed25519_publickey,
    sign_open: crate::ffi::ed25519_sign_open,
    sign: crate::ffi::ed25519_sign,
    sign_open_batch: crate::ffi::ed25519_sign_open_batch,
};

/// Dalek driver implementation (native rust)
pub const DALEK: Driver = Driver {
    publickey: crate::dalek_ed25519_publickey,
    sign_open: crate::dalek_ed25519_sign_open,
    sign: crate::dalek_ed25519_sign,
    sign_open_batch: crate::dalek_ed25519_sign_open_batch,
};
