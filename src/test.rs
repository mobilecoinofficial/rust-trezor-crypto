//! Helpers to ensure ABI compatibility for use when testing

pub use crate::UInt;

/// Driver ABI for dalek or donna impls
#[allow(unused)]
pub struct Driver {
    pub publickey: unsafe extern "C" fn(*mut u8, *mut u8),
    pub sign_open: unsafe extern "C" fn(*const u8, UInt, *mut u8, *mut u8) -> i32,
    pub sign: unsafe extern "C" fn(*const u8, UInt, *mut u8, *mut u8, *mut u8),
    pub sign_open_batch: unsafe extern "C" fn(*mut *const u8, *mut UInt, *mut *const u8, *mut *const u8, UInt, *mut i32) -> i32,
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


pub fn generate_batch<const N: usize>(signer: &Driver) -> [([u8; 32], [u8; 32], [u8; 128], UInt, [u8; 64]); N] {

    let mut batch = [(
        [0u8; 32],
        [0u8; 32],
        [0u8; 128],
        128,
        [0u8; 64],
    ); N];

    for i in 0..N {
        // Generate keys
        getrandom::getrandom(&mut batch[i].0).unwrap();
        batch[i].1 = [0u8; 32];
        unsafe { (signer.publickey)(batch[i].0.as_mut_ptr(), batch[i].1.as_mut_ptr()) };

        // Generate and sign message
        getrandom::getrandom(&mut batch[i].2).unwrap();
        unsafe { (signer.sign)( batch[i].2.as_ptr(),  batch[i].3, batch[i].0.as_mut_ptr(), batch[i].1.as_mut_ptr(), batch[i].4.as_mut_ptr()) };
    }

    batch
}