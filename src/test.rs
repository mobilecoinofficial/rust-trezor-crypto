//! Helpers to ensure ABI compatibility for use when testing

pub use crate::UInt;
use crate::{PublicKey, SecretKey, Signature, Scalar, ffi};

/// Driver ABI for dalek or donna impls
#[allow(unused)]
pub struct Driver {
    pub ed25519_publickey: unsafe extern "C" fn(*mut SecretKey, *mut PublicKey),
    pub ed25519_sign: unsafe extern "C" fn(*const u8, UInt, *mut SecretKey, *mut PublicKey, *mut Signature),
    pub ed25519_sign_open: unsafe extern "C" fn(*const u8, UInt, *mut PublicKey, *mut Signature) -> i32,
    pub ed25519_sign_open_batch: unsafe extern "C" fn(*mut *const u8, *mut UInt, *mut *const u8, *mut *const u8, UInt, *mut i32) -> i32,

    pub curved25519_scalarmult_basepoint: unsafe extern "C" fn(*mut Scalar, *mut Scalar),
    pub curve25519_scalarmult: unsafe extern "C" fn(*mut Scalar, *mut SecretKey, *mut Scalar),

    pub ed25519_publickey_ext: unsafe extern "C" fn(sk: *mut SecretKey, sk_ext: *mut SecretKey, pk: *mut PublicKey),

    pub ed25519_sign_ext: unsafe extern "C" fn(m: *const u8, mlen: UInt,
        sk: *mut SecretKey, sk_ext: *mut SecretKey, pk: *mut PublicKey, sig: *mut Signature,
    ),
}

/// Donna driver implementation (via FFI)
#[cfg(feature = "build_donna")]
pub const DONNA: Driver = Driver {
    ed25519_publickey: ffi::ed25519_publickey,
    ed25519_sign_open: ffi::ed25519_sign_open,
    ed25519_sign: ffi::ed25519_sign,
    ed25519_sign_open_batch: ffi::ed25519_sign_open_batch,
    curved25519_scalarmult_basepoint: ffi::curved25519_scalarmult_basepoint,
    curve25519_scalarmult: ffi::curve25519_scalarmult,
    ed25519_publickey_ext: ffi::ed25519_publickey_ext,
    ed25519_sign_ext: ffi::ed25519_sign_ext,
};

/// Dalek driver implementation (native rust)
pub const DALEK: Driver = Driver {
    ed25519_publickey: crate::dalek_ed25519_publickey,
    ed25519_sign_open: crate::dalek_ed25519_sign_open,
    ed25519_sign: crate::dalek_ed25519_sign,
    ed25519_sign_open_batch: crate::dalek_ed25519_sign_open_batch,
    curved25519_scalarmult_basepoint: crate::dalek_curved25519_scalarmult_basepoint,
    curve25519_scalarmult: crate::dalek_curve25519_scalarmult,
    ed25519_publickey_ext: 
    crate::dalek_ed25519_publickey_ext,
    ed25519_sign_ext: crate::dalek_ed25519_sign_ext,
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
        unsafe { (signer.ed25519_publickey)(batch[i].0.as_mut_ptr() as *mut SecretKey, batch[i].1.as_mut_ptr() as *mut PublicKey) };

        // Generate and sign message
        getrandom::getrandom(&mut batch[i].2).unwrap();
        unsafe { (signer.ed25519_sign)(
            batch[i].2.as_ptr(),
            batch[i].3, batch[i].0.as_mut_ptr() as *mut SecretKey,
            batch[i].1.as_mut_ptr() as *mut PublicKey,
            batch[i].4.as_mut_ptr() as *mut Signature,
        ) };
    }

    batch
}