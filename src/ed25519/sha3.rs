
use crate::{UInt, Int};
use super::{PublicKey, SecretKey, Signature, ed25519_sign};

use sha3::Sha3_512;

/// Derives a public key from a private key using sha3 digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey_sha3(sk: *mut SecretKey, pk: *mut PublicKey) {
    super::ed25519_publickey::<Sha3_512>(sk, pk)
}

/// Signs a message using the provided secret key using sha3 digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_sha3(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    pk: *mut PublicKey,
    sig: *mut Signature,
) {
    super::ed25519_sign::<Sha3_512>(m, mlen, sk, pk, sig)
}

/// Verifies a message using the provided secret key using sha3 digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_open_sha3(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> Int {
    super::ed25519_sign_open::<Sha3_512>(m, mlen, pk, sig)
}


#[cfg(test)]
mod tests {
    use crate::ed25519::*;
    use super::*;

    pub struct Driver {
        pub ed25519_publickey_sha3: unsafe extern "C" fn(*mut SecretKey, *mut PublicKey),
        pub ed25519_sign_sha3:
            unsafe extern "C" fn(*const u8, UInt, *mut SecretKey, *mut PublicKey, *mut Signature),
        pub ed25519_sign_open_sha3:
            unsafe extern "C" fn(*const u8, UInt, *mut PublicKey, *mut Signature) -> i32,
    }

    const DALEK: Driver = Driver {
        ed25519_publickey_sha3: dalek_ed25519_publickey_sha3,
        ed25519_sign_sha3: dalek_ed25519_sign_sha3,
        ed25519_sign_open_sha3: dalek_ed25519_sign_open_sha3,
    };

    // TODO: Donna driver

    // TODO: Interop tests
}