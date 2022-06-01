
use crate::{UInt, c_int};
use super::{PublicKey, SecretKey, Signature};

use sha3::Keccak512;

/// Derives a public key from a private key using keccak digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey_keccak(sk: *mut SecretKey, pk: *mut PublicKey) {
    super::ed25519_publickey::<Keccak512>(sk, pk)
}

/// Signs a message using the provided secret key using keccak digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_keccak(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    pk: *mut PublicKey,
    sig: *mut Signature,
) {
    super::ed25519_sign::<Keccak512>(m, mlen, sk, pk, sig)
}

/// Verifies a message using the provided secret key using keccak digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_open_keccak(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> c_int {
    super::ed25519_sign_open::<Keccak512>(m, mlen, pk, sig)
}


#[cfg(test)]
mod tests {
    use crate::ed25519::*;
    use super::*;

    pub struct Driver {
        pub ed25519_publickey_keccak: unsafe extern "C" fn(*mut SecretKey, *mut PublicKey),
        pub ed25519_sign_keccak:
            unsafe extern "C" fn(*const u8, UInt, *mut SecretKey, *mut PublicKey, *mut Signature),
        pub ed25519_sign_open_keccak:
            unsafe extern "C" fn(*const u8, UInt, *mut PublicKey, *mut Signature) -> i32,
    }

    const DALEK: Driver = Driver {
        ed25519_publickey_keccak: dalek_ed25519_publickey_keccak,
        ed25519_sign_keccak: dalek_ed25519_sign_keccak,
        ed25519_sign_open_keccak: dalek_ed25519_sign_open_keccak,
    };

    // TODO: Donna driver

    // TODO: Interop tests
}