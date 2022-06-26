//! ed25519 API using `sha3` signatures, equivalent to `ed25519-donna` APIs generated with a custom `sha3` hasher (see [`tests/ed25519-sha3.c`](https://github.com/ryankurte/rust-trezor-crypto/blob/main/tests/ed25519-sha3.c))

use super::{ed25519_sign, PublicKey, SecretKey, Signature};
use crate::{Int, UInt};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use sha3::Sha3_512;

/// Derives a public key from a private key using sha3 digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey_sha3(sk: *mut SecretKey, pk: *mut PublicKey) {
    let (sk, pk) = unsafe { (&(*sk), &mut (*pk)) };
    super::ed25519_publickey_digest::<Sha3_512>(sk, pk)
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

/// Scalar multiplication via Keccak derivation using the default basepoint
// TODO(@ryankurte): WIP in an attempt to assuage NEM tests
#[no_mangle]
pub extern "C" fn dalek_curved25519_scalarmult_basepoint_sha3(
    o: *mut PublicKey,
    s: *mut SecretKey,
) {
    super::dalek_curved25519_scalarmult_basepoint(o, s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::*;

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
