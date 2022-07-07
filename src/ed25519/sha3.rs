//! ed25519 API using `sha3` signatures, equivalent to `ed25519-donna` APIs generated with a custom `sha3` hasher (see [`tests/ed25519-sha3.c`](https://github.com/ryankurte/rust-trezor-crypto/blob/main/tests/ed25519-sha3.c))

use super::{PublicKey, SecretKey, Signature};
use crate::{Int, UInt};

use sha3::Sha3_512;

/// Derives a public key from a private key using sha3 digest
#[no_mangle]
pub extern "C" fn ed25519_publickey_sha3(sk: *mut SecretKey, pk: *mut PublicKey) {
    let (sk, pk) = unsafe { (&(*sk), &mut (*pk)) };
    super::ed25519_publickey_digest::<Sha3_512>(sk, pk)
}

/// Signs a message using the provided secret key using sha3 digest
#[no_mangle]
pub extern "C" fn ed25519_sign_sha3(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    pk: *mut PublicKey,
    sig: *mut Signature,
) {
    super::ed25519_sign_internal::<Sha3_512>(m, mlen, sk, pk, sig)
}

/// Verifies a message using the provided secret key using sha3 digest
#[no_mangle]
pub extern "C" fn ed25519_sign_open_sha3(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> Int {
    super::ed25519_sign_open_internal::<Sha3_512>(m, mlen, pk, sig)
}

/// Scalar multiplication via Keccak derivation using the default basepoint
// TODO(@ryankurte): WIP in an attempt to assuage NEM tests
#[no_mangle]
pub extern "C" fn curved25519_scalarmult_basepoint_sha3(
    o: *mut PublicKey,
    s: *mut SecretKey,
) {
    super::curved25519_scalarmult_basepoint(o, s);
}

#[cfg(test)]
mod tests {
    
    // TODO: covered via interop tests but, any test vectors we can find?
}
