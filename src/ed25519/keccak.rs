//! ed25519 API using `keccak512` signatures, equivalent to `ed25519-donna` APIs generated with a custom `keccak512` hasher (see [`tests/ed25519-keccak.c`](https://github.com/ryankurte/rust-trezor-crypto/blob/main/tests/ed25519-keccak.c))

use super::{PublicKey, SecretKey, Signature};
use crate::{Int, UInt};

use curve25519_dalek::montgomery::MontgomeryPoint;
use sha3::{Digest, Keccak512};

/// Derives a public key from a private key using keccak digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey_keccak(sk: *mut SecretKey, pk: *mut PublicKey) {
    let (sk, pk) = unsafe { (&(*sk), &mut (*pk)) };

    super::ed25519_publickey_digest::<Keccak512>(sk, pk)
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
) -> Int {
    super::ed25519_sign_open::<Keccak512>(m, mlen, pk, sig)
}

/// Scalar multiplication using the provided basepoint via Keccak derivation
// TODO(@ryankurte): added in an attempt to assuage NEM tests
#[no_mangle]
pub extern "C" fn dalek_curved25519_scalarmult_basepoint_keccak(
    o: *mut PublicKey,
    e: *mut SecretKey,
    bp: *mut PublicKey,
) -> i32 {
    let (o, e, bp) = unsafe { (&mut (*o), &(*e), &(*bp)) };

    // Construct scalar via keccak hash
    let e = curve25519_dalek::scalar::Scalar::hash_from_bytes::<Keccak512>(e);

    // Copy basepoint (public key) into slice
    let mut bpc = [0u8; 32];
    bpc.copy_from_slice(bp);

    let bp = MontgomeryPoint(bpc);

    // Compute `e * Montgomery(bp)` (ie. x25519 DH)
    let p = &e * &bp;

    // Write back to pk
    o.copy_from_slice(&p.to_bytes());

    return 0;
}

