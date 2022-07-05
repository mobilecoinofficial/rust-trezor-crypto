//! ed25519 API using `keccak512` signatures, equivalent to `ed25519-donna` APIs generated with a custom `keccak512` hasher (see [`tests/ed25519-keccak.c`](https://github.com/ryankurte/rust-trezor-crypto/blob/main/tests/ed25519-keccak.c))

use super::{PublicKey, SecretKey, Signature};
use crate::{Int, UInt};

use curve25519_dalek::{
    edwards::CompressedEdwardsY,
};
use sha3::{Digest, Keccak512};

/// Derives a public key from a private key using keccak digest
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey_keccak(sk: *mut SecretKey, pk: *mut PublicKey) {
    let (sk, pk) = unsafe { (&(*sk), &mut (*pk)) };

    super::ed25519_publickey_digest::<Keccak512>(sk, pk)
}


/// Signs a message using the provided secret key using keccak digest (both for message and secret key expansion)
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

/// Verifies a message using the provided public key and signature using keccak digest
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
// TODO(@ryankurte): WIP in an attempt to assuage NEM tests
#[no_mangle]
pub extern "C" fn dalek_ed25519_scalarmult_keccak(
    o: *mut PublicKey,
    sk: *mut SecretKey,
    bp: *mut PublicKey,
) -> i32 {
    let (o, sk, bp) = unsafe { (&mut (*o), &(*sk), &(*bp)) };

    // Construct expanded secret key using digest
    let mut h = Keccak512::new();
    h.update(&*sk);

    // Copy into buffer and clamp
    let mut buff = [0u8; 32];
    buff.copy_from_slice(&h.finalize().as_slice()[..32]);

    buff[0]  &= 248;
    buff[31] &=  63;
    buff[31] |=  64;

    // Construct scalar via keccak hash
    let e = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(buff);

    // Expand basepoint to ge25519 pt
    let bp = match CompressedEdwardsY(*bp).decompress() {
        Some(v) => v,
        None => return 1,
    };

    // Compute `e * bp` (ie. x25519 DH)
    let p = &e * &bp;

    // Compress result point
    let u = p.compress();

    // Write back to pk
    o.copy_from_slice(&u.to_bytes());

    return 0;
}

/// Scalar multiplication via Keccak derivation using the default basepoint
// TODO(@ryankurte): WIP in an attempt to assuage NEM tests
#[no_mangle]
pub extern "C" fn dalek_curved25519_scalarmult_basepoint_keccak(
    o: *mut PublicKey,
    s: *mut SecretKey,
) {
    super::dalek_curved25519_scalarmult_basepoint(o, s);
}

/// Integration tests (self contained)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::decode_bytes;

    #[test]
    fn ed25519_keccak_pubkey_derive() {
        // Vectors from trezor's test_apps.nem.hdnode.py
        // (with inexplicably reversed private keys)
        let tests = &[(
            "575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced",
            "c5f54ba980fcbb657dbaaa42700539b207873e134d2375efeab5f1ab52f87844",
        ), (
            "5b0e3fa5d3b49a79022d7c1e121ba1cbbf4db5821f47ab8c708ef88defc29bfe",
            "96eb2a145211b1b7ab5f0d4b14f8abc8d695c7aee31a3cfc2d4881313c68eea3",
        ), (
            "e8bf9bc0f35c12d8c8bf94dd3a8b5b4034f1063948e3cc5304e55e31aa4b95a6",
            "4feed486777ed38e44c489c7c4e93a830e4c4a907fa19a174e630ef0f6ed0409",
        )];

        for (pri_key, pub_key) in tests {
            let mut pri_key = decode_bytes::<32>(pri_key);
            pri_key.reverse();

            let pub_key = decode_bytes::<32>(pub_key);

            let mut p = PublicKey::default();

            dalek_ed25519_publickey_keccak(&mut pri_key, &mut p);

            assert_eq!(pub_key, p, "expected: {:02x?} actual: {:02x?}", pub_key, p);
        }
    }
}