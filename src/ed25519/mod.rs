//! Curve25519 operations over `sha512` (default), [`keccak`], and [`sha3`].
//! 
//! These functions are ABI compatible with those provided by `donna`, with the addition of a `dalek_` prefix to allow linking both implementations for testing.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    digest::{consts::U64, Digest}, montgomery::MontgomeryPoint,
};
use ed25519_dalek::{Sha512, Signer, Verifier, ExpandedSecretKey};
use ::sha3::Keccak256;

use crate::{Int, UInt};

/// Common constants
pub mod consts {
    pub const PUBLIC_KEY_LENGTH: usize = 32;
    pub const SECRET_KEY_LENGTH: usize = 32;
    pub const SIGNATURE_LENGTH: usize = 64;
    pub const SCALAR_LENGTH: usize = 32;

    // Ensure object sizes used here (and in FFI) match
    static_assertions::const_assert_eq!(PUBLIC_KEY_LENGTH, ed25519_dalek::PUBLIC_KEY_LENGTH);
    static_assertions::const_assert_eq!(SECRET_KEY_LENGTH, ed25519_dalek::SECRET_KEY_LENGTH);
    static_assertions::const_assert_eq!(SIGNATURE_LENGTH, ed25519_dalek::SIGNATURE_LENGTH);
}

use consts::*;

/// Ed25519 Public Key, compatible with donna's `typedef unsigned char ed25519_public_key[32]`
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

/// Ed25519 Secret Key, compatible with donna's `typedef unsigned char ed25519_secret_key[32]`
pub type SecretKey = [u8; SECRET_KEY_LENGTH];

/// Ed25519 Signature, compatible with donna's `typedef unsigned char ed25519_signature[64];`
pub type Signature = [u8; SIGNATURE_LENGTH];

/// Ed25519 Scalar, compatible with donna's `typedef unsigned char curved25519_key[32]`
pub type Scalar = [u8; SCALAR_LENGTH];


pub mod keccak;

pub mod sha3;


/// Derives a public key from a private key (using the default `sha512` digest)
///
/// Compatible with ed25519-donna [ed25519_publickey](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L45)
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey(sk: *mut SecretKey, pk: *mut PublicKey) {
    let (sk, pk) = unsafe { (&(*sk), &mut (*pk)) };

    // Parse out secret key
    let secret_key = match ed25519_dalek::SecretKey::from_bytes(sk) {
        Ok(v) => v,
        Err(_e) => {
            // TODO: how to propagate errors in a function returning void...

            // Ensure public key is zeroed
            pk.iter_mut().for_each(|v| *v = 0);

            return;
        }
    };

    // Generate and write public key
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);
    pk.copy_from_slice(public_key.as_bytes());
}

/// Generates a public key from the provided secret key using the specified [`Digest`]
pub fn ed25519_publickey_digest<D: Digest<OutputSize = U64>>(sk: &SecretKey, pk: &mut PublicKey) {
    // Generate expanded secret key from hash
    let mut h = D::new();
    h.update(&*sk);

    // Copy into buffer and clamp
    let mut buff = [0u8; 64];
    buff.copy_from_slice(h.finalize().as_slice());

    buff[0]  &= 248;
    buff[31] &=  63;
    buff[31] |=  64;

    // Generate expanded key
    let expanded = match ExpandedSecretKey::from_bytes(&buff) {
        Ok(v) => v,
        Err(_e) => return,
    };

    // Extract public key
    let public_key = ed25519_dalek::PublicKey::from(&expanded);

    // Write back to arg
    pk.copy_from_slice(public_key.as_bytes());
}

/// Verifies a signed message (using the default `sha512` digest)
///
/// Compatible with ed25519-donna [ed25519_sign_open](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L94)
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_open(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> Int {
    return ed25519_sign_open::<Sha512>(m, mlen, pk, sig);
}

/// Internal verify function, generic over digest types
fn ed25519_sign_open<D: Digest<OutputSize = U64>>(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> Int {
    // Convert pointers into slices
    let (m, pk, sig) = unsafe {
        (
            core::slice::from_raw_parts(m, mlen as usize),
            &(*pk),
            &(*sig),
        )
    };

    // Parse public key and signature
    let public_key = match ed25519_dalek::PublicKey::from_bytes(pk) {
        Ok(v) => v,
        Err(_e) => {
            return -1;
        }
    };
    let signature = match ed25519_dalek::Signature::try_from(&sig[..]) {
        Ok(v) => v,
        Err(_e) => {
            return -2;
        }
    };

    // Verify signature
    if let Err(_e) = public_key.verify_digest::<D>(m, &signature) {
        return -3;
    }

    return 0;
}

/// Internal sign function, generic over digest types
fn ed25519_sign<D: Digest<OutputSize = U64>>(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    pk: *mut PublicKey,
    sig: *mut Signature,
) {
    // Convert pointers into slices
    let (m, sk, pk, sig) = unsafe {
        (
            core::slice::from_raw_parts(m, mlen as usize),
            &(*sk),
            &(*pk),
            &mut (*sig),
        )
    };

    // Parse keys
    let secret_key = match ed25519_dalek::SecretKey::from_bytes(sk) {
        Ok(v) => v,
        Err(_e) => return,
    };
    let public_key = match ed25519_dalek::PublicKey::from_bytes(pk) {
        Ok(v) => v,
        Err(_e) => return,
    };

    // Generate edpanded for signing
    let expanded_key = ed25519_dalek::ExpandedSecretKey::from(&secret_key);

    let mut d = D::new();
    d.update(m);

    // Sign message
    let signature = expanded_key.sign_digest::<D>(m, &public_key);

    // Write signature back
    sig.copy_from_slice(signature.as_ref());
}

/// Signs a message using the provided secret key (using the default `sha512` digest)
///
/// Compatible with ed25519-donna [ed25519_sign](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L59)
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    pk: *mut PublicKey,
    sig: *mut Signature,
) {
    ed25519_sign::<Sha512>(m, mlen, sk, pk, sig);
}

const MAX_BATCH_SIZE: usize = 16;

/// Batch verify signatures, `valid[i] == 1` for valid, `valid[i] == 0` otherwise INCOMPLETE
/// 
// TODO(@ryankurte): `ed25519-donna-batchverify.h` has -a lot- going on, presumably for performance reasons (see `cargo bench`)...
// seems like [`ed25519_dalek::verify_batch`] could substitute but we still need to return the *valid values per message (and run without `std` or `alloc`)
// TODO(@ryankurte): reverse engineer the error returns from the existing code
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_open_batch(
    m: *mut *const u8,
    mlen: *mut UInt,
    pk: *mut *const u8,
    rs: *mut *const u8,
    num: UInt,
    valid: *mut Int,
) -> Int {
    use core::slice::{from_raw_parts};

    // Convert pointers into slices
    let (m, mlen, pk, rs, valid) = unsafe {
        (
            core::slice::from_raw_parts(m, num as usize),
            core::slice::from_raw_parts(mlen, num as usize),
            core::slice::from_raw_parts_mut(pk, num as usize),
            core::slice::from_raw_parts_mut(rs, num as usize),
            core::slice::from_raw_parts_mut(valid, num as usize),
        )
    };

    let mut all_valid = 0;

    // Set all messages to invalid
    valid.iter_mut().for_each(|v| *v = 1);

    // Check for signature validity
    for i in 0..num as usize {
        let v = dalek_ed25519_sign_open(
            m[i],
            mlen[i],
            pk[i] as *mut PublicKey,
            rs[i] as *mut Signature,
        );
        valid[i] = match v {
            0 => 1,
            _ => {
                all_valid = 1;
                0
            }
        };
    }

    all_valid
}

/// Generate random bytes using the system RNG
// TODO(@ryankurte): possible we don't need this / appears primarily used for testing
#[no_mangle]
pub extern "C" fn dalek_ed25519_randombytes_unsafe(out: *mut u8, count: UInt) {
    let buff = unsafe { core::slice::from_raw_parts_mut(out, count as usize) };
    let _ = getrandom::getrandom(buff);
}

/// Perform scalar multiplication of `e` over the edwards curve point
///
/// Compatible with ed25519-donna [curved25519_scalarmult_basepoint](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L125)
#[no_mangle]
pub extern "C" fn dalek_curved25519_scalarmult_basepoint(pk: *mut Scalar, e: *mut Scalar) {
    let (pk, e) = unsafe { (&mut (*pk), &(*e)) };

    // Copy into editable slice
    let mut ec = [0u8; 32];
    ec.copy_from_slice(e);

    // Clamp
    ec[0] &= 248;
    ec[31] &= 127;
    ec[31] |= 64;

    // Expand secret
    let s = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(ec);

    // scalar * basepoint
    let p = &ED25519_BASEPOINT_TABLE * &s;

    // convert to montgomery
    /* u = (y + z) / (z - y) */
    let u = p.to_montgomery();

    // Write back to pk
    pk.copy_from_slice(u.as_bytes());
}

/// Scalar multiplication using the provided basepoint
#[no_mangle]
pub extern "C" fn dalek_curve25519_scalarmult(
    o: *mut PublicKey,
    e: *mut SecretKey,
    bp: *mut PublicKey,
) {
    let (o, e, bp) = unsafe { (&mut (*o), &(*e), &(*bp)) };

    // Copy secret into editable slice
    let mut ec = [0u8; 32];
    ec.copy_from_slice(e);

    // Clamp secret key
    ec[0] &= 248;
    ec[31] &= 127;
    ec[31] |= 64;

    let e = curve25519_dalek::scalar::Scalar::from_bits(ec);

    // Copy basepoint (public key) into slice
    let mut bpc = [0u8; 32];
    bpc.copy_from_slice(bp);

    let bp = MontgomeryPoint(bpc);

    // Compute `e * Montgomery(bp)` (ie. x25519 DH)
    let p = &e * &bp;

    // Write back to pk
    o.copy_from_slice(&p.to_bytes());
}


/// Generate a public key using the expanded (`sk + sk_ext`) form of the secret key
#[no_mangle]
pub extern "C" fn dalek_ed25519_publickey_ext(
    sk: *mut SecretKey,
    sk_ext: *mut SecretKey,
    pk: *mut PublicKey,
) {
    let (sk, sk_ext, pk) = unsafe { (&(*sk), &(*sk_ext), &mut (*pk)) };

    // Rebuild expanded key
    let mut sk_full = [0u8; 64];
    sk_full[..32].copy_from_slice(sk);
    sk_full[32..].copy_from_slice(sk_ext);

    let expanded = match ed25519_dalek::ExpandedSecretKey::from_bytes(&sk_full) {
        Ok(v) => v,
        Err(_e) => return,
    };

    // Generate public key
    let public = ed25519_dalek::PublicKey::from(&expanded);

    pk.copy_from_slice(public.as_ref());
}

/// Generate a signature using the expanded (`sk + sk_ext`) form of the secret key.
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_ext(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    sk_ext: *mut SecretKey,
    pk: *mut PublicKey,
    sig: *mut Signature,
) {
    let (m, sk, sk_ext, pk, sig) = unsafe {
        (
            core::slice::from_raw_parts(m, mlen as usize),
            &(*sk),
            &(*sk_ext),
            &(*pk),
            &mut (*sig),
        )
    };

    // Rebuild extended key
    let mut sk_full = [0u8; 64];
    sk_full[..32].copy_from_slice(sk);
    sk_full[32..].copy_from_slice(sk_ext);

    let secret_key = match ed25519_dalek::ExpandedSecretKey::from_bytes(&sk_full) {
        Ok(k) => k,
        Err(_e) => return,
    };

    let public_key = match ed25519_dalek::PublicKey::from_bytes(pk) {
        Ok(v) => v,
        Err(_e) => return,
    };

    // Generate signature
    let signature = secret_key.sign(m, &public_key);

    // Write to provided buffer
    sig.copy_from_slice(signature.as_ref());
}
