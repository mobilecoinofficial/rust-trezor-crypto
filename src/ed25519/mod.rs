//! Curve25519 operations over `sha512` (default), [`keccak`], and [`sha3`].
//! 
//! These functions are ABI compatible with those provided by `donna`

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    digest::{consts::U64, Digest}, montgomery::MontgomeryPoint,
};
use ed25519_dalek::{Sha512, ExpandedSecretKey};

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

/// COSI specific signature type
pub type CosiSignature = [u8; SCALAR_LENGTH];

pub mod keccak;

pub mod sha3;

pub mod cosi;

/// Derives a public key from a private key (using the default `sha512` digest)
///
/// Compatible with ed25519-donna [ed25519_publickey](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L45)
#[no_mangle]
pub extern "C" fn ed25519_publickey(sk: *mut SecretKey, pk: *mut PublicKey) {
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
fn ed25519_publickey_digest<D: Digest<OutputSize = U64>>(sk: &SecretKey, pk: &mut PublicKey) {
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
pub extern "C" fn ed25519_sign_open(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> Int {
    return ed25519_sign_open_internal::<Sha512>(m, mlen, pk, sig);
}

/// Internal verify function, generic over digest types
fn ed25519_sign_open_internal<D: Digest<OutputSize = U64>>(
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
fn ed25519_sign_internal<D: Digest<OutputSize = U64>>(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    sig: *mut Signature,
) {
    // Convert pointers into slices
    let (m, sk, sig) = unsafe {
        (
            core::slice::from_raw_parts(m, mlen as usize),
            &(*sk),
            &mut (*sig),
        )
    };

    let secret_key = match ed25519_dalek::SecretKey::from_bytes(sk) {
        Ok(v) => v,
        Err(_e) => return,
    };


    // Expand secret key using provided digest
    let mut h = D::new();
    h.update(&*sk);

    // Copy into buffer and clamp
    let mut buff = [0u8; 64];
    buff.copy_from_slice(h.finalize().as_slice());

    buff[0]  &= 248;
    buff[31] &=  63;
    buff[31] |=  64;

    // Generate expanded key
    let secret_key = match ExpandedSecretKey::from_bytes(&buff) {
        Ok(v) => v,
        Err(_e) => return,
    };

    // Generate matching public key
    let public_key = ed25519_dalek::PublicKey::from(&secret_key);

    // Generate message hash for signing
    let mut d = D::new();
    d.update(m);

    // Sign message
    let signature = secret_key.sign_digest::<D>(m, &public_key);

    // Write signature back
    sig.copy_from_slice(signature.as_ref());
}

/// Signs a message using the provided secret key (using the default `sha512` digest)
///
/// Compatible with ed25519-donna [ed25519_sign](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L59)
#[no_mangle]
pub extern "C" fn ed25519_sign(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    sig: *mut Signature,
) {
    ed25519_sign_internal::<Sha512>(m, mlen, sk, sig);
}

/// Generate random bytes using the system RNG
// TODO(@ryankurte): possible we don't need this / appears primarily used for testing
#[no_mangle]
pub extern "C" fn ed25519_randombytes_unsafe(out: *mut u8, count: UInt) {
    let buff = unsafe { core::slice::from_raw_parts_mut(out, count as usize) };
    let _ = getrandom::getrandom(buff);
}

/// Perform scalar multiplication of `e` over the edwards curve point
///
/// Compatible with ed25519-donna [curved25519_scalarmult_basepoint](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L125)
#[no_mangle]
pub extern "C" fn curved25519_scalarmult_basepoint(pk: *mut Scalar, e: *mut Scalar) {
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
    let p = &ED25519_BASEPOINT_POINT * &s;

    // convert to montgomery
    /* u = (y + z) / (z - y) */
    let u = p.to_montgomery();

    // Write back to pk
    pk.copy_from_slice(u.as_bytes());
}



/// Scalar multiplication using the provided basepoint
#[no_mangle]
pub extern "C" fn curve25519_scalarmult(
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


/// Generate a public key corresponding to the expanded form of the secret key
/// NOTE: this uses the _non expanded_ secret key for derivation
#[no_mangle]
pub extern "C" fn ed25519_publickey_ext(
    sk: *mut SecretKey,
    pk: *mut PublicKey,
) {
    let (sk, pk) = unsafe { (&(*sk), &mut (*pk)) };

    let a = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(*sk);

    let A = a * &ED25519_BASEPOINT_POINT;

    let c = A.compress();

    pk.copy_from_slice(c.as_bytes());
}

/// Generate a signature using the expanded (`sk + sk_ext`) form of the secret key.
#[no_mangle]
pub extern "C" fn ed25519_sign_ext(
    m: *const u8,
    mlen: UInt,
    sk: *mut SecretKey,
    sk_ext: *mut SecretKey,
    sig: *mut Signature,
) {
    let (m, sk, sk_ext, sig) = unsafe {
        (
            core::slice::from_raw_parts(m, mlen as usize),
            &(*sk),
            &(*sk_ext),
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

    let public_key = ed25519_dalek::PublicKey::from(&secret_key);

    // Generate signature
    let signature = secret_key.sign(m, &public_key);

    // Write to provided buffer
    sig.copy_from_slice(signature.as_ref());
}



#[cfg(test)]
mod test {
    use super::*;

    // Vectors from `test_trezor.crypto.curve.curve25519.py`
    const SCALARMULT_VECS: (&str, &str, &str) = (
        "38c9d9b17911de26ed812f5cc19c0029e8d016bcbc6078bc9db2af33f1761e4a",
        "311b6248af8dabec5cc81eac5bf229925f6d218a12e0547fb1856e015cc76f5d",
        "a93dbdb23e5c99da743e203bd391af79f2b83fb8d0fd6ec813371c71f08f2d4d",
    );

    #[test]
    fn curve25519_scalarmult_vectors() {
        let (mut sk, mut pk, mut sess) = ([0u8; 32], [0u8; 32], [0u8; 32]);

        hex::decode_to_slice(SCALARMULT_VECS.0, &mut sk).unwrap();
        hex::decode_to_slice(SCALARMULT_VECS.1, &mut pk).unwrap();
        hex::decode_to_slice(SCALARMULT_VECS.2, &mut sess).unwrap();

        let mut sess2 = [0u8; 32];
        
        (curve25519_scalarmult)(
            sess2.as_mut_ptr() as *mut Scalar,
            sk.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        );

        assert_eq!(&sess[..], &sess2[..])
    }
}
