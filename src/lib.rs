//! A dalek cryptography based reproduction of the ed25519-donna API
//!
//! See:
//!   - https://github.com/ryankurte/rust-dalek-donna

#![cfg_attr(not(feature = "std"), no_std)]

use cty::c_int;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use ed25519_dalek::{Signer, Verifier};

#[cfg(feature = "build_donna")]
pub mod ffi;

#[cfg(feature = "build_donna")]
pub mod test;

// Constant lengths
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

use crate::consts::*;

// Bindgen / cty have some weird behaviours when mapping `size_t` on different platforms.
// use [`Uint`] in place of `cty::size_t` to avoid this.

/// Alias for size_t on 32-bit platforms where size_t is c_uint
#[cfg(target_pointer_width = "32")]
pub type UInt = cty::c_uint;

/// Alias for size_t on 64-bit platforms where size_t is c_ulong
#[cfg(target_pointer_width = "64")]
pub type UInt = cty::uint64_t;

/// PublicKey array
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

/// SecretKey array
pub type SecretKey = [u8; SECRET_KEY_LENGTH];

/// Signature array
pub type Signature = [u8; SIGNATURE_LENGTH];

/// Scalar array
pub type Scalar = [u8; SCALAR_LENGTH];

/// Derives a public key from a private key
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

/// Verifies a signed message
///
/// Compatible with ed25519-donna [ed25519_sign_open](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L94)
#[no_mangle]
pub extern "C" fn dalek_ed25519_sign_open(
    m: *const u8,
    mlen: UInt,
    pk: *mut PublicKey,
    sig: *mut Signature,
) -> c_int {
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
    if let Err(_e) = public_key.verify(m, &signature) {
        return -3;
    }

    return 0;
}

/// Signs a message using the provided secret key
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

    // Generate keypair for signing
    let keypair = ed25519_dalek::Keypair {
        public: public_key,
        secret: secret_key,
    };

    // Sign message
    let signature = match keypair.try_sign(m) {
        Ok(v) => v,
        Err(_e) => {
            // Ensure signature is zeroed
            sig.iter_mut().for_each(|v| *v = 0);
            return;
        }
    };

    // Write signature back
    sig.copy_from_slice(signature.as_ref());
}

/// Batch verify signatures, valid[i] == 1 for valid, 0 otherwise
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
    valid: *mut c_int,
) -> c_int {
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
// TODO(@ryankurte): possible we don't need this
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

    // Copy basepoint (public key) into editable slice
    let mut bpc = [0u8; 32];
    bpc.copy_from_slice(bp);

    // Clamp secret key and expand
    //ec[0] &= 248;
    //ec[31] &= 127;
    //ec[31] |= 64;

    let secret = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(ec.clone());

    let basepoint = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bpc.clone());

    // Perform multiplication
    // TODO: work out what this is -meant- to be doing

    #[cfg(nope)]
    let p = {
        let p = &ED25519_BASEPOINT_TABLE.basepoint_mul(&basepoint) * &secret;
        p.to_montgomery().to_bytes()
    };

    #[cfg(nope)]
    let p = {
        let p = &ED25519_BASEPOINT_TABLE * &secret * &basepoint;
        p.to_montgomery().to_bytes()
    };

    #[cfg(nope)]
    let p = {
        let shared = x25519_dalek::StaticSecret::from(ec.clone());
        let public = x25519_dalek::PublicKey::from(bpc.clone());

        let x = shared.diffie_hellman(&public);
        x.to_bytes()
    };

    //#[cfg(nope)]
    let p = { x25519_dalek::x25519(ec, bpc) };

    // Write back to pk
    o.copy_from_slice(&p);
}

/// Generate a public key using the expanded (sk + sk_ext) form of the secret key
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

/// Generate a signature using the expanded (sk + sk_ext) form of the secret key.
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
