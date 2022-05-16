//! A dalek cryptography based reproduction of the ed25519-donna API
//! 
//! See: 
//!   - https://github.com/ryankurte/rust-dalek-donna

#![cfg_attr(not(feature = "std"), no_std)]

use cty::c_int;

use ed25519_dalek::{Signer, Verifier, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

#[cfg(feature = "build_donna")]
pub mod ffi;

pub mod test;


// Bindgen / cty have some weird behaviours when mapping `size_t` on different platforms.
// use [`Uint`] in place of `cty::size_t` to avoid this.

/// Alias for size_t on 32-bit platforms where size_t is c_uint
#[cfg(target_pointer_width="32")]
pub type UInt = cty::c_uint;

/// Alias for size_t on 64-bit platforms where size_t is c_ulong
#[cfg(target_pointer_width="64")]
pub type UInt = cty::uint64_t;


/// Derives a public key from a private key
/// 
/// Compatible with ed25519-donna [ed25519_publickey](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519.c#L45) 
pub extern "C" fn dalek_ed25519_publickey(sk: *mut u8, pk: *mut u8) {
    // Convert pointers to slices
    let (sk, pk) = unsafe {
        (core::slice::from_raw_parts(sk, SECRET_KEY_LENGTH),
        core::slice::from_raw_parts_mut(pk, PUBLIC_KEY_LENGTH))
    };

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
pub extern "C" fn dalek_ed25519_sign_open(m: *const u8, mlen: UInt, pk: *mut u8, sig: *mut u8) -> c_int {
    // Convert pointers into slices
    let (m, pk, sig) = unsafe {(
        core::slice::from_raw_parts(m, mlen as usize),
        core::slice::from_raw_parts(pk, PUBLIC_KEY_LENGTH),
        core::slice::from_raw_parts(sig, SIGNATURE_LENGTH),
    )};

    // Parse public key and signature
    let public_key = match ed25519_dalek::PublicKey::from_bytes(pk) {
        Ok(v) => v,
        Err(_e) => {
            return -1;
        }
    };
    let signature = match ed25519_dalek::Signature::try_from(sig) {
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
pub extern "C" fn dalek_ed25519_sign(m: *const u8, mlen: UInt, sk: *mut u8, pk: *mut u8, sig: *mut u8) {
    // Convert pointers into slices
    let (m, sk, pk, sig) = unsafe {(
        core::slice::from_raw_parts(m, mlen as usize),
        core::slice::from_raw_parts(sk, SECRET_KEY_LENGTH),
        core::slice::from_raw_parts(pk, PUBLIC_KEY_LENGTH),
        core::slice::from_raw_parts_mut(sig, SIGNATURE_LENGTH),
    )};

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
    let keypair = ed25519_dalek::Keypair{
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
// TODO: `ed25519-donna-batchverify.h` has -a lot- going on, presumably for performance reasons (see `cargo bench`)... need to understand and implement this
// TODO: reverse engineer the error returns from the existing code
pub extern "C" fn dalek_ed25519_sign_open_batch(m: *mut *const u8, mlen: *mut UInt, pk: *mut *const u8, rs: *mut *const u8, num: UInt, valid: *mut c_int) -> c_int {
    // Convert pointers into slices
    let (m, mlen, pk, rs, valid) = unsafe {(
        core::slice::from_raw_parts(m, num as usize),
        core::slice::from_raw_parts(mlen, num as usize),
        core::slice::from_raw_parts_mut(pk, num as usize),
        core::slice::from_raw_parts_mut(rs, num as usize),
        core::slice::from_raw_parts_mut(valid, num as usize)
    )};

    let mut all_valid = 0;

    // Set all messages to invalid
    valid.iter_mut().for_each(|v| *v = 1);

    // Check for signature validity
    for i in 0..num as usize {
        let v = dalek_ed25519_sign_open(m[i], mlen[i], pk[i] as *mut u8, rs[i] as *mut u8);
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
pub extern "C" fn dalek_ed25519_randombytes_unsafe(out: *mut u8, count: UInt) {
    let buff = unsafe { core::slice::from_raw_parts_mut(out, count as usize) };
    let _ = getrandom::getrandom(buff);
}

/// TODO: this
pub extern "C" fn dalek_curved25519_scalarmult_basepoint(pk: *mut u8, e: *const u8) {
    todo!()
}

