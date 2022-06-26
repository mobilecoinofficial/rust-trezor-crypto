
use ed25519_donna_sys;

use trezor_crypto_lib::{
    UInt,
    ffi,
    ed25519::{self, PublicKey, SecretKey, Signature, Scalar},
    test::{self, Driver, ExtendedDriver, Batch},
};

/// Donna driver implementation (via FFI)
pub const DONNA: ExtendedDriver = ExtendedDriver {
    driver: Driver{
        publickey: ffi::ed25519_publickey,
        sign_open: ffi::ed25519_sign_open,
        sign: ffi::ed25519_sign,
        scalarmult_basepoint: ffi::curved25519_scalarmult_basepoint,
        scalarmult: Some(ffi::curve25519_scalarmult),
        sign_open_batch: Some(ffi::ed25519_sign_open_batch),
    },
    publickey_ext: ffi::ed25519_publickey_ext,
    sign_ext: ffi::ed25519_sign_ext,
};

/// Dalek driver implementation (native rust)
pub const DALEK: ExtendedDriver = ExtendedDriver {
    driver: Driver{
        publickey: ed25519::dalek_ed25519_publickey,
        sign_open: ed25519::dalek_ed25519_sign_open,
        sign: ed25519::dalek_ed25519_sign,
        scalarmult_basepoint: ed25519::dalek_curved25519_scalarmult_basepoint,
        scalarmult: Some(ed25519::dalek_curve25519_scalarmult),
        sign_open_batch: Some(ed25519::dalek_ed25519_sign_open_batch),
    },
    publickey_ext: ed25519::dalek_ed25519_publickey_ext,
    sign_ext: ed25519::dalek_ed25519_sign_ext,
};

#[test]
fn pubkey_compat() {
    test::derive_keys(&DONNA, &DALEK);
}

#[test]
fn donna_sign_donna_verify() {
    test::sign_verify(&DONNA, &DONNA);
}

#[test]
fn dalek_sign_dalek_verify() {
    test::sign_verify(&DALEK, &DALEK);
}

#[test]
fn donna_sign_dalek_verify() {
    test::sign_verify(&DONNA, &DALEK);
}

#[test]
fn dalek_sign_donna_verify() {
    test::sign_verify(&DALEK, &DONNA);
}

#[test]
fn scalarmult_basepoint() {
    test::scalarmult_basepoint(&DALEK, &DONNA);
}


// TODO: work out why donna fails with larger batch sizes
const TEST_BATCH_SIZE: usize = 16;

#[test]
fn batch_verify_donna_donna() {
    test::batch_verify::<TEST_BATCH_SIZE>(&DONNA, &DONNA);
}

#[test]
fn batch_verify_dalek_dalek() {
    test::batch_verify::<TEST_BATCH_SIZE>(&DALEK, &DALEK);
}

#[test]
fn batch_verify_donna_dalek() {
    test::batch_verify::<TEST_BATCH_SIZE>(&DONNA, &DALEK);
}

#[test]
fn batch_verify_dalek_donna() {
    test::batch_verify::<TEST_BATCH_SIZE>(&DALEK, &DONNA);
}

#[test]
fn publickey_ext() {
    test::publickey_ext(&DALEK, &DONNA);
}


#[test]
fn sign_ext_dalek_donna() {
    test::sign_ext(&DALEK, &DONNA);
}

#[test]
fn sign_ext_donna_dalek() {
    test::sign_ext(&DALEK, &DONNA);
}
