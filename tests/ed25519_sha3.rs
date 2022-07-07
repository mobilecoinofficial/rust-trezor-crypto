
use {ed25519_donna_sha3_sys as _};

use trezor_crypto_lib::{
    ffi,
    ed25519::sha3,
    test::{self, Driver},
};

/// Dalek driver implementation
const DALEK: Driver = Driver {
    publickey: sha3::ed25519_publickey_sha3,
    sign: sha3::ed25519_sign_sha3,
    sign_open: sha3::ed25519_sign_open_sha3,
    curved25519_scalarmult_basepoint: sha3::curved25519_scalarmult_basepoint_sha3,
    curve25519_scalarmult: None,
    ed25519_scalarmult: None,
};

/// Donna driver implementation (sha3 build via FFI)
const DONNA: Driver = Driver {
    publickey: ffi::ed25519_publickey_donna_sha3,
    sign: ffi::ed25519_sign2_donna_sha3,
    sign_open: ffi::ed25519_sign_open_donna_sha3,
    curved25519_scalarmult_basepoint: ffi::curved25519_scalarmult_basepoint_donna_sha3,
    curve25519_scalarmult: None,
    ed25519_scalarmult: None,
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