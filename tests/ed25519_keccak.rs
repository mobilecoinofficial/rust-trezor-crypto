
use {ed25519_donna_keccak_sys as _};

use trezor_crypto_lib::{
    ffi,
    ed25519::keccak,
    test::{self, Driver},
};

/// Dalek driver implementation
const DALEK: Driver = Driver {
    publickey: keccak::ed25519_publickey_keccak,
    sign: keccak::ed25519_sign_keccak,
    sign_open: keccak::ed25519_sign_open_keccak,
    curved25519_scalarmult_basepoint: keccak::curved25519_scalarmult_basepoint_keccak,
    curve25519_scalarmult: None,
    ed25519_scalarmult: Some(keccak::ed25519_scalarmult_keccak),
};

/// Donna driver implementation (keccak build via FFI)
const DONNA: Driver = Driver {
    publickey: ffi::ed25519_publickey_donna_keccak,
    sign: ffi::ed25519_sign_donna_keccak,
    sign_open: ffi::ed25519_sign_open_donna_keccak,
    curved25519_scalarmult_basepoint: ffi::curved25519_scalarmult_basepoint_donna_keccak,
    curve25519_scalarmult: None,
    ed25519_scalarmult: Some(ffi::ed25519_scalarmult_donna_keccak),
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
fn ed25519_scalarmult() {
    test::ed25519_scalarmult(&DALEK, &DONNA);
}

#[test]
fn curved25519_scalarmult_basepoint() {
    test::scalarmult_basepoint(&DALEK, &DONNA);
}
