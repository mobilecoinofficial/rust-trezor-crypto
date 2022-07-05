
use {ed25519_donna_sys as _};

use trezor_crypto_lib::{
    ed25519::{self, SecretKey, PublicKey, dalek_ed25519_publickey, dalek_ed25519_sign, dalek_ed25519_sign_open},
    ffi,
    test::{self, Driver, ExtendedDriver}, UInt,
};

/// Donna driver implementation (via FFI)
pub const DONNA: ExtendedDriver = ExtendedDriver {
    driver: Driver{
        publickey: ffi::ed25519_publickey,
        sign_open: ffi::ed25519_sign_open,
        sign: ffi::ed25519_sign,
        curved25519_scalarmult_basepoint: ffi::curved25519_scalarmult_basepoint,
        curve25519_scalarmult: Some(ffi::curve25519_scalarmult),
        ed25519_scalarmult: None,
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
        curved25519_scalarmult_basepoint: ed25519::dalek_curved25519_scalarmult_basepoint,
        curve25519_scalarmult: Some(ed25519::dalek_curve25519_scalarmult),
        ed25519_scalarmult: None,
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
