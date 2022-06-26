//! FFI bindings for compatibility tests, derived from [ed25519-donna](https://github.com/floodyberry/ed25519-donna) headers

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Include generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// NOTE: bindgen fails to track const/mut correctly over typedef'ed arrays
// so mutability of generated APIs is unfortunately all over the show...
// see: https://github.com/rust-lang/rust-bindgen/issues/1962

pub type PublicKey = crate::ffi::ed25519_public_key;

pub type SecretKey = crate::ffi::ed25519_secret_key;

pub type Signature = crate::ffi::ed25519_signature;

