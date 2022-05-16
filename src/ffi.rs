//! FFI bindings derived from ed25519-dalek headers

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Include generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Link donna library if enabled with feature `donna`
#[cfg_attr(feature = "build_donna", link(name = "ed25519_donna"))] extern {}


pub type PublicKey = crate::ffi::ed25519_public_key;

pub type SecretKey = crate::ffi::ed25519_secret_key;

pub type Signature = crate::ffi::ed25519_signature;

// NOTE: bindgen fails to track const/mut correctly over typedef'ed arrays
// so mutability is a bit all over the show...
// https://github.com/rust-lang/rust-bindgen/issues/1962

