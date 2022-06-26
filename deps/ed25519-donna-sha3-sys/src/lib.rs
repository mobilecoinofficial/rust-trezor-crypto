#![no_std]

// Link against ed25519-donna sha3 build
#[link(name = "ed25519_donna_sha3")]
extern "C" {}

// Link against libc
#[link(name = "c")]
extern "C" {}
