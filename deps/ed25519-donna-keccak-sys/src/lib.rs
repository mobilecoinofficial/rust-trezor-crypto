#![no_std]

// Link against ed25519-donna keccak build
#[link(name = "ed25519_donna_keccak")]
extern "C" {}

// Link against libc
#[link(name = "c")]
extern "C" {}
