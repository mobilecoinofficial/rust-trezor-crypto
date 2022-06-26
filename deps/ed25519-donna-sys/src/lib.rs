#![no_std]

// Link against ed25519-donna standard build
#[link(name = "ed25519_donna")]
extern "C" {}

// Link against libc
#[link(name = "c")]
extern "C" {}
