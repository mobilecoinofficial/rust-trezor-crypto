# trezor-crypto-lib

A rust implementation of the [trezor-crypto]() C APIs based on [dalek cryptography](https://github.com/dalek-cryptography/).

## Status

[![GitHub tag](https://img.shields.io/github/tag/ryankurte/rust-trezor-crypto.svg)](https://github.com/ryankurte/rust-trezor-crypto)
[![Rust](https://github.com/ryankurte/rust-trezor-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/ryankurte/rust-trezor-crypto/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/trezor-crypto-lib.svg)](https://crates.io/crates/trezor-crypto-lib)
[![Docs.rs](https://docs.rs/trezor-crypto-lib/badge.svg)](https://docs.rs/trezor-crypto-lib)


## Layout

- [src](src/) contains the cryptographic function implementations
- [vendor](vendor/) contains vendored in submodules for compatibility tests
- [deps](deps/) contains `*-sys` modules wrapping vendored code
- [tests](tests/) contains compatibility tests for `trezor-crypto-lib` operations against `*-sys` modules
