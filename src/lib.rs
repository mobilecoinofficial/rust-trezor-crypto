//! A rust implementation of the trezor-crypto library
//! 
//! See <https://github.com/ryankurte/rust-trezor-crypto>

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(doc_cfg)]

#[cfg(feature = "build_donna")]
pub mod ffi;

#[cfg(feature = "build_donna")]
pub mod test;

pub mod ed25519;

pub mod ge;

pub mod modm;

// Bindgen / cty have some weird behaviours when mapping `size_t` on different platforms.
// use [`Uint`] in place of `cty::size_t` to avoid this.

/// Alias for size_t on 32-bit platforms where usize_t is c_uint
#[cfg(target_pointer_width = "32")]
pub type UInt = cty::c_uint;

/// Alias for size_t on 64-bit platforms where usize_t is c_ulong
#[cfg(target_pointer_width = "64")]
pub type UInt = cty::uint64_t;

/// Alias for int on all platforms
pub type Int = cty::c_int;
