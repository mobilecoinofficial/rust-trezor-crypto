//! A dalek cryptography based reproduction of the ed25519-donna API
//!
//! See:
//!   - https://github.com/ryankurte/rust-dalek-donna

#![cfg_attr(not(feature = "std"), no_std)]

use cty::c_int;


#[cfg(feature = "build_donna")]
pub mod ffi;

#[cfg(feature = "build_donna")]
pub mod test;

pub mod curve25519;

pub mod ed25519;

// Bindgen / cty have some weird behaviours when mapping `size_t` on different platforms.
// use [`Uint`] in place of `cty::size_t` to avoid this.

/// Alias for size_t on 32-bit platforms where size_t is c_uint
#[cfg(target_pointer_width = "32")]
pub type UInt = cty::c_uint;

/// Alias for size_t on 64-bit platforms where size_t is c_ulong
#[cfg(target_pointer_width = "64")]
pub type UInt = cty::uint64_t;
