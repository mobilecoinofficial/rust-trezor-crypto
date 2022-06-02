//! 
//! 
//! Via ed25519-donna-impl-base.(c|h)
//! 

use cty::{c_uchar, c_int};
use curve25519_dalek::{self as c};

use crate::modm::{Bignum256Modm, Bignum25519};

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct Ge25519 {
	pub x: Bignum25519,
    pub y: Bignum25519,
    pub z: Bignum25519,
    pub t: Bignum25519,
}

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct Ge25519P1p1 {
	pub x: Bignum25519,
    pub y: Bignum25519,
    pub z: Bignum25519,
    pub t: Bignum25519,
}

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct Ge25519Niels {
	pub ysubx: Bignum25519,
    pub xaddy: Bignum25519,
    pub t2d: Bignum25519
}

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct Ge25519PNiels {
    pub ysubx: Bignum25519,
    pub xaddy: Bignum25519,
    pub z: Bignum25519,
    pub t2d: Bignum25519,
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_set_neutral(r: *mut Ge25519) {
    (*r).y[0] = 1;
    (*r).z[0] = 1;
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_add(r: *mut Ge25519, a: *const Ge25519, b: *const Ge25519, signbit: c_uchar) {
    //ge25519_pniels P_ni = {0};
	//ge25519_p1p1 P_11 = {0};

	//ge25519_full_to_pniels(&P_ni, q);
	//ge25519_pnielsadd_p1p1(&P_11, p, &P_ni, signbit);
	//ge25519_p1p1_to_full(r, &P_11);
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_double(r: *mut Ge25519, p: *const Ge25519) {
    //	ge25519_p1p1 t = {0};
    //	ge25519_double_p1p1(&t, p);
    //	ge25519_p1p1_to_full(r, &t);
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_mul8(r: *mut Ge25519, p: *const Ge25519) {
    //ge25519_double_partial(r, t);
	//ge25519_double_partial(r, r);
	//ge25519_double(r, r);
    todo!()
}

/// computes [s1]p1 + [s2]base
#[no_mangle]
pub unsafe extern "C" fn ge25519_double_scalarmult_vartime(r: *mut Ge25519, p1: *const Ge25519, s1: *const Bignum256Modm, s2: *const Bignum256Modm) {

}

/// computes [s1]p1 + [s2]p2
#[no_mangle]
pub unsafe extern "C" fn ge25519_double_scalarmult_vartime2(r: *mut Ge25519, p1: *const Ge25519, s1: *const Bignum256Modm, p2: *const Ge25519, s2: *const Bignum256Modm) {
    todo!()
}


#[no_mangle]
pub unsafe extern "C" fn ge25519_pack() {
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_unpack_vartime() {
    //int res = ge25519_unpack_negative_vartime(r, s);
	//ge25519_neg_full(r);
	//return res;
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_copy(r: *mut Ge25519, p: *const Ge25519) {
    (*r).x = (*p).x;
    (*r).y = (*p).y;
    (*r).z = (*p).z;
    (*r).t = (*p).t;
}

// ??
#[no_mangle]
pub unsafe extern "C" fn ge25519_fromfe_frombytes_vartime() {
    todo!()
}

// computes [s1]p1, constant time 
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult(r: *mut Ge25519, p1: *const Ge25519, s1: *const Bignum256Modm) {
    todo!()
}

/// computes [s] niels_basepoint
/// 
/// (wraps [`ge25519_scalarmult_base_niels`] while passing basepoint table)
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult_base_wrapper(r: *mut Ge25519, p: *const Bignum256Modm) {
    // 	ge25519_scalarmult_base_niels(r, ge25519_niels_base_multiples, s);
    todo!()
}

/// computes [s]basepoint
/// TODO(@ryankurte): existing impl expects basepoint table passed in, refactor to avoid?
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult_base_niels(r: *mut Ge25519, p: *const Bignum256Modm) {
    todo!()
}


#[no_mangle]
pub unsafe extern "C" fn ge25519_check(r: *const Ge25519) -> c_int {
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_eq(a: *const Ge25519, b: *const Ge25519) -> c_int {
    todo!()
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_verify() {
    todo!()
}
