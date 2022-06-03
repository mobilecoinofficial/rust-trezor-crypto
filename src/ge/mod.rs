//! 
//! 
//! Via ed25519-donna-impl-base.(c|h)
//! 

use core::ops::Mul;

use cty::{c_uchar, c_int};
use curve25519_dalek::{self as c};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};


use crate::{modm::{Bignum256Modm, Bignum25519}, ed25519::Scalar};

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct Ge25519 {
	pub x: Bignum25519,
    pub y: Bignum25519,
    pub z: Bignum25519,
    pub t: Bignum25519,
}

impl TryFrom<&Ge25519> for EdwardsPoint {
    type Error = ();

    fn try_from(v: &Ge25519) -> Result<Self, Self::Error> {
        EdwardsPoint::try_from_raw(v.x, v.y, v.z, v.t)   
    }
}

impl From<&EdwardsPoint> for Ge25519 {
    fn from(p: &EdwardsPoint) -> Self {
        let (x, y, z, t) = p.as_raw();
        Ge25519{x, y, z, t}
    }
}

#[cfg(nope)]
impl From<ProjectiveNielsPoint> for Ge25519 {
    fn from(_: ProjectiveNielsPoint) -> Self {
        todo!()
    }
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


//ge25519_pniels P_ni = {0};
//ge25519_p1p1 P_11 = {0};
//ge25519_full_to_pniels(&P_ni, q);
//ge25519_pnielsadd_p1p1(&P_11, p, &P_ni, signbit);
//ge25519_p1p1_to_full(r, &P_11);
#[no_mangle]
pub unsafe extern "C" fn ge25519_add(r: *mut Ge25519, a: *const Ge25519, b: *const Ge25519, signbit: c_uchar) {

    let a1 = match EdwardsPoint::try_from(&*a) {
        Ok(v) => v,
        Err(_) => return,
    };

    let b1 = match EdwardsPoint::try_from(&*b) {
        Ok(v) => v,
        Err(_) => return,
    };

    // TODO: what're we actually doing with the signbit here?
    let r1 = match signbit != 0 {
        true => a1 + b1,
        false => a1 - b1,
    };

    *r = Ge25519::from(&r1);
}

//	ge25519_p1p1 t = {0};
//	ge25519_double_p1p1(&t, p);
//	ge25519_p1p1_to_full(r, &t);
#[no_mangle]
pub unsafe extern "C" fn ge25519_double(r: *mut Ge25519, p: *const Ge25519) {

    let p1 = match EdwardsPoint::try_from(&*p) {
        Ok(v) => v,
        Err(_) => return,
    };

    // TODO: is doubling an edwards point equivalent to scalar multiplication..?
    // why is `.double()` internal only?
    let r1 = c::scalar::Scalar::from(2u8) * &p1;

    *r = Ge25519::from(&r1);
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_mul8(r: *mut Ge25519, p: *const Ge25519) {
    //ge25519_double_partial(r, t);
	//ge25519_double_partial(r, r);
	//ge25519_double(r, r);
    //TODO(@ryankurte): implement this
}

/// computes [s1]p1 + [s2]base
#[no_mangle]
pub unsafe extern "C" fn ge25519_double_scalarmult_vartime(r: *mut Ge25519, p1: *const Ge25519, s1: *const Bignum256Modm, s2: *const Bignum256Modm) {
    //TODO(@ryankurte): implement this
}

/// computes [s1]p1 + [s2]p2
#[no_mangle]
pub unsafe extern "C" fn ge25519_double_scalarmult_vartime2(r: *mut Ge25519, p1: *const Ge25519, s1: *const Bignum256Modm, p2: *const Ge25519, s2: *const Bignum256Modm) {
    //TODO(@ryankurte): implement this
}

/// Convert to compressed curve form
#[no_mangle]
pub unsafe extern "C" fn ge25519_pack(r: *mut [u8; 32], v: *const Ge25519) {
    //TODO(@ryankurte): implement this
    // 

    // Appears to be projectiveNielsPoint to compressed edwards..? 

}

#[no_mangle]
pub unsafe extern "C" fn ge25519_unpack_vartime() {
    //int res = ge25519_unpack_negative_vartime(r, s);
	//ge25519_neg_full(r);
	//return res;
    //TODO(@ryankurte): implement this
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
    //TODO(@ryankurte): implement this
}

// computes [s1]p1, constant time 
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult(r: *mut Ge25519, p1: *const Ge25519, s1: *const Bignum256Modm) {
    //TODO(@ryankurte): implement this
}

/// computes [s] niels_basepoint
/// 
/// (wraps [`ge25519_scalarmult_base_niels`] while passing basepoint table)
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult_base_wrapper(r: *mut Ge25519, p: *const Bignum256Modm) {
    // 	ge25519_scalarmult_base_niels(r, ge25519_niels_base_multiples, s);
    //TODO(@ryankurte): implement this
}

/// computes [s]basepoint
/// TODO(@ryankurte): existing impl expects basepoint table passed in, refactor to avoid?
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult_base_niels(r: *mut Ge25519, p: *const Bignum256Modm) {
    //TODO(@ryankurte): implement this
}


#[no_mangle]
pub unsafe extern "C" fn ge25519_check(r: *const Ge25519) -> c_int {
    //TODO(@ryankurte): implement this
    return -1;
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_eq(a: *const Ge25519, b: *const Ge25519) -> c_int {
    //TODO(@ryankurte): implement this
    return -1;
}


#[no_mangle]
pub unsafe extern "C" fn ed25519_verify() {
    //TODO(@ryankurte): implement this
}


#[cfg(test)]
mod test {


}