
use cty::c_uchar;

use crate::ffi::ge25519_t;

pub unsafe extern "C" fn ge25519_set_neutral(r: *mut ge25519_t) {
    (*r).y[0] = 1;
    (*r).z[0] = 1;
}

pub unsafe extern "C" fn ge25519_add(r: *mut ge25519_t, a: *const ge25519_t, b: *const ge25519_t, signbit: c_uchar) {
    

}

pub unsafe extern "C" fn ge25519_double() {

}

pub unsafe extern "C" fn ge25519_mul8() {

}

pub unsafe extern "C" fn ge25519_double_scalarmult_vartime() {

}

pub unsafe extern "C" fn ge25519_double_scalarmult_vartime2() {

}

pub unsafe extern "C" fn ge25519_scalarmult_base_wrapper() {

}

pub unsafe extern "C" fn ge25519_scalarmult() {

}

pub unsafe extern "C" fn ge25519_unpack_vartime() {

}

pub unsafe extern "C" fn ge25519_copy() {

}

pub unsafe extern "C" fn ge25519_fromfe_frombytes_vartime() {

}

pub unsafe extern "C" fn ge25519_niels_base_multiples() {

}

pub unsafe extern "C" fn ge25519_scalarmult_base_niels() {

}

