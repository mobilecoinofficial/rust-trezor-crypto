use byteorder::{ByteOrder, LittleEndian};
use cty::c_int;
use curve25519_dalek::scalar::Scalar;

pub type Bignum25519 = [u32; 10];

pub type Bignum256Modm = [u32; 9];


//ok &= iszero256_modm(x) ^ 1;
//barrett_reduce256_modm(t, z, x);
//ok &= eq256_modm(t, x);
#[no_mangle]
pub unsafe extern "C" fn check256_modm(v: *const Bignum256Modm) -> c_int {
    let v = Scalar::from_unpacked_u32(*v);

    // Check we-re non-zero
    if v == Scalar::zero() {
        return 0;
    }

    // TODO(@ryankurte): is this equivalent to the barrett reduction..?
    if &v != &v.reduce() {
        return 0;
    }

    return 1;
}

#[no_mangle]
pub unsafe extern "C" fn iszero256_modm(v: *const Bignum256Modm) -> c_int {
    let mut differentbits: u32 = 0;

    for i in 0..(*v).len() {
        differentbits |= (*v)[i]
    }

    (1 & ((differentbits - 1) >> (*v).len())) as i32
}

#[no_mangle]
pub unsafe extern "C" fn eq256_modm(a: *const Bignum256Modm, b: *const Bignum256Modm) -> c_int {
    let (a, b) = (Scalar::from_unpacked_u32(*a), Scalar::from_unpacked_u32(*b));

    match a == b {
        true => 1,
        false => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn get256_modm(v: *mut u64, r: *const Bignum256Modm) -> c_int {
    let r = Scalar::from_unpacked_u32(*r);

    // TODO(@ryankurte): is there some reduction that should be applied here..?

    // Check scalar is within u64 bounds
    for i in 4..32 {
        if r[i] != 0 {
            return -1;
        }
    }

    // Return scalar value
    *v = LittleEndian::read_u64(r.as_bytes());

    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn set256_modm(r: *mut Bignum256Modm, v: u64) {
    let s = Scalar::from(v);
    *r = s.to_unpacked_u32();
}

#[no_mangle]
pub unsafe extern "C" fn add256_modm(
    r: *mut Bignum256Modm,
    x: *const Bignum256Modm,
    y: *const Bignum256Modm,
) {
    let (x, y) = (Scalar::from_unpacked_u32(*x), Scalar::from_unpacked_u32(*y));

    *r = (x + y).reduce().to_unpacked_u32();
}

#[no_mangle]
pub unsafe extern "C" fn sub256_modm(
    r: *mut Bignum256Modm,
    x: *const Bignum256Modm,
    y: *const Bignum256Modm,
) {
    let (x, y) = (Scalar::from_unpacked_u32(*x), Scalar::from_unpacked_u32(*y));

    *r = (x - y).reduce().to_unpacked_u32();
}

#[no_mangle]
pub unsafe extern "C" fn mul256_modm(
    r: *mut Bignum256Modm,
    x: *const Bignum256Modm,
    y: *const Bignum256Modm,
) {
    let (x, y) = (Scalar::from_unpacked_u32(*x), Scalar::from_unpacked_u32(*y));

    *r = (x * y).reduce().to_unpacked_u32();
}

#[no_mangle]
pub unsafe extern "C" fn copy256_modm(r: *mut Bignum256Modm, x: *const Bignum256Modm) {
    *r = *x;
}

#[no_mangle]
pub unsafe extern "C" fn mulsub256_modm(
    r: *mut Bignum256Modm,
    a: *const Bignum256Modm,
    b: *const Bignum256Modm,
    c: *const Bignum256Modm,
) {
    let (a, b, c) = (
        Scalar::from_unpacked_u32(*a),
        Scalar::from_unpacked_u32(*b),
        Scalar::from_unpacked_u32(*c),
    );

    *r = (c - a * b).reduce().to_unpacked_u32();
}

#[no_mangle]
pub unsafe extern "C" fn muladd256_modm(
    r: *mut Bignum256Modm,
    a: *const Bignum256Modm,
    b: *const Bignum256Modm,
    c: *const Bignum256Modm,
) {
    let (a, b, c) = (
        Scalar::from_unpacked_u32(*a),
        Scalar::from_unpacked_u32(*b),
        Scalar::from_unpacked_u32(*c),
    );

    *r = (c + a * b).reduce().to_unpacked_u32();
}

/// [`expand256_modm`] from [modm-donna-32bit.c:208](https://github.com/floodyberry/ed25519-donna/blob/8757bd4cd209cb032853ece0ce413f122eef212c/modm-donna-32bit.h#L208)
#[no_mangle]
pub unsafe extern "C" fn expand256_modm(o: *mut Bignum256Modm, i: *const u8, len: usize) {
    let mut raw = [0u8; 32];

    let i = core::slice::from_raw_parts(i, len);
    raw.copy_from_slice(i);

    let s = Scalar::from_bytes_mod_order(raw);
    *o = s.reduce().to_unpacked_u32();
}

/// [`expand_raw256_modm`] from [modm-donna-32bit.c:261](https://github.com/floodyberry/ed25519-donna/blob/8757bd4cd209cb032853ece0ce413f122eef212c/modm-donna-32bit.h#L261)
#[no_mangle]
pub unsafe extern "C" fn expand_raw256_modm(o: *mut Bignum256Modm, i: *const [u8; 32usize]) {
    let s = Scalar::from_bytes_mod_order(*i);
    *o = s.to_unpacked_u32();
}

#[no_mangle]
pub unsafe extern "C" fn contract256_modm(o: *mut [u8; 32], i: *const Bignum256Modm) {
    let s = Scalar::from_unpacked_u32(*i).reduce();
    *o = s.to_bytes();
}

#[cfg(test)]
mod test {
    // TODO(@ryankurte): write tests...
}
