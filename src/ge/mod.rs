//!
//!
//! Via ed25519-donna-impl-base.(c|h)
//!

use core::slice;

use cty::{c_int, c_uchar, size_t};

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_TABLE, MONTGOMERY_A, SQRT_M1, MONTGOMERY_A_NEG},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    internals::FieldElement2625,
};
use sha3::{Keccak512};

use crate::modm::{Bignum25519, Bignum256Modm};

#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub struct Ge25519 {
    pub x: Bignum25519,
    pub y: Bignum25519,
    pub z: Bignum25519,
    pub t: Bignum25519,
}

//  requires mods to ed25519-dalek to construct / destruct
// _technically_ the Ge25519 object has the same repr, but, can't really depend on this so we're going to need to regularly copy
impl TryFrom<&Ge25519> for EdwardsPoint {
    type Error = ();

    fn try_from(v: &Ge25519) -> Result<Self, Self::Error> {
        unsafe { EdwardsPoint::try_from_raw_u32(v.x, v.y, v.z, v.t) }
    }
}

impl From<&EdwardsPoint> for Ge25519 {
    fn from(p: &EdwardsPoint) -> Self {
        let (x, y, z, t) = unsafe { p.as_raw_u32() };
        Ge25519 { x, y, z, t }
    }
}

impl Default for Ge25519 {
    fn default() -> Self {
        Self::from(&EdwardsPoint::default())
    }
}

impl Ge25519 {
    /// Write an `EdwardsPoint` to a `Ge25519`
    pub(crate) fn update(&mut self, p: &EdwardsPoint) {
        let (x, y, z, t) = unsafe { p.as_raw_u32() };

        self.x.copy_from_slice(&x);
        self.y.copy_from_slice(&y);
        self.z.copy_from_slice(&z);
        self.t.copy_from_slice(&t);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_set_neutral(r: *mut Ge25519) {
    // TODO(@ryankurte): is this a _complete_ definition?
    (*r).y[0] = 1;
    (*r).z[0] = 1;
}

//ge25519_pniels P_ni = {0};
//ge25519_p1p1 P_11 = {0};
//ge25519_full_to_pniels(&P_ni, q);
//ge25519_pnielsadd_p1p1(&P_11, p, &P_ni, signbit);
//ge25519_p1p1_to_full(r, &P_11);
#[no_mangle]
pub unsafe extern "C" fn ge25519_add(
    r: *mut Ge25519,
    a: *const Ge25519,
    b: *const Ge25519,
    signbit: c_uchar,
) {
    let a1 = match EdwardsPoint::try_from(&*a) {
        Ok(v) => v,
        Err(_) => return,
    };

    let b1 = match EdwardsPoint::try_from(&*b) {
        Ok(v) => v,
        Err(_) => return,
    };

    // TODO(@ryankurte): work out what the sign bit is -actually- doing?
    let r1 = match signbit != 0 {
        true => a1 + b1,
        false => a1 - b1,
    };

    (*r).update(&r1)
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

    // TODO(@ryankurte): is doubling an edwards point equivalent to scalar multiplication..?
    // why is `.double()` internal only?
    let r1 = Scalar::from(2u8) * &p1;

    *r = Ge25519::from(&r1);
}

/// r = [8]P
//ge25519_double_partial(r, t);
//ge25519_double_partial(r, r);
//ge25519_double(r, r);
#[no_mangle]
pub unsafe extern "C" fn ge25519_mul8(r: *mut Ge25519, p: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p) {
        Ok(v) => v,
        Err(_) => return,
    };

    let r1 = p1.mul_by_cofactor();

    *r = Ge25519::from(&r1);
}

/// r = [s1]p1 + [s2]base
#[no_mangle]
pub unsafe extern "C" fn ge25519_double_scalarmult_vartime(
    r: *mut Ge25519,
    p1: *const Ge25519,
    s1: *const Bignum256Modm,
    s2: *const Bignum256Modm,
) {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return,
    };

    let (s1, s2) = (
        Scalar::from_unpacked_u32(*s1),
        Scalar::from_unpacked_u32(*s2),
    );

    let r1 = s1 * p1 + &ED25519_BASEPOINT_TABLE * &s2;

    *r = Ge25519::from(&r1);
}

/// r = [s1]p1 + [s2]p2
#[no_mangle]
pub unsafe extern "C" fn ge25519_double_scalarmult_vartime2(
    r: *mut Ge25519,
    p1: *const Ge25519,
    s1: *const Bignum256Modm,
    p2: *const Ge25519,
    s2: *const Bignum256Modm,
) {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return,
    };
    let p2 = match EdwardsPoint::try_from(&*p2) {
        Ok(v) => v,
        Err(_) => return,
    };

    let (s1, s2) = (
        Scalar::from_unpacked_u32(*s1),
        Scalar::from_unpacked_u32(*s2),
    );

    let r1 = s1 * p1 + s2 * p2;

    *r = Ge25519::from(&r1);
}

/// Convert to compressed curve form
#[no_mangle]
pub unsafe extern "C" fn ge25519_pack(r: *mut [u8; 32], p1: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return,
    };

    let c1 = p1.compress();

    (*r).copy_from_slice(c1.as_bytes());
}

/// Unpack from compressed curve form
#[no_mangle]
pub unsafe extern "C" fn ge25519_unpack_vartime(r: *mut Ge25519, c: *const [u8; 32]) -> c_int {
    let c1 = CompressedEdwardsY(*c);

    let r1 = match c1.decompress() {
        Some(v) => v,
        None => return 0,
    };

    (*r) = Ge25519::from(&r1);

    return 1;
}

/// Copy from p to r
#[no_mangle]
pub unsafe extern "C" fn ge25519_copy(r: *mut Ge25519, p: *const Ge25519) {
    (*r).x = (*p).x;
    (*r).y = (*p).y;
    (*r).z = (*p).z;
    (*r).t = (*p).t;
}

// Point from sha3 keccak hash (field element?) in variable time
// TODO: is this what the xmr folks are -trying- to do..?
#[no_mangle]
pub unsafe extern "C" fn ge25519_from_hash_sha3k_vartime(
    r: *mut Ge25519,
    data: *mut u8,
    len: usize,
) {
    let buff = slice::from_raw_parts(data, len);

    let p = EdwardsPoint::hash_from_bytes::<Keccak512>(buff);

    *r = Ge25519::from(&p);
}

// Point from [hash] (field element?) in variable time
// TODO(@ryankurte): what is this -actually- doing / is this duplicating some common cryptographic operation?
#[no_mangle]
pub unsafe extern "C" fn ge25519_fromfe_frombytes_vartime(
    r: *mut Ge25519,
    p: *const [u8; 32],
) {

    // Zmod(2^255-19) from byte array to bignum25519 ([u32; 10]) expansion with modular reduction
    let u = FieldElement2625::from_bytes(&*p);

    // Check input is canonical
    // TODO: what else do we need here..?
    // curve25519_expand_reduce(u, s);
    if *p != u.to_bytes() {
        return;
    }

    // v = 2 * u^2
    // curve25519_square(v, u);
    // curve25519_add_reduce(v, v, v);
    let v = u.square2();
    
    // w = v + 1 = (2 * u^2) + 1
    // curve25519_set(w, 1);
	// curve25519_add_reduce(w, v, w);
    let w = &v + &FieldElement2625::one();

    // x = w ^ 2
    let x = w.square();

    // y = (-1 * A^2) * v = -2 * A^2 * u^2
    // curve25519_mul(y, fe_ma2, v);
    let y = FieldElement2625::minus_one() * MONTGOMERY_A.square() * v;

    // x = w^2 - 2 * A^2 * u^2
    // curve25519_add_reduce(x, x, y);
    let x = &x + &y;

    // TODO: Where does M come from?1!
    // curve25519_divpowm1(r->x, w, x); /* (w / x)^(m + 1) */ ?!
    // alt: x = uv^3(uv^7)^((q-5)/8) ?

    let (r_x_is_neg, mut r_x) = FieldElement2625::sqrt_ratio_i(
        &(&w * &x.invert()),
        &FieldElement2625::one(),
    );

    // curve25519_square(y, r->x);
    let y = r_x.square();
    
	// curve25519_mul(x, y, x);
    let x = &y * &x;
    
	// curve25519_sub_reduce(y, w, x);
    let mut y = &w - &x;
    
	// curve25519_copy(z, fe_ma);
    let mut z = MONTGOMERY_A;

    let mut negative = false;
    let mut sign = 0;

    let two = &FieldElement2625::one() + &FieldElement2625::one();

    


    if &y != &FieldElement2625::zero() {
        y = &w + &x;

        if &y != &FieldElement2625::zero() {
            negative = true;
        } else {

            let (_, temp1) = FieldElement2625::sqrt_ratio_i(
                &two.negate() * &MONTGOMERY_A * (&MONTGOMERY_A + &two),
                &FieldElement2625::one(),
            );

            r_x = &(&r_x * &FieldElement2625::minus_one()) * &temp1;
            negative = false;
        }

    } else {

        let (_, temp2) = FieldElement2625::sqrt_ratio_i(
            &two * &MONTGOMERY_A * (&MONTGOMERY_A + &two),
            &FieldElement2625::one(),
        );

        r_x = &(&r_x * &FieldElement2625::minus_one()) * &temp2;
    }

    if !negative {
        r_x = &r_x * &u;
        z = &MONTGOMERY_A_NEG * &u.square2();
        sign = 0;

    } else {
        z = MONTGOMERY_A_NEG;
        x = &x * &SQRT_M1;
        y = &w - &x;

        if &y != &FieldElement2625::zero() {
            let (_, temp3) = FieldElement2625::sqrt_ratio_i(
                FieldElement2625::minus_one() * &SQRT_M1 * &MONTGOMERY_A * (&MONTGOMERY_A + &two),
                &FieldElement2625::one(),
            );

            r_x = &(&r_x * &FieldElement2625::one()) * &temp3;
            
        } else {
            let (_, temp4) = FieldElement2625::sqrt_ratio_i(
                &SQRT_M1 * &MONTGOMERY_A * (&MONTGOMERY_A + &two),
                &FieldElement2625::one(),
            );

            r_x = &(&r_x * &FieldElement2625::minus_one()) * &temp4;
        }

        sign = 1;
    }

    //*r = Ge25519{x, y, z, }

    //(*r) = Ge25519::from(&r1);
}

// computes [s1]p1, constant time
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult(
    r: *mut Ge25519,
    p1: *const Ge25519,
    s1: *const Bignum256Modm,
) {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return,
    };

    let s1 = Scalar::from_unpacked_u32(*s1);

    let r1 = p1 * s1;

    *r = Ge25519::from(&r1);
}

/// computes [s] niels_basepoint
///
/// (wraps [`ge25519_scalarmult_base_niels`] while passing basepoint table)
// 	ge25519_scalarmult_base_niels(r, ge25519_niels_base_multiples, s);
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult_base_wrapper(r: *mut Ge25519, s: *const Bignum256Modm) {
    let s1 = Scalar::from_unpacked_u32(*s);

    let r1 = &ED25519_BASEPOINT_TABLE * &s1;

    *r = Ge25519::from(&r1);
}

/// Check if R is on a curve
#[no_mangle]
pub unsafe extern "C" fn ge25519_check(p1: *const Ge25519) -> c_int {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // For a valid point compress and decompress should result
    // in the same point
    // TODO(@ryankurte): is there a better way to do this?
    let c = p1.compress();
    match c.decompress() {
        Some(p2) if &p1 == &p2 => 1,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ge25519_eq(a: *const Ge25519, b: *const Ge25519) -> c_int {
    let (p1, p2) = match (EdwardsPoint::try_from(&*a), EdwardsPoint::try_from(&*b)) {
        (Ok(p1), Ok(p2)) => (p1, p2),
        _ => return 0,
    };

    match &p1 == &p2 {
        true => 1,
        false => 0,
    }
}

/// Timing safe memory compare
#[no_mangle]
pub unsafe extern "C" fn ed25519_verify(
    x: *const c_uchar,
    y: *const c_uchar,
    len: size_t,
) -> c_int {
    let (x, y) = (
        slice::from_raw_parts(x, len as usize),
        slice::from_raw_parts(y, len as usize),
    );

    let mut diff = 0;

    for i in 0..len {
        diff |= x[i] ^ y[i];
    }

    match diff {
        0 => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod test {
    use curve25519_dalek::edwards::EdwardsBasepointTable;

    use super::*;

    fn decode_point(s: &str) -> Ge25519 {
        let mut value = [0u8; 32];

        hex::decode_to_slice(s, &mut value).unwrap();

        let p = CompressedEdwardsY(value);

        Ge25519::from(&p.decompress().unwrap())
    }

    fn decode_bignum(s: &str) -> [u32; 9] {
        let mut value = [0u8; 32];

        hex::decode_to_slice(s, &mut value).unwrap();

        let s = Scalar::from_bytes_mod_order(value);
        s.to_unpacked_u32()
    }

    fn decode_bytes<const N: usize>(s: &str) -> [u8; N] {
        let mut value = [0u8; N];

        hex::decode_to_slice(s, &mut value).unwrap();

        value
    }

    /// `test_encoding` from test_apps.monero.crypto.py
    #[test]
    fn encoding() {
        let tests = &["2486224797d05cae3cba4be043be2db0df381f3f19cfa113f86ab38e3d8d2bd0"];

        for t in tests {
            let point = decode_bytes(t);

            // Decode packed point
            let mut decoded = Ge25519::default();
            unsafe { ge25519_unpack_vartime(&mut decoded, &point) };

            // Re-encode packed point
            let mut encoded = [0u8; 32];
            unsafe { ge25519_pack(&mut encoded, &decoded) };

            assert_eq!(point, encoded);
        }
    }

    /// `test_scalarmult_base` from test_apps.monero.crypto.py
    #[test]
    fn scalarmult_base() {
        let tests = &[
            (
                "a0eea49140a3b036da30eacf64bd9d56ce3ef68ba82ef13571ec511edbcf8303",
                "16bb4a3c44e2ced511fc0d4cd86b13b3af21efc99fb0356199fac489f2544c09",
            ),
            (
                "fd290dce39f781aebbdbd24584ed6d48bd300de19d9c3decfda0a6e2c6751d0f",
                "123daf90fc26f13c6529e6b49bfed498995ac383ef19c0db6771143f24ba8dd5",
            ),
        ];

        for (s, e) in tests {
            let scalar = decode_bignum(s);
            let exp = decode_bytes(e);

            println!("Scalar: {:02x?}", scalar);

            println!("Expected: {:02x?}", exp);

            // Perform scalar multiplication
            let mut res = Ge25519::default();
            unsafe { ge25519_scalarmult_base_wrapper(&mut res, &scalar) };

            println!("Result: {:02x?}", res);

            // Pack result and check
            let mut compressed_res = [0u8; 32];
            unsafe { ge25519_pack(&mut compressed_res, &res) };
            assert_eq!(compressed_res, exp);

            println!("Compressed: {:02x?}", compressed_res);

            // Unpack exponent and check
            let mut unpacked_exp = Ge25519::default();
            unsafe { ge25519_unpack_vartime(&mut unpacked_exp, &exp) };

            // Compare unpacked points
            let eq = unsafe { ge25519_eq(&res, &unpacked_exp) };
            assert_eq!(eq, 1);
        }
    }

    /// `test_scalarmult` from test_apps.monero.crypto.py
    #[test]
    fn scalarmult() {
        let tests = &[(
            "3482fb9735ef879fcae5ec7721b5d3646e155c4fb58d6cc11c732c9c9b76620a",
            "2486224797d05cae3cba4be043be2db0df381f3f19cfa113f86ab38e3d8d2bd0",
            "adcd1f5881f46f254900a03c654e71950a88a0236fa0a3a946c9b8daed6ef43d",
        )];

        for (private, public, exp) in tests {
            let private = decode_bignum(private);
            let public = decode_point(public);
            let exp = decode_bytes(exp);

            // Perform multiplication
            let mut res = Ge25519::default();
            unsafe { ge25519_scalarmult(&mut res, &public, &private) };

            // Pack result point
            let mut compressed_res = [0u8; 32];
            unsafe { ge25519_pack(&mut compressed_res, &res) };

            assert_eq!(compressed_res, exp);
        }
    }
}
