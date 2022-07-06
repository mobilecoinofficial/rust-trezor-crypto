//! Generic edwards curve operations, ABI compatible with [`ed25519-donna-impl-base.h`](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519-donna-impl-base.h)
//!
//!

use core::slice;

use byteorder::{ByteOrder, LittleEndian};
use cty::{c_int, c_uchar, size_t};

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    field::FieldElement,
    traits::Identity,
};

use crate::{
    modm::{Bignum25519, Bignum256Modm},
    consts::{MONTGOMERY_A, MONTGOMERY_A_NEG, SQRT_M1, MINUS_ONE, FE_FFFB1, FE_FFFB2, FE_FFFB3, FE_FFFB4},
};

/// Edwards point object compatible with `ge25519_t` from [ed25519-donna.h:81](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519-donna.h#L81)
/// 
/// TODO: test against bindgen version to ensure struct alignment?
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
        let (x, y, z, t) = unsafe { p.to_raw_u32() };
        Ge25519 { x, y, z, t }
    }
}

impl Default for Ge25519 {
    fn default() -> Self {
        Self::from(&EdwardsPoint::default())
    }
}

/// TODO
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_set_neutral(r: *mut Ge25519) {
    (*r) = Ge25519::from(&EdwardsPoint::identity());
}

/// Point addition, `r = a + b` if signbit == 0, `r = a - b` if signbit == 1
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_add(
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

    let r1 = match signbit == 0 {
        true => a1 + b1,
        false => a1 - b1,
    };

    *r = Ge25519::from(&r1);
}

/// Point doubling, `r = 2 * p`
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_double(r: *mut Ge25519, p: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p) {
        Ok(v) => v,
        Err(_) => return,
    };

    let r1 = &p1 + &p1;

    *r = Ge25519::from(&r1);
}

/// Multiply by cofactor, `r = [8]P`
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_mul8(r: *mut Ge25519, p: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p) {
        Ok(v) => v,
        Err(_) => return,
    };

    let r1 = p1.mul_by_cofactor();

    *r = Ge25519::from(&r1);
}

/// Point/Scalar multiplication, `r = [s1]p1 + [s2]base`
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_double_scalarmult_vartime(
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

    let r1 = s1 * p1 + &ED25519_BASEPOINT_POINT * &s2;

    *r = Ge25519::from(&r1);
}

/// Point/Scalar multiplication, `r = [s1]p1 + [s2]p2`
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_double_scalarmult_vartime2(
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

/// Convert point `p1` ([`Ge25519`]) to compressed form `r` (`[u8; 32]`)
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_pack(r: *mut [u8; 32], p1: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return,
    };

    let c1 = p1.compress();

    (*r).copy_from_slice(c1.as_bytes());
}

/// Unpack compressed curve form `c` (`[u8; 32]`) to `r` ([`Ge25519`])
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_unpack_vartime(r: *mut Ge25519, c: *const [u8; 32]) -> c_int {
    let c1 = CompressedEdwardsY(*c);

    let r1 = match c1.decompress() {
        Some(v) => v,
        None => return 0,
    };

    (*r) = Ge25519::from(&r1);

    return 1;
}

///Point copy, `r = p`
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_copy(r: *mut Ge25519, p: *const Ge25519) {
    (*r).x = (*p).x;
    (*r).y = (*p).y;
    (*r).z = (*p).z;
    (*r).t = (*p).t;
}

const REDUCE_MASK_25: u32 = (1 << 25) - 1;
const REDUCE_MASK_26: u32 = (1 << 26) - 1;

/// Re-implementation of curve25519_expand_reduce from trezor's donna port
unsafe fn dalek_curve25519_expand_reduce(hash: &[u8; 32]) -> FieldElement {
    let mut x = [0u32; 8];

    // Load in words
    for i in 0..x.len() {
        x[i] = LittleEndian::read_u32(&hash[i*4..]);
    }

    // Perform expansion / reduction
    let mut out = [0u32; 10];

    out[0] = (                       x[0] as u64       ) as u32 & REDUCE_MASK_26;
	out[1] = ((((x[1] as u64) << 32) | x[0] as u64) >> 26) as u32 & REDUCE_MASK_25;
	out[2] = ((((x[2] as u64) << 32) | x[1] as u64) >> 19) as u32 & REDUCE_MASK_26;
	out[3] = ((((x[3] as u64) << 32) | x[2] as u64) >> 13) as u32 & REDUCE_MASK_25;
	out[4] = ((                      x[3] as u64) >>  6) as u32 & REDUCE_MASK_26;
	out[5] = (                       x[4] as u64       ) as u32 & REDUCE_MASK_25;
	out[6] = ((((x[5] as u64) << 32) | x[4] as u64) >> 25) as u32 & REDUCE_MASK_26;
	out[7] = ((((x[6] as u64) << 32) | x[5] as u64) >> 19) as u32 & REDUCE_MASK_25;
	out[8] = ((((x[7] as u64) << 32) | x[6] as u64) >> 12) as u32 & REDUCE_MASK_26;
	out[9] = ((                      x[7] as u64) >>  6) as u32; // & reduce_mask_25; /* ignore the top bit */
	out[0] += 19 * (out[9] >> 25);
	out[9] &= REDUCE_MASK_25;

    FieldElement::from_raw_u32(out)
}

/// Point from hash (`[u8; 32]`) in variable time (monero impl) INCOMPLETE
///
// TODO: incomplete / broken
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_fromfe_frombytes_vartime(
    r: *mut Ge25519,
    p: *const [u8; 32],
) {

    // Zmod(2^255-19) from byte array to bignum25519 ([u32; 10]) expansion with modular reduction
    let mut u = dalek_curve25519_expand_reduce(&*p);
    if *p != u.to_bytes() {
        // TODO: canonicalisation doesn't -seem- to change anything
        u = FieldElement::from_bytes(&u.to_bytes());
    }

    // `ge25519_fromfe_frombytes_vartim` re-implementation based on monero source
    let p = ge25519_fromfe_frombytes_vartime_monero(&u);
    
    // Convert to C ABI compatible point
    *r = Ge25519::from(&p);
}

// Re-implementation from monero source
fn ge25519_fromfe_frombytes_vartime_monero(u: &FieldElement) -> EdwardsPoint {
    // w = (2 * u^2 + 1) % q
    let w = &u.square2() + &FieldElement::one();

    // xp = (w^2 - 2 * A^2 * u^2) % q
    let xp = &w.square() - &(&MONTGOMERY_A.square2() * &u.square());

    // Re-implemented from monero crypto-ops.c
    let mut rx = fe_divpowm1(&w, &xp);

    // x = rx * rx * (w * w - 2 * A * A * u * u) % q
    let mut x = &rx.square() * &xp;

    // y = (2 * u * u  + 1 - x) % q #w - x, if y is zero, then x = w
    let mut y = &w - &x;

    let z: FieldElement;

    let mut negative = false;

    if y != FieldElement::zero() {
        // Check if we have negative square root
        y = &w + &x;
        if y != FieldElement::zero() {
            negative = true;

        } else {
            // rx = rx * -1 * ed25519.sqroot(-2 * A * (A + 2) ) % q
            rx = &rx * &FE_FFFB1;

            negative = false;
        }

    } else {
        // y was 0
        // rx = (rx * -1 * ed25519.sqroot(2 * A * (A + 2) ) ) % q 
        rx = &rx * &FE_FFFB2;
    }

    let sign;

    if !negative {
        // rx = (rx * u) % q
        rx = &rx * &u;
        // z = (-2 * A * u * u)  % q
        z = &MONTGOMERY_A_NEG * &u.square2();

        sign = 0;

    } else {
        
        z = MONTGOMERY_A_NEG;                   // z = -1 * A
        x = &x * &SQRT_M1;                      // x = x * sqrtm1 % q 
        y = &w - &x;                            // y = (w - x) % q 

        if y != FieldElement::zero() {
            // rx = rx * ed25519.sqroot( -1 * sqrtm1 * A * (A + 2)) % q
            rx = &(&rx * &MINUS_ONE) * &FE_FFFB3;
        } else {
            // rx = rx * -1 * ed25519.sqroot( sqrtm1 * A * (A + 2)) % q
            rx = &(&rx * &MINUS_ONE) * &FE_FFFB4;
        }
            
        sign = 1;
    }

    // if ( (rx % 2) != sign ):
    // TODO: is this direction correct?
    if rx.is_negative().unwrap_u8() != sign {
        // rx =  - (rx) % q 
        rx.negate();
    }

    // rz = (z + w) % q
    let rz = &z + &w;
    // ry = (z - w) % q
    let ry = &z - &w;
    // rx = rx * rz % q
    let rx = &rx * &rz;

    let rt = FieldElement::one();

    let p = unsafe { EdwardsPoint::try_from_raw_u32(
        rx.to_raw_u32(),
        ry.to_raw_u32(),
        rz.to_raw_u32(),
        rt.to_raw_u32(),
    ).unwrap() };

    p
}

/// `fe_divpowm1` from monero's crypto-ops.c
fn fe_divpowm1(u: &FieldElement, v: &FieldElement) -> FieldElement {

    let v3 = &v.square() * &v;
    let uv7 = &(&v3.square() * &v) * u;      // uv7 = u * v^7

    // fe_pow22523(uv7, uv7);

    let t0 = uv7.square();              // fe_sq(t0, uv7);
    let t1 = t0.square().square();      // fe_sq(t1, t0); fe_sq(t1, t1);
    let t1 = &uv7 * &t1;                // fe_mul(t1, uv7, t1);
    let t0 = &t0 * &t1;                 // fe_mul(t0, t0, t1);
    let t0 = t0.square();               // fe_sq(t0, t0);
    let t0 = &t1 * &t0;                 // fe_mul(t0, t1, t0);
    let mut t1 = t0.square();           // fe_sq(t1, t0);
    for _i in 0..4 {
        t1 = t1.square();               // fe_sq(t1, t1);
    }
    let t0 = &t1 * &t0;                 // fe_mul(t0, t1, t0);
    let mut t1 = t0.square();           // fe_sq(t1, t0);
    for _i in 0..9 {
        t1 = t1.square();               // fe_sq(t1, t1);
    }
    let t1 = &t1 * &t0;                 // fe_mul(t1, t1, t0);
    let mut t2 = t1.square();           // fe_sq(t2, t1);
    for _i in 0..19 {
        t2 = t2.square();               // fe_sq(t2, t2);
    }
    let mut t1 = &t2 * &t1;             // fe_mul(t1, t2, t1);
    for _i in 0..10 {
        t1 = t1.square();               // fe_sq(t1, t1);
    }
    let t0 = &t1 * &t0;                 // fe_mul(t0, t1, t0);
    let mut t1 = t0.square();           // fe_sq(t1, t0);
    for _i in 0..49 {
        t1 = t1.square();               // fe_sq(t1, t1);
    }
    let t1 = &t1 * &t0;                 // fe_mul(t1, t1, t0);
    let mut t2 = t1.square();           // fe_sq(t2, t1);
    for _i in 0..99 {
        t2 = t2.square();               // fe_sq(t2, t2);
    }
    let mut t1 = &t2 * &t1;             // fe_mul(t1, t2, t1);
    for _i in 0..50 {
        t1 = t1.square();               // fe_sq(t1, t1);
    }
    let t0 = &t1 * &t0;                 // fe_mul(t0, t1, t0);
    let t0 = t0.square().square();      // fe_sq(t0, t0); fe_sq(t0, t0);
    let t0 = &t0 * &uv7;                // fe_mul(t0, t0, uv7);

    /* End fe_pow22523.c */
    /* t0 = (uv^7)^((q-5)/8) */
    let t0 = &t0 * &v3;                 // fe_mul(t0, t0, v3);
    let r = &t0 * &u;                   // fe_mul(r, t0, u);

    r
}

/// Point scalar multiplication, `r = [s1]p1`, constant time
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_scalarmult(
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

/// Compute point from scalar via niels_basepoint, `r = s * B`
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_scalarmult_base_wrapper(r: *mut Ge25519, s: *const Bignum256Modm) {
    let s1 = Scalar::from_unpacked_u32(*s);

    let r1 = &ED25519_BASEPOINT_POINT * &s1;

    *r = Ge25519::from(&r1);
}

/// Check if point `p1` is on a curve
// TODO: better description..?
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_check(p1: *const Ge25519) -> c_int {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    // For a valid point compress and decompress should result in the same point
    // TODO: i think we're conflating a point's _validity_ on the curve (see dalek's ValidityCheck) vs. whether a point is in reduced (ie. modulo'd) form..?
    let c = p1.compress();
    match c.decompress() {
        Some(p2) if &p1 == &p2 => 1,
        _ => 0,
    }
}

/// Point comparison, returns 1 if points are equal, 0 otherwise
#[no_mangle]
pub unsafe extern "C" fn dalek_ge25519_eq(a: *const Ge25519, b: *const Ge25519) -> c_int {
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
/// 
/// See [ed25519-donna.h:L67](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519-donna.h#L67)
/// TODO: why is this called `_verify` instead of something wild like, `_compare`..?
#[no_mangle]
pub unsafe extern "C" fn dalek_ed25519_verify(
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

    use crate::test::decode_bytes;
    
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
        unsafe { s.to_unpacked_u32() }
    }



    /// `test_encoding` from test_apps.monero.crypto.py
    #[test]
    fn encode_decode() {
        let tests = &["2486224797d05cae3cba4be043be2db0df381f3f19cfa113f86ab38e3d8d2bd0"];

        for t in tests {
            let point = decode_bytes(t);

            // Decode packed point
            let mut decoded = Ge25519::default();
            unsafe { dalek_ge25519_unpack_vartime(&mut decoded, &point) };

            // Re-encode packed point
            let mut encoded = [0u8; 32];
            unsafe { dalek_ge25519_pack(&mut encoded, &decoded) };

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
            unsafe { dalek_ge25519_scalarmult_base_wrapper(&mut res, &scalar) };

            println!("Result: {:02x?}", res);

            // Pack result and check
            let mut compressed_res = [0u8; 32];
            unsafe { dalek_ge25519_pack(&mut compressed_res, &res) };
            assert_eq!(compressed_res, exp);

            println!("Compressed: {:02x?}", compressed_res);

            // Unpack exponent and check
            let mut unpacked_exp = Ge25519::default();
            unsafe { dalek_ge25519_unpack_vartime(&mut unpacked_exp, &exp) };

            // Compare unpacked points
            let eq = unsafe { dalek_ge25519_eq(&res, &unpacked_exp) };
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
            unsafe { dalek_ge25519_scalarmult(&mut res, &public, &private) };

            // Pack result point
            let mut compressed_res = [0u8; 32];
            unsafe { dalek_ge25519_pack(&mut compressed_res, &res) };

            assert_eq!(compressed_res, exp);
        }
    }

    #[test]
    fn test_ge25519_fromfe_frombytes_vartime() {
        
        let tests = &[
        // Vectors from trezor-firmware `test_apps.monero.crypto.py`
        #[cfg(nope)]
        (
            "42f6835bf83114a1f5f6076fe79bdfa0bd67c74b88f127d54572d3910dd09201",
            "54863a0464c008acc99cffb179bc6cf34eb1bbdf6c29f7a070a7c6376ae30ab5",
        ),
        // Vectors from monero `tests/crypto/tests.txt`
        // https://github.com/monero-project/monero/blob/release-v0.13/tests/crypto/tests.txt
        (
            "83efb774657700e37291f4b8dd10c839d1c739fd135c07a2fd7382334dafdd6a",
            "2789ecbaf36e4fcb41c6157228001538b40ca379464b718d830c58caae7ea4ca",
        ), (
            "5c380f98794ab7a9be7c2d3259b92772125ce93527be6a76210631fdd8001498",
            "31a1feb4986d42e2137ae061ea031838d24fa523234954cf8860bcd42421ae94",
        ), (
            "036291b42946c45b627a83701184f7d41647779cf5475d39e029443be33acacc",
            "ccc370b8bd978dc2d096eede50271c16922994b97959a9bd0171aaf5d4eb981f",
        ), (
            "fff86285af4a9e8f777fb16723fea046207e0c5949934836acb43a36360ec7eb",
            "98fc4d1c6077c21c2993bcd7abb0af6b4daaa4c2fdea13eb4cd5ad5f7ce0de6f",
        ),(
            "7ed5a8182b8c79f553a101ef17df87dd45870821d53fbb00dd4d5b2a52f0effc",
            "0ea13276d187cffa25955e3c49cf72244bbe8c1d3b72a1f5f0502139970f106e",
        ),(
            "4c60069c56d10bb3edc4dfe98d73f39456d846d4139fd3adaffd198e5009bdda",
            "2097cd5377111642d9d7b96980a316e5227a4ed0f989232d09f1268048282a6e",
        ),(
            "176b82d6d68b0b906da1e992f5010f23b25d36112d8987d52e514ceeb8010e3d",
            "3c8abee0fefa206c3631bf8c3208593afda93fa8a1ef75355ae05b3fe41c2749",
        ),(
            "72aa89d776c6bc7bd09385ac7e8112868f85025fa966bb5df65bbbd5c63a13c6",
            "dfb5f593f9e78041c63f784e6db5f902d98ecfa3bd3668f8baa56062cc9e9e35",
        ),(
            "abfb4aef4ed3277ddbcb0bf13fc54faa8e161ce9b58c625d4523fc050e67e991",
            "746f5b282beda0f831a7cb453bc5727cfc70d01227a109fb26a62d06f09ade3e",
        ),(
            "433ea849299a1e5f0ba7a47f2446104f892101945d4179e9048192bbc8f59af6",
            "f647b5caf04c090bf1ed6261154ce7a50449e17fa1d547fe6c21b03b7eab73c5",
        )];

        let mut i = 0;
        let mut failures = 0;

        for (_h, _p) in tests {
            let h = decode_bytes(_h);
            let p = decode_bytes::<32>(_p);

            println!("\r\niteration {}", i);
            i += 1;

            println!("hash: {}", _h);
            println!("expected: {}", _p);

            // Compute point from hash
            let mut res = Ge25519::default();
            unsafe { dalek_ge25519_fromfe_frombytes_vartime(&mut res, &h) };

            // Pack result point
            let mut compressed_res = [0u8; 32];
            unsafe { dalek_ge25519_pack(&mut compressed_res, &res) };

            println!("result: {}", hex::encode(compressed_res));

            // Check results match
            //assert_eq!(compressed_res, p);
            if compressed_res != p {
                println!("**** FAILED ****");
                failures += 1;
            } else {
                println!("**** OK ****");
            }
        }

        assert!(failures == 0, "{}/{} test cases failed", failures, tests.len());
    }

    #[test]
    fn test_expand_reduce() {
        let tests = &[(
            "95587a5ef6900fa8e32d6a41bd8090b1e33e694284323d1d1f02d69865f2bc15",
            "95587a5ef6900fa8e32d6a41bd8090b1e33e694284323d1d1f02d69865f2bc15"
        ), (
            "95587a5ef6900fa8e32d6a41bd8090b1e33e694284323d1d1f02d69865f2bcff",
            "a8587a5ef6900fa8e32d6a41bd8090b1e33e694284323d1d1f02d69865f2bc7f",
        ), (
            "95587a5ef6900fa8e32d6affbd8090b1e33e694284323fffff02d69865f2bcff",
            "a8587a5ef6900fa8e32d6affbd8090b1e33e694284323fffff02d69865f2bc7f",
        )];

        let mut errors = 0;

        for (_i, expected) in tests {

            println!("input:  {}", _i);
            println!("expect: {}", expected);

            let i = decode_bytes::<32>(_i);

            let r = unsafe { dalek_curve25519_expand_reduce(&i) };

            let result_hex = hex::encode(r.to_bytes());

            println!("result: {}\r\n", result_hex);

            if &result_hex != expected {
                errors += 1;
            }
        }

        assert!(errors == 0, "{}/{} tests failed", errors, tests.len());
    }
}
