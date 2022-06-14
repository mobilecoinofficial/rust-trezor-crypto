//! Generic edwards curve operations, ABI compatible with [`ed25519-donna-impl-base.h`](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519-donna-impl-base.h)
//!
//!

use core::slice;
use std::f32::MIN;

use cty::{c_int, c_uchar, size_t};

use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_TABLE, MONTGOMERY_A, SQRT_M1, MONTGOMERY_A_NEG, MINUS_ONE},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    internals::FieldElement2625,
};
use sha3::{Keccak512};

use crate::modm::{Bignum25519, Bignum256Modm};

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

/// TODO
#[no_mangle]
pub unsafe extern "C" fn ge25519_set_neutral(r: *mut Ge25519) {
    // TODO(@ryankurte): is this a _complete_ definition?
    (*r).y[0] = 1;
    (*r).z[0] = 1;
}

/// Point addition, `r = a + b`
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

/// Point doubling, `r = 2 * p`
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

/// Multiply by cofactor, `r = [8]P`
#[no_mangle]
pub unsafe extern "C" fn ge25519_mul8(r: *mut Ge25519, p: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p) {
        Ok(v) => v,
        Err(_) => return,
    };

    let r1 = p1.mul_by_cofactor();

    *r = Ge25519::from(&r1);
}

/// Point/Scalar multiplication, `r = [s1]p1 + [s2]base`
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

/// Point/Scalar multiplication, `r = [s1]p1 + [s2]p2`
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

/// Convert point `p1` ([`Ge25519`]) to compressed form `r` (`[u8; 32]`)
#[no_mangle]
pub unsafe extern "C" fn ge25519_pack(r: *mut [u8; 32], p1: *const Ge25519) {
    let p1 = match EdwardsPoint::try_from(&*p1) {
        Ok(v) => v,
        Err(_) => return,
    };

    let c1 = p1.compress();

    (*r).copy_from_slice(c1.as_bytes());
}

/// Unpack compressed curve form `c` (`[u8; 32]`) to `r` ([`Ge25519`])
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

///Point copy, `r = p`
#[no_mangle]
pub unsafe extern "C" fn ge25519_copy(r: *mut Ge25519, p: *const Ge25519) {
    (*r).x = (*p).x;
    (*r).y = (*p).y;
    (*r).z = (*p).z;
    (*r).t = (*p).t;
}

/// Point from hash (`[u8; 32]`) in variable time (monero impl) INCOMPLETE
/// 
/// Elligator2 based point derivation for Monero
// TODO: incomplete / broken
#[no_mangle]
pub unsafe extern "C" fn ge25519_fromfe_frombytes_vartime(
    r: *mut Ge25519,
    p: *const [u8; 32],
) {

    // Zmod(2^255-19) from byte array to bignum25519 ([u32; 10]) expansion with modular reduction
    let mut u = FieldElement2625::from_bytes(&*p);

    // TODO: Check input is canonical / expand & reduce?
    // curve25519_expand_reduce(u, s);
    //let mut u = expand_reduce(&*p);

    // TODO: non-canonical inputs give invalid results..? 
    if *p != u.to_bytes() {
        println!("Non-canonical input");
        u = FieldElement2625::from_bytes(&u.to_bytes());
        //return;
    }

    // w = (2 * u * u + 1) % q
    let w = &u.square2() + &FieldElement2625::one();

    // xp = (w *  w - 2 * A * A * u * u) % q
    let xp = &w.square() - &(&MONTGOMERY_A.square2() * &u.square());

    // rx = ed25519.expmod(w * ed25519.inv(xp),(q+3)/8,q) 
    let mut rx = (&w * &xp.invert()).pow_p58();


    // x = rx * rx * (w * w - 2 * A * A * u * u) % q
    let mut x = &rx.square() * &xp;

    // y = (2 * u * u  + 1 - x) % q #w - x, if y is zero, then x = w
    let mut y = &w - &x;

    let mut z = FieldElement2625::zero();


    let two = &FieldElement2625::one() + &FieldElement2625::one();
    let minus_two = &FieldElement2625::zero() - &two;


    let fffb1 = &MINUS_ONE * &FieldElement2625::sqrt_ratio_i(
        &(&(&minus_two * &MONTGOMERY_A) * &(&MONTGOMERY_A + &two)),
        &FieldElement2625::one(),
    ).1;

    let fffb2 = &MINUS_ONE * &FieldElement2625::sqrt_ratio_i(
        &(&(&two * &MONTGOMERY_A) * &(&MONTGOMERY_A + &two)),
        &FieldElement2625::one(),
    ).1;

    let fffb3 = &FieldElement2625::sqrt_ratio_i(
        &(&(&MINUS_ONE * &(&SQRT_M1 * &MONTGOMERY_A)) * &(&MONTGOMERY_A + &two)),
        &FieldElement2625::one(),
    ).1;

    let fffb4 = &MINUS_ONE * &FieldElement2625::sqrt_ratio_i(
        &(&(&SQRT_M1 * &MONTGOMERY_A) * &(&MONTGOMERY_A + &two)),
        &FieldElement2625::one(),
    ).1;


    let mut negative = false;

    if y != FieldElement2625::zero() {
        // Check if we have negative square root
        y = &w + &x;
        if y != FieldElement2625::zero() {
            negative = true;

        } else {
            // rx = rx * -1 * ed25519.sqroot(-2 * A * (A + 2) ) % q
            rx = &rx * &fffb1;

            negative = false;
        }

        println!("Non zero!");
        
    } else {
        // y was 0
        // rx = (rx * -1 * ed25519.sqroot(2 * A * (A + 2) ) ) % q 
        rx = &rx * &fffb2;

        println!("Zero~!");
    }

    let mut sign = 0;

    if !negative {
        // rx = (rx * u) % q
        rx = &rx * &u;
        // z = (-2 * A * u * u)  % q
        z = &MONTGOMERY_A_NEG * &u.square2();

        sign = 0;

        println!("Not negative!");

    } else {
        // z = -1 * A
        z = MONTGOMERY_A_NEG;
        // x = x * sqrtm1 % q 
        x = &x * &SQRT_M1;
        // y = (w - x) % q 
        y = &w - &x;

        if y != FieldElement2625::zero() {
            // rx = rx * ed25519.sqroot( -1 * sqrtm1 * A * (A + 2)) % q
            rx = &rx * &fffb3;
        } else {
            // rx = rx * -1 * ed25519.sqroot( sqrtm1 * A * (A + 2)) % q
            rx = &rx * &fffb4;
        }
            
        sign = 1;

        println!("Negative!");
    }
    
    // if ( (rx % 2) != sign ):
    // TODO: is this direction correct?
    if rx.is_negative().unwrap_u8() != sign {
        // rx =  - (rx) % q 
        rx.negate();

        println!("Negated!");
    }

    // rz = (z + w) % q
    let rz = &z + &w;
    // ry = (z - w) % q
    let ry = &z - &w;
    // rx = rx * rz % q
    let rx = &rx * &rz;

    let rt = &rx * &ry;

    let p = EdwardsPoint::try_from_raw_u32(
        *rx.as_ref(),
        *ry.as_ref(),
        *rz.as_ref(),
        // TODO: i -think- this torsion part is incorrect?
        *rt.as_ref(),
    ).unwrap();

    // TODO: compress, work out whether mul8 is included in test vectors?
    //let p = p.mul_by_cofactor();
    
    *r = Ge25519::from(&p);
}


/// Point scalar multiplication, `r = [s1]p1`, constant time
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

/// Compute point from scalar via niels_basepoint, `r = s * B`
#[no_mangle]
pub unsafe extern "C" fn ge25519_scalarmult_base_wrapper(r: *mut Ge25519, s: *const Bignum256Modm) {
    let s1 = Scalar::from_unpacked_u32(*s);

    let r1 = &ED25519_BASEPOINT_TABLE * &s1;

    *r = Ge25519::from(&r1);
}

/// Check if point `p1` is on a curve
// TODO: better description..?
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

/// Point comparison, returns 1 if points are equal, 0 otherwise
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
/// 
/// See [ed25519-donna.h:L67](https://github.com/floodyberry/ed25519-donna/blob/master/ed25519-donna.h#L67)
/// TODO: why is this called `_verify` instead of something wild like, `_compare`..?
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


// TODO: expand reduce helper, not sure what this is -meant- to be doing yet...
fn expand_reduce(r: &[u8; 32]) -> FieldElement2625 {

    let mut f = FieldElement2625::from_bytes(r);


    let mut ec = f.to_bytes();

    FieldElement2625::from_bytes(&ec)
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
    fn encode_decode() {
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

    #[test]
    #[ignore = "incomplete implementation"]
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
            "83efb774657700e37291f4b8dd10c839d1c739fd135c07a2fd7382334dafdd6a","2789ecbaf36e4fcb41c6157228001538b40ca379464b718d830c58caae7ea4ca",
        ), (
            "5c380f98794ab7a9be7c2d3259b92772125ce93527be6a76210631fdd8001498", "31a1feb4986d42e2137ae061ea031838d24fa523234954cf8860bcd42421ae94",
        ), (
            "036291b42946c45b627a83701184f7d41647779cf5475d39e029443be33acacc",
            "ccc370b8bd978dc2d096eede50271c16922994b97959a9bd0171aaf5d4eb981f",
        ),(
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
            unsafe { ge25519_fromfe_frombytes_vartime(&mut res, &h) };

            // Pack result point
            let mut compressed_res = [0u8; 32];
            unsafe { ge25519_pack(&mut compressed_res, &res) };

            println!("result: {}", hex::encode(compressed_res));

            // Check results match
            //assert_eq!(compressed_res, p);
            if compressed_res != p {
                failures += 1;
            }
        }

        assert!(failures == 0, "{}/{} test cases failed", failures, tests.len());
    }

    #[test]
    #[ignore = "incomplete implementation"]
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

            let r = expand_reduce(&i);

            let result_hex = hex::encode(r.to_bytes());

            println!("result: {}\r\n", result_hex);

            if &result_hex != expected {
                errors += 2;
            }
        }

        assert!(errors == 0, "{}/{} tests failed", errors, tests.len());
    }

}
