
#![allow(unused)]

use curve25519_dalek::{field::FieldElement};

/// The value of minus one, equal to `-&FieldElement::one()`
pub const MINUS_ONE: FieldElement = FieldElement::from_raw_u32([
    67108844, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 33554431
]);

/// Edwards `d` value, equal to `-121665/121666 mod p`.
pub const EDWARDS_D: FieldElement = FieldElement::from_raw_u32([
    56195235, 13857412, 51736253, 6949390, 114729, 24766616, 60832955, 30306712, 48412415, 21499315,
]);

/// Precomputed value of one of the square roots of -1 (mod p)
pub const SQRT_M1: FieldElement = FieldElement::from_raw_u32([
    34513072, 25610706, 9377949, 3500415, 12389472, 33281959, 41962654, 31548777, 326685, 11406482,
]);

/// `MONTGOMERY_A` is equal to 486662, which is a constant of the curve equation
/// for Curve25519 in its Montgomery form. (This is used internally within the
/// Elligator map.)
pub const MONTGOMERY_A: FieldElement = FieldElement::from_raw_u32([486662, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

/// `MONTGOMERY_A_NEG` is equal to -486662. (This is used internally within the
/// Elligator map.)
pub const MONTGOMERY_A_NEG: FieldElement = FieldElement::from_raw_u32([
    66622183, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 33554431, 67108863, 33554431,
]);


/* Constants for monero's `ge25519_fromfe_frombytes_vartime` */
/* A = 2 * (1 - d) / (1 + d) = 486662 */

///  -A^2
pub const FE_MA2: FieldElement = FieldElement::from_raw_u32([
    0x33de3c9, 0x1fff236, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff]);

/// -A
pub const FE_MA: FieldElement = FieldElement::from_raw_u32([
    0x3f892e7, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff]); 
    
/// sqrt(-2 * A * (A + 2))
pub const FE_FFFB1: FieldElement = FieldElement::from_raw_u32([
    0x1e3bdff, 0x025a2b3, 0x18e5bab, 0x0ba36ac, 0x0b9afed, 0x004e61c, 0x31d645f, 0x09d1bea, 0x102529e, 0x0063810]); 

// sqrt(2 * A * (A + 2))
pub const FE_FFFB2: FieldElement = FieldElement::from_raw_u32([
    0x383650d, 0x066df27, 0x10405a4, 0x1cfdd48, 0x2b887f2, 0x1e9a041, 0x1d7241f, 0x0612dc5, 0x35fba5d, 0x0cbe787]);

/// sqrt(-sqrt(-1) * A * (A + 2))
pub const FE_FFFB3: FieldElement = FieldElement::from_raw_u32([
    0x0cfd387, 0x1209e3a, 0x3bad4fc, 0x18ad34d, 0x2ff6c02, 0x0f25d12, 0x15cdfe0, 0x0e208ed, 0x32eb3df, 0x062d7bb]); 

/// sqrt(sqrt(-1) * A * (A + 2))
pub const FE_FFFB4: FieldElement = FieldElement::from_raw_u32([
    0x2b39186, 0x14640ed, 0x14930a7, 0x04509fa, 0x3b91bf0, 0x0f7432e, 0x07a443f, 0x17f24d8, 0x031067d, 0x0690fcc]);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn constant_fe_ma2() {
        let fe_ma2 = &FieldElement::minus_one() * &MONTGOMERY_A.square();
        assert_eq!(&fe_ma2, &FE_MA2);
    }

    #[test]
    fn constant_fe_fffbn() {
        let two = &FieldElement::one() + &FieldElement::one();
        let minus_two = &FieldElement::minus_one() * &two;

        let a_a_2 = &MONTGOMERY_A * &(&MONTGOMERY_A + &two);

        let fffb1 = &MINUS_ONE * &FieldElement::sqrt_ratio_i(
            &(&minus_two * &a_a_2),
            &FieldElement::one(),
        ).1;
        assert_eq!(&fffb1, &FE_FFFB1, "FFFB1");

    
        let fffb2 = &MINUS_ONE * &FieldElement::sqrt_ratio_i(
            &(&two * &a_a_2),
            &FieldElement::one(),
        ).1;
        assert_eq!(&fffb2, &FE_FFFB2, "FFFB2");

        let n_sqrt_n_one = &MINUS_ONE * &SQRT_M1;
    
        // TODO: FFFB3 const _claims_ to be: `sqrt(-sqrt(-1) * A * (A + 2))` but _appears_ to be `-sqrt(-sqrt(-1) * A * (A + 2))` ..?

        let fffb3 = &MINUS_ONE * &FieldElement::sqrt_ratio_i(
            &(&(&MINUS_ONE * &SQRT_M1) * &a_a_2),
            &FieldElement::one(),
        ).1;
        assert_eq!(&fffb3, &FE_FFFB3, "FFFB3");
    
        let fffb4 = FieldElement::sqrt_ratio_i(
            &(&SQRT_M1 * &a_a_2),
            &FieldElement::one(),
        ).1;
        assert_eq!(&fffb4, &FE_FFFB4, "FFFB4");
    }
}
