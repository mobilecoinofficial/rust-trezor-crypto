#![feature(test)]

use crate::UInt;

extern crate test;

use curve25519_dalek::scalar::Scalar;
use dalek_donna::{test::*, ffi::{PublicKey, SecretKey}};

/// Check key derivation functions match
#[test]
fn derive_keys() {
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();

    println!("Using secret key: {:02x?}", sk);

    // Perform dalek key derivation
    let mut dalek_sk = sk.clone();
    let mut dalek_pk: PublicKey = [0u8; 32];
    unsafe { (DALEK.ed25519_publickey)(dalek_sk.as_mut_ptr(), dalek_pk.as_mut_ptr()) };
    assert_eq!(dalek_sk, sk);

    // Perform donna key derivation
    let mut donna_sk = sk.clone();
    let mut donna_pk: PublicKey = [0u8; 32];
    unsafe { (DONNA.ed25519_publickey)(donna_sk.as_mut_ptr(), donna_pk.as_mut_ptr()) };
    assert_eq!(donna_sk, sk);
    
    // Compare results
    assert_eq!(dalek_pk, donna_pk);
}

fn sign_verify(signer: &Driver, verifier: &Driver) {
    // Generate message
    let mut m = [0u8; 32];
    getrandom::getrandom(&mut m).unwrap();

    // Generate keys
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();
    let mut pk: PublicKey = [0u8; 32];
    unsafe { (signer.ed25519_publickey)(sk.as_mut_ptr(), pk.as_mut_ptr()) };

    let mut sig = [0u8; 64];

    // Sign using donna
    unsafe { (signer.ed25519_sign)(m.as_ptr(), m.len() as UInt, sk.as_mut_ptr(), pk.as_mut_ptr(), sig.as_mut_ptr()) };

    // Verify using dalek

    // Check OK signature
    let res = unsafe { (verifier.ed25519_sign_open)(m.as_ptr(), m.len() as UInt, pk.as_mut_ptr(), sig.as_mut_ptr()) };
    assert_eq!(res, 0);

    // Check broken signature
    sig[0] ^= 0xFF;
    let res = unsafe { (verifier.ed25519_sign_open)(m.as_ptr(), m.len() as UInt, pk.as_mut_ptr(), sig.as_mut_ptr()) };
    assert!(res != 0);
}

#[test]
fn donna_sign_donna_verify() {
    sign_verify(&DONNA, &DONNA);
}

#[test]
fn dalek_sign_dalek_verify() {
    sign_verify(&DALEK, &DALEK);
}

#[test]
fn donna_sign_dalek_verify() {
    sign_verify(&DONNA, &DALEK);
}

#[test]
fn dalek_sign_donna_verify() {
    sign_verify(&DALEK, &DONNA);
}


fn batch_verify<const N: usize>(signer: &Driver, verifier: &Driver) {
    // Generate messages / keys / signatures
    let batch = generate_batch::<N>(signer);

    // Remap into arrays of pointers
    let mut pk: Vec<_> = batch.iter().map(|ref v| v.1.as_ptr() ).collect();
    let mut m: Vec<_> = batch.iter().map(|ref v| v.2.as_ptr() ).collect();
    let mut mlen: Vec<_> = batch.iter().map(|v| v.3).collect();
    let mut sigs: Vec<_> = batch.iter().map(|ref mut v| v.4.as_ptr() ).collect();


    // Perform batch verification
    let mut valid = [0; N];


    // Valid good batch
    let res = unsafe { (verifier.ed25519_sign_open_batch)(
        m.as_mut_ptr() as *mut *const u8, 
        mlen.as_mut_ptr() as *mut UInt, 
        pk.as_mut_ptr() as *mut *const u8, 
        sigs.as_mut_ptr() as *mut *const u8,
        N as UInt,
        valid.as_mut_ptr()
    ) };

    assert_eq!(res, 0, "Expected success");
    assert_eq!(valid, [1; N], "Unexpected success flags");


    // Invalidate first message
    let d = m[0] as *mut u8;
    unsafe { (*d) ^= 0xFF };

    // Valid batch with error
    let res = unsafe { (verifier.ed25519_sign_open_batch)(
        m.as_mut_ptr() as *mut *const u8, 
        mlen.as_mut_ptr() as *mut UInt, 
        pk.as_mut_ptr() as *mut *const u8, 
        sigs.as_mut_ptr() as *mut *const u8,
        N as UInt,
        valid.as_mut_ptr()
    ) };

    assert!(res != 0, "expected failure");
    let mut expected = [1; N];
    expected[0] = 0;
    assert_eq!(valid, expected, "unexpected failure flags");
}

// TODO: work out why donna fails with larger batch sizes
const TEST_BATCH_SIZE: usize = 16;

#[test]
fn batch_verify_donna_donna() {
    batch_verify::<TEST_BATCH_SIZE>(&DONNA, &DONNA);
}

#[test]
fn batch_verify_dalek_dalek() {
    batch_verify::<TEST_BATCH_SIZE>(&DALEK, &DALEK);
}

#[test]
fn batch_verify_donna_dalek() {
    batch_verify::<TEST_BATCH_SIZE>(&DONNA, &DALEK);
}

#[test]
fn batch_verify_dalek_donna() {
    batch_verify::<TEST_BATCH_SIZE>(&DALEK, &DONNA);
}

#[test]
fn scalarmult() {
    let mut rng = rand_core::OsRng;

    let scalars = &[
        Scalar::zero(),
        Scalar::one(),
        Scalar::random(&mut rng),
    ];

    for s in scalars {
        let mut s = s.as_bytes().to_vec();

        let mut dalek_s = [0u8; 32];
        unsafe {
            (DALEK.curve25519_scalarmult_basepoint)(dalek_s.as_mut_ptr(), s.as_mut_ptr());
        }

        let mut donna_s = [0u8; 32];
        unsafe {
            (DONNA.curve25519_scalarmult_basepoint)(donna_s.as_mut_ptr(), s.as_mut_ptr());
        }

        assert_eq!(dalek_s, donna_s);
    }

    
}
