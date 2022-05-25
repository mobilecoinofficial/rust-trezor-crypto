#![feature(test)]

use crate::UInt;

extern crate test;

extern crate libc;

use dalek_donna_ffi::{test::*, PublicKey, Scalar, SecretKey, Signature};

/// Check key derivation functions are compatible
#[test]
fn derive_keys() {
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();

    println!("Using secret key: {:02x?}", sk);

    // Perform dalek key derivation
    let mut dalek_sk = sk.clone();
    let mut dalek_pk: PublicKey = [0u8; 32];
    unsafe {
        (DALEK.ed25519_publickey)(
            dalek_sk.as_mut_ptr() as *mut SecretKey,
            dalek_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(dalek_sk, sk);

    // Perform donna key derivation
    let mut donna_sk = sk.clone();
    let mut donna_pk: PublicKey = [0u8; 32];
    unsafe {
        (DONNA.ed25519_publickey)(
            donna_sk.as_mut_ptr() as *mut SecretKey,
            donna_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
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
    unsafe {
        (signer.ed25519_publickey)(
            sk.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    let mut sig = [0u8; 64];

    // Sign using donna
    unsafe {
        (signer.ed25519_sign)(
            m.as_ptr(),
            m.len() as UInt,
            sk.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };

    // Verify using dalek

    // Check OK signature
    let res = unsafe {
        (verifier.ed25519_sign_open)(
            m.as_ptr(),
            m.len() as UInt,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };
    assert_eq!(res, 0);

    // Check broken signature
    sig[0] ^= 0xFF;
    let res = unsafe {
        (verifier.ed25519_sign_open)(
            m.as_ptr(),
            m.len() as UInt,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };
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

/// Test batch verification
fn batch_verify<const N: usize>(signer: &Driver, verifier: &Driver) {
    // Generate batch for processing
    let Batch {
        public_keys,
        mut messages,
        signatures,
        lengths,
        ..
    } = Batch::<N>::new(signer);

    // Remap into arrays of pointers
    let mut pk: Vec<_> = public_keys.iter().map(|ref v| v.as_ptr()).collect();
    let mut m: Vec<_> = messages
        .iter_mut()
        .map(|ref mut v| v.as_mut_ptr())
        .collect();
    let mut mlen: Vec<_> = lengths.iter().map(|v| *v).collect();
    let mut sigs: Vec<_> = signatures.iter().map(|ref mut v| v.as_ptr()).collect();

    // Perform batch verification
    let mut valid = [0; N];

    // Valid good batch
    let res = unsafe {
        (verifier.ed25519_sign_open_batch)(
            m.as_mut_ptr() as *mut *const u8,
            mlen.as_mut_ptr() as *mut UInt,
            pk.as_mut_ptr() as *mut *const u8,
            sigs.as_mut_ptr() as *mut *const u8,
            N as UInt,
            valid.as_mut_ptr(),
        )
    };

    assert_eq!(res, 0, "Expected success");
    assert_eq!(valid, [1; N], "Unexpected success flags");

    // Invalidate first message
    let d = m[0] as *mut u8;
    unsafe { (*d) ^= 0xFF };

    // Valid batch with error
    let res = unsafe {
        (verifier.ed25519_sign_open_batch)(
            m.as_mut_ptr() as *mut *const u8,
            mlen.as_mut_ptr() as *mut UInt,
            pk.as_mut_ptr() as *mut *const u8,
            sigs.as_mut_ptr() as *mut *const u8,
            N as UInt,
            valid.as_mut_ptr(),
        )
    };

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

/// Test scalar multiplication
#[test]
fn scalarmult_basepoint() {
    let mut rng = rand_core::OsRng;

    use curve25519_dalek::scalar::Scalar as S;

    // Test set, zero one and a random scalar
    let scalars = &[S::zero(), S::one(), S::random(&mut rng)];

    for s in scalars {
        let mut s = s.as_bytes().to_vec();

        let mut dalek_s = [0u8; 32];
        unsafe {
            (DALEK.curved25519_scalarmult_basepoint)(
                dalek_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
            );
        }

        let mut donna_s = [0u8; 32];
        unsafe {
            (DONNA.curved25519_scalarmult_basepoint)(
                donna_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
            );
        }

        assert_eq!(dalek_s, donna_s);
    }
}

/// Test expanded public key generation
#[test]
fn publickey_ext() {
    // Create new secret key and generate
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();

    // Generate expanded secret key
    let expanded = {
        let sk = ed25519_dalek::SecretKey::from_bytes(&sk).unwrap();
        ed25519_dalek::ExpandedSecretKey::from(&sk).to_bytes()
    };

    let (mut sk_base, mut sk_ext) = ([0u8; 32], [0u8; 32]);
    sk_base.copy_from_slice(&expanded[..32]);
    sk_ext.copy_from_slice(&expanded[32..]);

    // Perform dalek key derivation
    let mut dalek_pk: PublicKey = [0u8; 32];
    unsafe {
        (DALEK.ed25519_publickey_ext)(
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            dalek_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(&sk_base, &expanded[..32]);

    // Perform donna key derivation
    let mut donna_pk: PublicKey = [0u8; 32];
    unsafe {
        (DONNA.ed25519_publickey_ext)(
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            donna_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(&sk_base, &expanded[..32]);

    // Compare results
    assert_eq!(dalek_pk, donna_pk);
}

/// Test expanded key signing
fn sign_ext(signer: &Driver, verifier: &Driver) {
    let mut m = [0u8; 48];
    getrandom::getrandom(&mut m).unwrap();

    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();

    // Generate expanded secret key
    let expanded = {
        let sk = ed25519_dalek::SecretKey::from_bytes(&sk).unwrap();
        ed25519_dalek::ExpandedSecretKey::from(&sk)
    };

    let ex = expanded.to_bytes();
    let (mut sk_base, mut sk_ext) = ([0u8; 32], [0u8; 32]);
    sk_base.copy_from_slice(&ex[..32]);
    sk_ext.copy_from_slice(&ex[32..]);

    // Generate matching expanded public key
    let mut pk: PublicKey = [0u8; 32];
    unsafe {
        (signer.ed25519_publickey_ext)(
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    // Perform sign
    let mut sig: Signature = [0u8; 64];
    unsafe {
        (signer.ed25519_sign_ext)(
            m.as_mut_ptr(),
            m.len() as UInt,
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    }

    // Perform verify
    let res = unsafe {
        (verifier.ed25519_sign_open)(
            m.as_mut_ptr(),
            m.len() as UInt,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };
    assert_eq!(res, 0);
}

#[test]
fn sign_ext_dalek_donna() {
    sign_ext(&DALEK, &DONNA);
}

#[test]
fn sign_ext_donna_dalek() {
    sign_ext(&DALEK, &DONNA);
}

#[test]
fn curve25519_scalarmult_communicative() {
    let (mut sk1, mut sk2) = ([0u8; 32], [0u8; 32]);
    getrandom::getrandom(&mut sk1).unwrap();
    getrandom::getrandom(&mut sk2).unwrap();

    let mut pk1 = [0u8; 32];
    unsafe {
        (DALEK.ed25519_publickey)(
            pk1.as_mut_ptr() as *mut PublicKey,
            sk1.as_mut_ptr() as *mut SecretKey,
        )
    };

    let mut pk2 = [0u8; 32];
    unsafe {
        (DALEK.ed25519_publickey)(
            pk2.as_mut_ptr() as *mut PublicKey,
            sk2.as_mut_ptr() as *mut SecretKey,
        )
    };

    let mut s1 = [0u8; 32];
    unsafe {
        (DALEK.curve25519_scalarmult)(
            s1.as_mut_ptr() as *mut Scalar,
            sk1.as_mut_ptr() as *mut SecretKey,
            pk2.as_mut_ptr() as *mut PublicKey,
        )
    };

    let mut s2 = [0u8; 32];
    unsafe {
        (DALEK.curve25519_scalarmult)(
            s2.as_mut_ptr() as *mut Scalar,
            sk2.as_mut_ptr() as *mut SecretKey,
            pk1.as_mut_ptr() as *mut PublicKey,
        )
    };

    assert_eq!(s1, s2);
}

// Vectors from `test_trezor.crypto.curve.curve25519.py`
const SCALARMULT_VECS: (&str, &str, &str) = (
    "38c9d9b17911de26ed812f5cc19c0029e8d016bcbc6078bc9db2af33f1761e4a",
    "311b6248af8dabec5cc81eac5bf229925f6d218a12e0547fb1856e015cc76f5d",
    "a93dbdb23e5c99da743e203bd391af79f2b83fb8d0fd6ec813371c71f08f2d4d",
);

#[test]
#[ignore = "curve25519_scalarmult not yet implemented"]
fn curve25519_scalarmult_vectors() {
    let (mut sk, mut pk, mut sess) = ([0u8; 64], [0u8; 64], [0u8; 64]);

    base64::decode_config_slice(SCALARMULT_VECS.0, base64::STANDARD, &mut sk).unwrap();
    base64::decode_config_slice(SCALARMULT_VECS.1, base64::STANDARD, &mut pk).unwrap();
    base64::decode_config_slice(SCALARMULT_VECS.2, base64::STANDARD, &mut sess).unwrap();

    let mut sess2 = [0u8; 64];
    unsafe {
        (DALEK.curve25519_scalarmult)(
            sess2.as_mut_ptr() as *mut Scalar,
            sk.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    assert_eq!(&sess[..32], &sess2[..32])
}

/// Test scalar multiplication with provided basepoints
// TODO(@ryankurte): does this make sense?
#[test]
#[ignore = "curve25519_scalarmult not yet implemented"]
fn curve25519_scalarmult() {
    let mut rng = rand_core::OsRng;

    use curve25519_dalek::scalar::Scalar as S;

    // Test set, zero one and a random scalar
    let tests = &[
        (S::zero(), S::one()),
        (S::one(), S::one()),
        (S::random(&mut rng), S::one()),
    ];

    for (s, bp) in tests {
        let mut s = s.as_bytes().to_vec();
        let mut bp = bp.as_bytes().to_vec();

        let mut dalek_s = [0u8; 32];
        unsafe {
            (DALEK.curve25519_scalarmult)(
                dalek_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
                bp.as_mut_ptr() as *mut Scalar,
            );
        }

        let mut donna_s = [0u8; 32];
        unsafe {
            (DONNA.curve25519_scalarmult)(
                donna_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
                bp.as_mut_ptr() as *mut Scalar,
            );
        }

        assert_eq!(dalek_s, donna_s);
    }
}
