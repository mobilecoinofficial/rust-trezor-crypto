//! Helpers to ensure ABI compatibility for use when testing

use core::ops::{Deref, DerefMut};

pub use crate::UInt;
use crate::{
    ed25519::{PublicKey, Scalar, SecretKey, Signature},
};

/// Basic driver object for compatibility testing of ed25519 operations
pub struct Driver {
    /// Generate a public key from the provided secret key
    pub publickey: unsafe extern "C" fn(*mut SecretKey, *mut PublicKey),
    
    /// Sign the provided message using the secret and public keys
    pub sign:
        unsafe extern "C" fn(*const u8, UInt, *mut SecretKey, *mut Signature),
    
    /// Verify the provided message using the public key and signature
    pub sign_open:
        unsafe extern "C" fn(*const u8, UInt, *mut PublicKey, *mut Signature) -> i32,
    
    /// Curve scalar multiplication with the provided basepoint
    pub curve25519_scalarmult: Option<unsafe extern "C" fn(*mut PublicKey, *mut SecretKey, *mut PublicKey)>,

    /// Curve scalar multiplication with default basepoint
    pub curved25519_scalarmult_basepoint: unsafe extern "C" fn(*mut PublicKey, *mut SecretKey),

    /// Point multiplication with the provided basepoint
    pub ed25519_scalarmult: Option<unsafe extern "C" fn(*mut PublicKey, *mut SecretKey, *mut PublicKey) -> i32>,
}

/// Extended driver includes basic driver and methods using extended keys
pub struct ExtendedDriver {
    pub driver: Driver,

    pub publickey_ext:
    unsafe extern "C" fn(sk: *mut SecretKey, sk_ext: *mut SecretKey, pk: *mut PublicKey),

    pub sign_ext: unsafe extern "C" fn(
        m: *const u8,
        mlen: UInt,
        sk: *mut SecretKey,
        sk_ext: *mut SecretKey,
        sig: *mut Signature,
    ),
}

impl Deref for ExtendedDriver {
    type Target = Driver;

    fn deref(&self) -> &Self::Target {
        &self.driver
    }
}

impl DerefMut for ExtendedDriver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.driver
    }
}

/// Decode a hex string to `N` sized array of bytes
#[cfg(any(test, feature = "hex"))]
pub fn decode_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut value = [0u8; N];
    hex::decode_to_slice(s, &mut value).unwrap();
    value
}


/// Test key derivation matches between drivers
pub fn derive_keys(a: &Driver, b: &Driver) {
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();

    // Perform dalek key derivation
    let mut a_sk = sk.clone();
    let mut a_pk: PublicKey = [0u8; 32];
    unsafe {
        (a.publickey)(
            a_sk.as_mut_ptr() as *mut SecretKey,
            a_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(a_sk, sk);

    // Perform donna key derivation
    let mut b_sk = sk.clone();
    let mut b_pk: PublicKey = [0u8; 32];
    unsafe {
        (b.publickey)(
            b_sk.as_mut_ptr() as *mut SecretKey,
            b_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(b_sk, sk);

    // Compare results
    assert_eq!(a_pk, b_pk);
}


/// Sign a random message with `signer` and verify with `verifier`
pub fn sign_verify(signer: &Driver, verifier: &Driver) {
    // Generate message
    let mut m = [0u8; 32];
    getrandom::getrandom(&mut m).unwrap();

    // Generate keys
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();
    let mut pk: PublicKey = [0u8; 32];
    unsafe {
        (signer.publickey)(
            sk.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    let mut sig = [0u8; 64];

    // Sign using `signer`
    unsafe {
        (signer.sign)(
            m.as_ptr(),
            m.len() as UInt,
            sk.as_mut_ptr() as *mut SecretKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };

    // Verify using `verifier`

    // Check OK signature
    let res = unsafe {
        (verifier.sign_open)(
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
        (verifier.sign_open)(
            m.as_ptr(),
            m.len() as UInt,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };
    assert!(res != 0);
}

/// Test scalar multiplication against the provided basepoint
pub fn curve25519_scalarmult(a: &Driver, b: &Driver) {
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

        let mut a_s = [0u8; 32];
        unsafe {
            (a.curve25519_scalarmult.unwrap())(
                a_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
                bp.as_mut_ptr() as *mut Scalar,
            );
        }

        let mut b_s = [0u8; 32];
        unsafe {
            (b.curve25519_scalarmult.unwrap())(
                b_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
                bp.as_mut_ptr() as *mut Scalar,
            );
        }

        assert_eq!(a_s, b_s);
    }
}

/// Test point multiplication against the provided basepoint
pub fn ed25519_scalarmult(a: &Driver, b: &Driver) {
    let mut rng = rand_core::OsRng;

    use curve25519_dalek::scalar::Scalar as S;

    // Generate keys
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();
    let mut pk: PublicKey = [0u8; 32];
    unsafe {
        (a.publickey)(
            sk.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    // Test set, zero one and a random scalar
    let tests = &[
        S::zero(),
        S::one(),
        S::random(&mut rng),
    ];

    for bp in tests {
        let mut bp = bp.as_bytes().to_vec();

        let mut a_s = [0u8; 32];
        unsafe {
            (a.ed25519_scalarmult.unwrap())(
                a_s.as_mut_ptr() as *mut PublicKey,
                sk.as_mut_ptr() as *mut SecretKey,
                bp.as_mut_ptr() as *mut PublicKey,
            );
        }

        println!("a: {:02x?}", a_s);

        let mut b_s = [0u8; 32];
        unsafe {
            (b.ed25519_scalarmult.unwrap())(
                b_s.as_mut_ptr() as *mut PublicKey,
                sk.as_mut_ptr() as *mut SecretKey,
                bp.as_mut_ptr() as *mut PublicKey,
            );
        }

        println!("b: {:02x?}", b_s);

        assert_eq!(a_s, b_s);
    }
}

/// Test scalar multiplication against the standard basepoint
pub fn scalarmult_basepoint(a: &Driver, b: &Driver) {
    let mut rng = rand_core::OsRng;

    use curve25519_dalek::scalar::Scalar as S;

    // Test set, zero one and a random scalar
    let tests = &[
        S::zero(),
        S::one(),
        S::random(&mut rng),
    ];

    for s in tests {
        let mut s = s.as_bytes().to_vec();

        let mut a_s = [0u8; 32];
        unsafe {
            (a.curved25519_scalarmult_basepoint)(
                a_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
            );
        }

        let mut b_s = [0u8; 32];
        unsafe {
            (b.curved25519_scalarmult_basepoint)(
                b_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
            );
        }

        assert_eq!(a_s, b_s);
    }
}

/// Test expanded public key generation
pub fn publickey_ext(a: &ExtendedDriver, b: &ExtendedDriver) {
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
    let mut a_pk: PublicKey = [0u8; 32];
    unsafe {
        (a.publickey_ext)(
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            a_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(&sk_base, &expanded[..32]);

    // Perform donna key derivation
    let mut b_pk: PublicKey = [0u8; 32];
    unsafe {
        (b.publickey_ext)(
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            b_pk.as_mut_ptr() as *mut PublicKey,
        )
    };
    assert_eq!(&sk_base, &expanded[..32]);

    // Compare results
    assert_eq!(a_pk, b_pk);
}

/// Test expanded key signing
pub fn sign_ext(signer: &ExtendedDriver, verifier: &ExtendedDriver) {
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
        (signer.publickey_ext)(
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    // Perform sign
    let mut sig: Signature = [0u8; 64];
    unsafe {
        (signer.sign_ext)(
            m.as_mut_ptr(),
            m.len() as UInt,
            sk_base.as_mut_ptr() as *mut SecretKey,
            sk_ext.as_mut_ptr() as *mut SecretKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    }

    // Perform verify
    let res = unsafe {
        (verifier.sign_open)(
            m.as_mut_ptr(),
            m.len() as UInt,
            pk.as_mut_ptr() as *mut PublicKey,
            sig.as_mut_ptr() as *mut Signature,
        )
    };
    assert_eq!(res, 0);
}
