//! Helpers to ensure ABI compatibility for use when testing

use core::ops::{Deref, DerefMut};

pub use crate::UInt;
use crate::{
    ed25519::consts::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH},
    ed25519::{self, PublicKey, Scalar, SecretKey, Signature},
    ffi,
};

/// Basic driver object for compatibility testing of ed25519 operations
pub struct Driver {
    /// Generate a public key from the provided secret key
    pub publickey: unsafe extern "C" fn(*mut SecretKey, *mut PublicKey),
    
    /// Sign the provided message using the secret and public keys
    pub sign:
        unsafe extern "C" fn(*const u8, UInt, *mut SecretKey, *mut PublicKey, *mut Signature),
    
    /// Verify the provided message using the public key and signature
    pub sign_open:
        unsafe extern "C" fn(*const u8, UInt, *mut PublicKey, *mut Signature) -> i32,
    
    /// Scalar multiplication with the provided basepoint
    pub scalarmult: Option<unsafe extern "C" fn(*mut PublicKey, *mut SecretKey, *mut PublicKey)>,

    /// Scalar multiplication with default (edwards) basepoint
    pub scalarmult_basepoint: unsafe extern "C" fn(*mut PublicKey, *mut SecretKey),

    /// Batch verify messages
    pub sign_open_batch: Option<unsafe extern "C" fn(
        *mut *const u8,
        *mut UInt,
        *mut *const u8,
        *mut *const u8,
        UInt,
        *mut i32,
    ) -> i32>,

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
        pk: *mut PublicKey,
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


pub struct Batch<const N: usize, const M: usize = 128> {
    pub secret_keys: [SecretKey; N],
    pub public_keys: [PublicKey; N],
    pub messages: [[u8; M]; N],
    pub lengths: [UInt; N],
    pub signatures: [Signature; N],
}

impl<const N: usize, const M: usize> Batch<N, M> {
    /// Generate a collection for batch verification
    pub fn new(signer: &Driver) -> Self {
        let mut secret_keys = [[0u8; SECRET_KEY_LENGTH]; N];
        let mut public_keys = [[0u8; PUBLIC_KEY_LENGTH]; N];

        let mut messages = [[0u8; M]; N];
        let mut signatures = [[0u8; SIGNATURE_LENGTH]; N];

        for i in 0..N {
            // Generate random secret key
            getrandom::getrandom(&mut secret_keys[i]).unwrap();

            // Generate matching public key
            unsafe {
                (signer.publickey)(
                    secret_keys[i].as_mut_ptr() as *mut SecretKey,
                    public_keys[i].as_mut_ptr() as *mut PublicKey,
                )
            };

            // Generate message
            getrandom::getrandom(&mut messages[i]).unwrap();

            // Generate signature
            unsafe {
                (signer.sign)(
                    messages[i].as_mut_ptr(),
                    M as UInt,
                    secret_keys[i].as_mut_ptr() as *mut SecretKey,
                    public_keys[i].as_mut_ptr() as *mut PublicKey,
                    signatures[i].as_mut_ptr() as *mut Signature,
                )
            };
        }

        Self {
            secret_keys,
            public_keys,
            messages,
            lengths: [M as UInt; N],
            signatures,
        }
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
            pk.as_mut_ptr() as *mut PublicKey,
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
pub fn scalarmult(a: &Driver, b: &Driver) {
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
            (a.scalarmult.unwrap())(
                a_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
                bp.as_mut_ptr() as *mut Scalar,
            );
        }

        let mut b_s = [0u8; 32];
        unsafe {
            (b.scalarmult.unwrap())(
                b_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
                bp.as_mut_ptr() as *mut Scalar,
            );
        }

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
            (a.scalarmult_basepoint)(
                a_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
            );
        }

        let mut b_s = [0u8; 32];
        unsafe {
            (b.scalarmult_basepoint)(
                b_s.as_mut_ptr() as *mut Scalar,
                s.as_mut_ptr() as *mut Scalar,
            );
        }

        assert_eq!(a_s, b_s);
    }
}


/// Test batch verification
pub fn batch_verify<const N: usize>(signer: &Driver, verifier: &Driver) {
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
        (verifier.sign_open_batch.unwrap())(
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
        (verifier.sign_open_batch.unwrap())(
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
            pk.as_mut_ptr() as *mut PublicKey,
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
