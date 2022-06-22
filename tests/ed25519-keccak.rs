


use trezor_crypto_lib::{
    ffi,
    UInt,
    ed25519::*,
    ed25519::keccak::*
};


#[cfg_attr(feature = "build_donna", link(name = "ed25519_donna_keccak"))]
extern "C" {}

fn decode_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut value = [0u8; N];
    hex::decode_to_slice(s, &mut value).unwrap();
    value
}

pub struct Driver {
    pub publickey: unsafe extern "C" fn(*mut SecretKey, *mut PublicKey),
    pub sign:
        unsafe extern "C" fn(*const u8, UInt, *mut SecretKey, *mut PublicKey, *mut Signature),
    pub sign_open:
        unsafe extern "C" fn(*const u8, UInt, *mut PublicKey, *mut Signature) -> i32,
    pub scalarmult_basepoint: unsafe extern "C" fn(*mut PublicKey, *mut SecretKey, *mut PublicKey) -> i32,
}

const DALEK: Driver = Driver {
    publickey: dalek_ed25519_publickey_keccak,
    sign: dalek_ed25519_sign_keccak,
    sign_open: dalek_ed25519_sign_open_keccak,
    scalarmult_basepoint: dalek_curved25519_scalarmult_basepoint_keccak,
};

const DONNA: Driver = Driver {
    publickey: ffi::ed25519_publickey_keccak,
    sign: ffi::ed25519_sign_keccak,
    sign_open: ffi::ed25519_sign_open_keccak,
    scalarmult_basepoint: ffi::curved25519_scalarmult_basepoint_keccak,
};

#[test]
fn test_pubkey_derive() {
    // Vectors from trezor's test_apps.nem.hdnode.py
    // (with inexplicably reversed private keys)
    let tests = &[(
        "575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced",
        "c5f54ba980fcbb657dbaaa42700539b207873e134d2375efeab5f1ab52f87844",
    ), (
        "5b0e3fa5d3b49a79022d7c1e121ba1cbbf4db5821f47ab8c708ef88defc29bfe",
        "96eb2a145211b1b7ab5f0d4b14f8abc8d695c7aee31a3cfc2d4881313c68eea3",
    ), (
        "e8bf9bc0f35c12d8c8bf94dd3a8b5b4034f1063948e3cc5304e55e31aa4b95a6",
        "4feed486777ed38e44c489c7c4e93a830e4c4a907fa19a174e630ef0f6ed0409",
    )];

    for (pri_key, pub_key) in tests {
        let mut pri_key = decode_bytes::<32>(pri_key);
        pri_key.reverse();

        let pub_key = decode_bytes::<32>(pub_key);

        let mut p = PublicKey::default();

        unsafe { dalek_ed25519_publickey_keccak(&mut pri_key, &mut p) };

        assert_eq!(pub_key, p, "expected: {:02x?} actual: {:02x?}", pub_key, p);
    }
}

#[test]
fn test_pubkey_compat() {
    // Generate random public key
    let mut sk: SecretKey = [0u8; 32];
    getrandom::getrandom(&mut sk).unwrap();

    let mut dalek_pk = PublicKey::default();
    unsafe { (DALEK.publickey)(
        sk.as_mut_ptr() as *mut SecretKey,
        dalek_pk.as_mut_ptr() as *mut PublicKey,
    ) };

    let mut donna_pk: PublicKey = [0u8; 32];
    unsafe {
        (DONNA.publickey)(
            sk.as_mut_ptr() as *mut SecretKey,
            donna_pk.as_mut_ptr() as *mut PublicKey,
        )
    };

    // Compare results
    assert_eq!(dalek_pk, donna_pk);
}
