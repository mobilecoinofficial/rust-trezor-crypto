
use {ed25519_donna_sys as _};

use trezor_crypto_lib::{
    ed25519::{self, SecretKey, PublicKey, dalek_ed25519_publickey, dalek_ed25519_sign_open, cosi},
    ffi,
    test::{self, Driver, ExtendedDriver}, UInt,
};

#[test]
fn cosi_combine_publickeys_1() {
    cosi_combine_publickeys::<1>()
}

#[test]
fn cosi_combine_publickeys_2() {
    cosi_combine_publickeys::<2>()
}

#[test]
fn cosi_combine_publickeys_8() {
    cosi_combine_publickeys::<8>()
}

fn cosi_combine_publickeys<const N: usize>() {
    // Load secret keys
    let mut sks = [[0u8; 32]; N];
    for i in 0..N {
        getrandom::getrandom(&mut sks[i]).unwrap();
    }

    // Generate public keys
    let mut pks = [[0u8; 32]; N];
    for i in 0..N {
        dalek_ed25519_publickey(&mut sks[i], &mut pks[i]);
    }

    // Perform dalek cosi operation
    let mut a_pk = [0u8; 32];
    unsafe { cosi::dalek_ed25519_cosi_combine_publickeys(&mut a_pk, pks.as_ptr(), N as UInt) };

    // Perform donna cosi operation
    let mut b_pk = [0u8; 32];
    unsafe { ffi::ed25519_cosi_combine_publickeys(&mut b_pk, pks.as_ptr(), N as UInt) };

    // Check outputs match
    assert_eq!(a_pk, b_pk);
}

#[test]
#[cfg(feature = "incomplete")]
fn cosi_combine_sigs_1() {
    cosi_combine_sigs::<1>();
}

#[test]
#[cfg(feature = "incomplete")]
fn cosi_combine_sigs_2() {
    cosi_combine_sigs::<2>();
}

#[cfg(feature = "incomplete")]
fn cosi_combine_sigs<const N: usize>() {
    // Generate public and private keys and combine
    let mut sks = [[0u8; 32]; N];
    let mut pks = [[0u8; 32]; N];
    for i in 0..N {
        getrandom::getrandom(&mut sks[i]).unwrap();
        dalek_ed25519_publickey(&mut sks[i], &mut pks[i]);
    }

    // Generate "signatures" (randomly)
    let mut sigs = [[0u8; 32]; N];
    for i in 0..N {
        getrandom::getrandom(&mut sigs[i]).unwrap();
    }
    
    // Create nonces and commitments and combine
    let mut nonces = [[0u8; 32]; N];
    let mut commits = [[0u8; 32]; N];
    for i in 0..N {
        getrandom::getrandom(&mut nonces[i]);
        dalek_ed25519_publickey(&mut commits[i], &mut nonces[i]);
    }
    
    let mut R = [0u8; 32];
    unsafe { cosi::dalek_ed25519_cosi_combine_publickeys(&mut R, commits.as_ptr(), N as UInt) };


    // Perform dalek cosi operation
    let mut a_sig = [0u8; 64];
    unsafe { cosi::dalek_ed25519_cosi_combine_signatures(&mut a_sig, &R, sigs.as_ptr(), N as UInt) };

    // Perform donna cosi operation
    let mut b_sig = [0u8; 64];
    unsafe { ffi::ed25519_cosi_combine_signatures(&mut b_sig, &mut R, sigs.as_ptr(), N as UInt) };

    // Check outputs match
    assert_eq!(a_sig, b_sig);
}

#[test]
#[cfg(feature = "incomplete")]
fn cosi_sign() {
    cosi_sign_n::<2>();
}

#[cfg(feature = "incomplete")]
fn cosi_sign_n<const N: usize>() {

    // Setup message to be signed
    let mut msg = [0u8; 128];
    getrandom::getrandom(&mut msg).unwrap();


    // Generate public and private keys and combine
    let mut sks = [[0u8; 32]; N];
    let mut pks = [[0u8; 32]; N];
    for i in 0..N {
        getrandom::getrandom(&mut sks[i]).unwrap();
        dalek_ed25519_publickey(&mut sks[i], &mut pks[i]);
    }

    let (mut cosi_pk_a, mut cosi_pk_b) = ([0u8; 32], [0u8; 32]);
    unsafe { cosi::dalek_ed25519_cosi_combine_publickeys(&mut cosi_pk_a, pks.as_ptr(), N as UInt) };

    unsafe { ffi::ed25519_cosi_combine_publickeys(&mut cosi_pk_b, pks.as_ptr(), N as UInt) };
    
    assert_eq!(cosi_pk_a, cosi_pk_b);


    // Create nonces and commitments and combine
    let mut nonces = [[0u8; 32]; N];
    let mut commits = [[0u8; 32]; N];

    for i in 0..N {
        getrandom::getrandom(&mut nonces[i]);
        dalek_ed25519_publickey(&mut commits[i], &mut nonces[i]);
    }
    
    let (mut r_a, mut r_b) = ([0u8; 32], [0u8; 32]);
    unsafe { cosi::dalek_ed25519_cosi_combine_publickeys(&mut r_a, commits.as_ptr(), N as UInt) };

    unsafe { ffi::ed25519_cosi_combine_publickeys(&mut r_b, commits.as_ptr(), N as UInt) };

    assert_eq!(r_a, r_b, "COSI combined pubkey mismatch");

    // Sign and combine signatures

    let (mut sigs_a, mut sigs_b) = ([[0u8; 32]; N], [[0u8; 32]; N]);
    for i in 0..N {

        unsafe { cosi::dalek_ed25519_cosi_sign(msg.as_ptr(), msg.len() as UInt, &sks[i], &nonces[i], &r_a, &pks[i], &mut sigs_a[i]) };

        unsafe { ffi::ed25519_cosi_sign(msg.as_ptr(), msg.len() as UInt, &mut sks[i], &mut nonces[i], &mut r_a, &mut pks[i], &mut sigs_b[i]) };

        assert_eq!(sigs_a[i], sigs_b[i], "COSI sign mismatch");
    }

    let (mut cosi_sig_a, mut cosi_sig_b) = ([0u8; 64], [0u8; 64]);
    unsafe {
        cosi::dalek_ed25519_cosi_combine_signatures(&mut cosi_sig_a, &r_a, sigs_a.as_ptr(), sigs_a.len() as UInt);
        ffi::ed25519_cosi_combine_signatures(&mut cosi_sig_b, &mut r_b, sigs_b.as_ptr(), sigs_b.len() as UInt);
    };

    assert_eq!(cosi_sig_a, cosi_sig_b, "COSI combined signature mismatch");


    // Check signature against normal verify
    let res_a = dalek_ed25519_sign_open(msg.as_ptr(), msg.len() as UInt, &mut cosi_pk_a, &mut cosi_sig_a);
    
    let res_b = unsafe { ffi::ed25519_sign_open(msg.as_ptr(), msg.len() as UInt, &mut cosi_pk_b, &mut cosi_sig_b) };


    assert_eq!(res_a, res_b);

    // Check outputs match
    //assert_eq!(a_sig, b_sig);
}
