
use curve25519_dalek::{
    digest::{consts::U64, Digest}, edwards::{EdwardsPoint, CompressedEdwardsY},
};
use ed25519_dalek::{Sha512, ExpandedSecretKey};

use crate::{Int, UInt, modm::expand256_modm};

use super::{PublicKey, SecretKey, Signature, CosiSignature};


/// Combine public keys via COSI
#[no_mangle]
pub unsafe extern "C" fn dalek_ed25519_cosi_combine_publickeys(
    o: *mut PublicKey,
    pks: *const PublicKey,
    n: UInt) -> Int {
    
    let pks = core::slice::from_raw_parts(pks, n as usize);

    // Short-circuit for single keys
    if n == 1 {
        *o = *(&pks[0] as *const PublicKey);
        return 0;
    }

    let mut t = EdwardsPoint::default();

    for pk in pks {
        // Unpack the point
        let c1 = CompressedEdwardsY(*pk);
        let r1 = match c1.decompress() {
            Some(v) => v,
            None => return -1,
        };

        // Add to running total
        t += r1;
    }
    
    // Write back result
    let c = t.compress();
    (*o).copy_from_slice(c.as_bytes());

    return 0;
}

/// Combine signatures via COSI
#[cfg(feature = "incomplete")]
#[no_mangle]
pub unsafe extern "C" fn dalek_ed25519_cosi_combine_signatures(
    o: *mut Signature,
    r: *const PublicKey,
    sigs: *const CosiSignature,
    n: UInt) {
    
    use curve25519_dalek::scalar::Scalar;

    let sigs = core::slice::from_raw_parts(sigs, n as usize);
    let mut s = Scalar::zero();

    // Sum signatures
    for sig in sigs {
        let mut b = [0u8; 32];
        b.copy_from_slice(&sig[..32]);

        let t = Scalar::from_bytes_mod_order(b);
        s += t;
    }
    
    let s = s.reduce().to_bytes();

    // Result is r[..32] + t[..32]
    ((*o)[..32].copy_from_slice(&*r));
    ((*o)[32..][..32].copy_from_slice(&s));
}

/// Sign via COSI
#[cfg(feature = "incomplete")]
#[no_mangle]
pub unsafe extern "C" fn dalek_ed25519_cosi_sign(
    m: *const u8,
    mlen: UInt,
    sk: *const SecretKey,
    nonce: *const SecretKey,
    R: *const PublicKey,
    pk: *const PublicKey,
    sig: *mut CosiSignature,
) {
    use curve25519_dalek::scalar::Scalar;

    let msg = core::slice::from_raw_parts(m, mlen as usize);

    //let sk = Scalar::from_bytes_mod_order(*sk);
    //let nonce = Scalar::from_bytes_mod_order(*nonce);

    let extsk = ed25519_extsk::<Sha512>(&*sk);
    let extnonce = ed25519_extsk::<Sha512>(&*nonce);

    //println!("DALEK EXTSK: {:02x?}", extsk);
    //println!("DALEK EXTNONCE: {:02x?}", extnonce);

    /* r = nonce */
    let mut r = Scalar::from_bytes_mod_order(extnonce);

    #[cfg(test)]
    println!("DALEK R: {:08x?}", r.to_unpacked_u32());


    //println!("DALEK NONCE: {:08x?}", nonce.to_unpacked_u32());

    /* H(R, A, m) */
    let mut h = Sha512::new();
    h.update(*R);
    h.update(*pk);
    h.update(msg);
    let v = h.finalize();

    //println!("DALEK H: {:02x?}", v.as_slice());

    /* S = H(R,A,m).. */
    let mut buff = [0u8; 32];
    buff.copy_from_slice(&v.as_slice()[..32]);
    let mut S = Scalar::from_bytes_mod_order(buff);

    #[cfg(test)]
    println!("DALEK S: {:08x?}", S.to_unpacked_u32());

    /* S = H(R,A,m)a */
    let a = Scalar::from_bytes_mod_order(extsk);
    S = S * &a;

    /* S = (r + H(R,A,m)a) */
    S = S + r;

    /* sig = (r + H(R,A,m)a) mod L */
    *sig = S.reduce().to_bytes();
}

fn ed25519_extsk<D: Digest<OutputSize = U64>>(data: &[u8]) -> [u8; 32] {
    // Construct expanded secret key using digest
    let mut h = D::new();
    h.update(data);

    // Copy into buffer and clamp
    let mut buff = [0u8; 32];
    buff.copy_from_slice(&h.finalize().as_slice()[..32]);

    buff[0]  &= 248;
    buff[31] &=  63;
    buff[31] |=  64;

    buff
}
