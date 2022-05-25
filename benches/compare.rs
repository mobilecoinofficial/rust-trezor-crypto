
#![feature(test)]

extern crate test;

use dalek_donna_ffi::test::*;

const BENCH_BATCH_SIZE: usize = 64;

fn bench_batch_verify<const N: usize>(b: &mut test::Bencher, driver: &Driver) {
    // Generate batch
    // Generate messages / keys / signatures
    let batch = generate_batch::<N>(driver);

    // Remap into arrays of pointers
    let mut pk: Vec<_> = batch.iter().map(|ref v| v.1.as_ptr() ).collect();
    let mut m: Vec<_> = batch.iter().map(|ref v| v.2.as_ptr() ).collect();
    let mut mlen: Vec<_> = batch.iter().map(|v| v.3).collect();
    let mut sigs: Vec<_> = batch.iter().map(|ref mut v| v.4.as_ptr() ).collect();

    b.iter(|| {
        // Perform batch verification
        let mut valid = [0; N];

        let res = unsafe { (driver.ed25519_sign_open_batch)(
            m.as_mut_ptr() as *mut *const u8, 
            mlen.as_mut_ptr() as *mut UInt, 
            pk.as_mut_ptr() as *mut *const u8, 
            sigs.as_mut_ptr() as *mut *const u8,
            N as u64,
            valid.as_mut_ptr()
        ) };

        assert_eq!(res, 0);
        assert_eq!(valid, [1; N]);
    })
}


#[bench]
fn bench_batch_verify_donna(b: &mut test::Bencher) {
    bench_batch_verify::<BENCH_BATCH_SIZE>(b, &DONNA)
}

#[bench]
fn bench_batch_verify_dalek(b: &mut test::Bencher) {
    bench_batch_verify::<BENCH_BATCH_SIZE>(b, &DALEK)
}

