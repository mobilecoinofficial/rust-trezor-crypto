use std::path::PathBuf;

fn main() -> anyhow::Result<()> {

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");

    // Build donna C bindings for testing
    #[cfg(feature = "build_donna")]
    build_bindings()?;

    // Build donna C library for testing
    #[cfg(feature = "build_donna")]
    build_lib()?;

    Ok(())
}

// Build C bindings for test use
#[cfg(feature = "build_donna")]
fn build_bindings() -> anyhow::Result<()> {
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    
    // TODO: attempting (unsuccessfully so far) to extract static inline functions
    // from the grasp of the donna headers...
    #[cfg(nope)]
    {
    let files = &[
        "ed25519-donna-impl-base.h",
        "curve25519-donna-32bit.h",
    ];

    // Rewrite donna headers to drop static from defs
    let p = PathBuf::from("vendor/ed25519-donna");
    for f in files {
        let s = std::fs::read_to_string(p.join(f))?;
        let s = s.replace("DONNA_INLINE static ", "");
        std::fs::write(out_path.join(f), s)?;
    }
    }

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", out_path.to_str().unwrap()))
        .clang_arg("-Ivendor/ed25519-donna")
        .clang_arg("-Ivendor/curve25519-donna")
        .clang_arg("-DED25519_FORCE_32BIT")
        .clang_arg("-DCURVE25519_FORCE_32BIT")
        //.clang_arg("--sysroot-/home/ryan/.arm-none-eabi/")
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .ctypes_prefix("cty")
        .allowlist_type("ed25519_.*")
        .allowlist_type("curved25519_.*")
        .allowlist_type("ge25519_.*")
        .allowlist_type("bignum.*")
        .allowlist_function("ed25519_.*")
        .allowlist_function("curve25519_.*")
        .allowlist_function("curved25519_.*")
        .allowlist_function("ge25519_.*")
        // Array pointers in arguments neatens up the function definitions
        // but doesn't help with the mutability bug
        .array_pointers_in_arguments(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write generated bindings to build
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}

// Build donna C library for test use
#[cfg(feature = "build_donna")]
fn build_lib() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=tests/extensions.c");

    // Compile library
    // See `src/ffi.rs` for linking
    cc::Build::new()
        .include("vendor/ed25519-donna")
        .file("vendor/ed25519-donna/ed25519.c")
        .file("tests/extensions.c")
        // TODO: re-enable these
        //.file("tests/ed25519-keccak.c")
        //.file("tests/ed25519-sha3.c")
        // Using reference hasher for ease, could swap to rust version
        .define("ED25519_REFHASH", "1")
        .define("ED25519_TEST", "1")
        .warnings(false)
        .compile("libed25519_donna.a");

    cc::Build::new()
        .include("vendor/curve25519-donna")
        .file("vendor/curve25519-donna/curve25519.c")
        // Using reference hasher for ease, could swap to rust version
        //.define("ED25519_REFHASH", "1")
        .define("ED25519_TEST", "1")
        .warnings(false)
        .compile("libcurve25519_donna.a");


    Ok(())
}
