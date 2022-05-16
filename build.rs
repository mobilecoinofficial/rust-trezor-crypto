
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
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

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .clang_arg("-Ivendor/ed25519-donna")
        //.clang_arg("--sysroot-/home/ryan/.arm-none-eabi/")
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .ctypes_prefix("cty")
        .allowlist_type("ed25519_.*")
        .allowlist_type("curved25519_.*")
        .allowlist_function("ed25519_.*")
        .allowlist_function("curved25519_.*")
        // Array pointers in arguments neatens up the function definitions
        // but doesn't help with the mutability bug
        //.array_pointers_in_arguments(true)
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

    // Compile library
    // See `src/ffi.rs` for linking
    cc::Build::new()
        .include("vendor/ed25519-donna")
        .file("vendor/ed25519-donna/ed25519.c")
        // Using reference hasher for ease, could swap to rust version
        .define("ED25519_REFHASH", "1")
        .define("ED25519_TEST", "1")
        .warnings(false)
        .compile("libed25519_donna.a");

    Ok(())
}
