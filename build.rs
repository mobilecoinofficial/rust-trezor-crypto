use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");

    build_bindings()?;

    Ok(())
}

// Build FFI bindings for testing
fn build_bindings() -> anyhow::Result<()> {
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

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
        .allowlist_type("keccak.*")
        .allowlist_type("sha3.*")
        .allowlist_function("ed25519_.*")
        .allowlist_function("curve25519_.*")
        .allowlist_function("curved25519_.*")
        .allowlist_function("ge25519_.*")
        .allowlist_var("KECCAK.*")
        .allowlist_var("SHA3.*")
        .array_pointers_in_arguments(true)
        .generate()
        .expect("Unable to generate bindings");

    // Write generated bindings to build
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}
