use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/*");

    let _out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // TODO: Generate bindings for ed25519-donna w/ sha3

    // Compile ed25519-donna w/ sha3
    cc::Build::new()
        .include("../../vendor/ed25519-donna")
        .include("src")
        .file("src/ed25519-sha3.c")
        .define("ED25519_CUSTOMHASH", "1")
        .define("ED25519_TEST", "1")
        .warnings(false)
        .compile("libed25519_donna_sha3.a");

    Ok(())
}
