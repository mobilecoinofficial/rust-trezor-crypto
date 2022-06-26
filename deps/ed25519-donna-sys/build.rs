use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/*");

    let _out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // TODO: Generate bindings for ed25519-donna w/ reference hash

    // Compile ed25519-donna w/ reference hash
    cc::Build::new()
    .include("../../vendor/ed25519-donna")
    .file("../../vendor/ed25519-donna/ed25519.c")
    .file("src/extensions.c")
    .define("ED25519_REFHASH", "1")
    .define("ED25519_TEST", "1")
    .warnings(false)
    .compile("libed25519_donna.a");

    Ok(())
}
