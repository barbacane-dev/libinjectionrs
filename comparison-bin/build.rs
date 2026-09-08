#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::disallowed_methods)]

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_dir = PathBuf::from(&manifest_dir).parent().unwrap().join("ffi-harness").join("lib");
    let static_lib = lib_dir.join("libinjection_harness.a");

    // Build the C harness from source rather than expecting `make` to have
    // been run by hand. Without this, `cargo build -p libinjection-comparison`
    // fails at link time on a fresh checkout, which is also why the
    // differential tooling was easy to skip.
    if !static_lib.exists() {
        let harness_dir = PathBuf::from(&manifest_dir).parent().unwrap().join("ffi-harness");
        let c_src = PathBuf::from(&manifest_dir).parent().unwrap().join("libinjection-c").join("src");
        assert!(
            c_src.join("libinjection_sqli.c").exists(),
            "libinjection-c/src is missing. Run: git submodule update --init --recursive"
        );
        let status = std::process::Command::new("make")
            .current_dir(&harness_dir)
            .status()
            .expect("failed to run make for the C harness");
        assert!(status.success(), "building the C harness failed");
    }

    // Link the static library directly by path
    println!("cargo:rustc-link-arg={}", static_lib.display());
    println!("cargo:rerun-if-changed=../ffi-harness/harness.c");
    println!("cargo:rerun-if-changed=../ffi-harness/Makefile");
    
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=../ffi-harness/harness.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("../ffi-harness/harness.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}