use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let target = root.join("target/x86_64-unknown-none/release/aqos-kernel");
    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "aqos-kernel",
            "--target",
            "x86_64-unknown-none",
            "--release",
        ])
        .status()
        .expect("failed to invoke cargo for the kernel");
    assert!(status.success(), "kernel build failed");

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("aqos-bios.img");
    bootloader::BiosBoot::new(&target)
        .create_disk_image(&out)
        .expect("failed to create BIOS disk image");
    println!("cargo:rustc-env=AQOS_BIOS_IMAGE={}", out.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("kernel/src/main.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join("kernel/Cargo.toml").display()
    );
    let _ = fs::metadata(&out).expect("BIOS image was not created");
}
