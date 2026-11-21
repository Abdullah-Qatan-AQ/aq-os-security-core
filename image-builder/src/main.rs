use std::{env, path::Path, process::Command};

fn main() {
    let image = env!("AQOS_BIOS_IMAGE");
    if std::env::args().any(|arg| arg == "--run") {
        let status = Command::new("qemu-system-x86_64")
            .args([
                "-drive",
                &format!("format=raw,file={image}"),
                "-serial",
                "stdio",
            ])
            .status()
            .expect("qemu-system-x86_64 is required for --run");
        std::process::exit(status.code().unwrap_or(1));
    }
    println!("AQ OS BIOS image: {}", Path::new(image).display());
    println!("Run with: cargo run -p aqos-image -- --run");
}
