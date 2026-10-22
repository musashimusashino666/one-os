use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if let Err(error) = run() {
        eprintln!("oneos-xtask: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let command = std::env::args().nth(1).unwrap_or_else(|| "help".to_owned());

    match command.as_str() {
        "image" => build_bios_image(),
        "help" | "--help" | "-h" => {
            println!("ONE OS build tools");
            println!("  cargo run -p oneos-xtask -- image");
            println!("      Build the kernel and create target/one-os-bios.img");
            Ok(())
        }
        other => Err(format!("unknown command: {other}; run with --help").into()),
    }
}

fn build_bios_image() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;

    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "one-os-kernel",
            "--target",
            "x86_64-unknown-none",
        ])
        .status()?;

    if !status.success() {
        return Err(format!("kernel build failed with status {status}").into());
    }

    let kernel_name = format!("one-os-kernel{}", std::env::consts::EXE_SUFFIX);
    let kernel_path = root
        .join("target")
        .join("x86_64-unknown-none")
        .join("debug")
        .join(kernel_name);

    if !kernel_path.is_file() {
        return Err(format!("kernel artifact was not found: {}", kernel_path.display()).into());
    }

    let image_path = root.join("target").join("one-os-bios.img");
    bootloader::BiosBoot::new(&kernel_path).create_disk_image(&image_path)?;

    println!("Created BIOS disk image: {}", image_path.display());
    Ok(())
}
