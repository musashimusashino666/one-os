use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

const KERNEL_PACKAGE: &str = "one-os-kernel";
const KERNEL_TARGET: &str = "x86_64-unknown-none";
const KERNEL_BIN: &str = "one-os-kernel";

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
            println!(
                "      Build the kernel and create one-os-bios.img in Cargo's target directory"
            );
            Ok(())
        }
        other => Err(format!("unknown command: {other}; run with --help").into()),
    }
}

fn cargo_metadata(root: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

fn cargo_target_directory(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let metadata = cargo_metadata(root)?;
    let directory = metadata
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .ok_or("cargo metadata did not report target_directory")?;
    Ok(PathBuf::from(directory))
}

fn build_kernel(root: &Path, target_directory: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args([
            "build",
            "-p",
            KERNEL_PACKAGE,
            "--target",
            KERNEL_TARGET,
            "--message-format=json-render-diagnostics",
        ])
        .output()?;

    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!("kernel build failed with status {}", output.status).into());
    }

    // Cargo's compiler-artifact JSON is the source of truth for the produced
    // executable path, including custom target directories and target naming.
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact")
            || message
                .get("target")
                .and_then(|target| target.get("name"))
                .and_then(serde_json::Value::as_str)
                != Some(KERNEL_BIN)
            || !message
                .get("target")
                .and_then(|target| target.get("kind"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")))
        {
            continue;
        }

        if let Some(path) = message
            .get("executable")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .filter(|path| path.is_file())
        {
            return Ok(path);
        }
    }

    // Fallback for Cargo versions/targets that omit the executable field.
    // x86_64-unknown-none uses the target executable name without a host suffix.
    let fallback = target_directory
        .join(KERNEL_TARGET)
        .join("debug")
        .join(KERNEL_BIN);
    if fallback.is_file() {
        return Ok(fallback);
    }

    Err(format!(
        "Cargo built the kernel but did not report a usable executable at {}",
        fallback.display()
    )
    .into())
}

fn build_bios_image() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let target_directory = cargo_target_directory(&root)?;
    let kernel_path = build_kernel(&root, &target_directory)?;
    let image_path = target_directory.join("one-os-bios.img");

    bootloader::BiosBoot::new(&kernel_path).create_disk_image(&image_path)?;

    println!("Created BIOS disk image: {}", image_path.display());
    Ok(())
}
