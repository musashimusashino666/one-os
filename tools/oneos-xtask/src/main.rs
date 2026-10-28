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
        "image" => build_bios_image(None),
        "image-test-exception" => build_bios_image(Some("test-exception")),
        "image-test-general-protection" => build_bios_image(Some("test-general-protection")),
        "image-test-page-fault" => build_bios_image(Some("test-page-fault")),
        "image-test-double-fault" => build_bios_image(Some("test-double-fault")),
        "image-test-ist" => build_bios_image(Some("test-ist")),
        "image-test-supervisor-write-protection" => {
            build_bios_image(Some("test-supervisor-write-protection"))
        }
        "image-test-nx-protection" => build_bios_image(Some("test-nx-protection")),
        "image-test-vm-transitions" => build_bios_image(Some("test-vm-transitions")),
        "image-test-root-leak-safety" => build_bios_image(Some("test-root-leak-safety")),
        "image-test-wx-runtime-audit" => build_bios_image(Some("test-wx-runtime-audit")),
        "image-test-nmi-wx-transition" => build_bios_image(Some("test-nmi-wx-transition")),
        "help" | "--help" | "-h" => {
            println!("ONE OS build tools");
            println!("  cargo run -p oneos-xtask -- image");
            println!(
                "      Build the normal kernel and create one-os-bios.img in Cargo's target directory"
            );
            println!("  cargo run -p oneos-xtask -- image-test-exception");
            println!("      Build a test-only invalid-opcode exception image");
            println!("  cargo run -p oneos-xtask -- image-test-general-protection");
            println!("      Build a test-only general-protection exception image");
            println!("  cargo run -p oneos-xtask -- image-test-page-fault");
            println!("      Build a test-only page-fault exception image");
            println!("  cargo run -p oneos-xtask -- image-test-double-fault");
            println!("      Build a test-only double-fault/IST diagnostic image");
            println!("  cargo run -p oneos-xtask -- image-test-ist");
            println!("      Build an image to verify NMI and machine-check IST stack selection");
            println!("  cargo run -p oneos-xtask -- image-test-supervisor-write-protection");
            println!("      Build a test-only supervisor read-only protection image");
            println!("  cargo run -p oneos-xtask -- image-test-nx-protection");
            println!("      Build a test-only NX instruction-fetch protection image");
            println!("  cargo run -p oneos-xtask -- image-test-vm-transitions");
            println!("      Build a test-only map/unmap/remap and TLB-transition image");
            println!("  cargo run -p oneos-xtask -- image-test-root-leak-safety");
            println!("      Build a test-only uncertain-CR3 root-token leak safety image");
            println!("  cargo run -p oneos-xtask -- image-test-wx-runtime-audit");
            println!("      Build a dedicated post-activation W^X audit diagnostic image");
            println!("  cargo run -p oneos-xtask -- image-test-nmi-wx-transition");
            println!("      Build a test-only image for QMP-injected NMI during W^X break-before-make");
            Ok(())
        }
        other => Err(format!("unknown command: {other}; run with --help").into()),
    }
}

fn cargo_metadata(root: &Path) -> Result<serde_json::Value, Box<dyn Error>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--locked", "--format-version", "1", "--no-deps"])
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

fn build_kernel(
    root: &Path,
    target_directory: &Path,
    test_feature: Option<&str>,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut command = Command::new("cargo");
    command
        .current_dir(root)
        .args(["build", "--locked", "-p", KERNEL_PACKAGE]);

    if let Some(feature) = test_feature {
        command.args(["--features", feature]);
    }

    let output = command
        .args([
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

fn build_bios_image(test_feature: Option<&str>) -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let target_directory = cargo_target_directory(&root)?;
    let kernel_path = build_kernel(&root, &target_directory, test_feature)?;
    let image_name = match test_feature {
        None => "one-os-bios.img",
        Some("test-exception") => "one-os-exception-test-bios.img",
        Some("test-general-protection") => "one-os-general-protection-test-bios.img",
        Some("test-page-fault") => "one-os-page-fault-test-bios.img",
        Some("test-double-fault") => "one-os-double-fault-test-bios.img",
        Some("test-ist") => "one-os-ist-test-bios.img",
        Some("test-supervisor-write-protection") => {
            "one-os-supervisor-write-protection-test-bios.img"
        }
        Some("test-nx-protection") => "one-os-nx-protection-test-bios.img",
        Some("test-vm-transitions") => "one-os-vm-transitions-test-bios.img",
        Some("test-root-leak-safety") => "one-os-root-leak-safety-test-bios.img",
        Some("test-wx-runtime-audit") => "one-os-wx-runtime-audit-test-bios.img",
        Some("test-nmi-wx-transition") => "one-os-nmi-wx-transition-test-bios.img",
        Some(other) => return Err(format!("unknown test feature: {other}").into()),
    };
    let image_path = target_directory.join(image_name);

    bootloader::BiosBoot::new(&kernel_path).create_disk_image(&image_path)?;

    println!("Created BIOS disk image: {}", image_path.display());
    Ok(())
}
