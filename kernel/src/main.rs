#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

//! Initial x86_64 kernel entry point.
//!
//! This bootstrap provides serial diagnostics, basic CPU exception handling,
//! and a halt loop. It is not yet a complete or independently bootable OS.

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use core::arch::asm;
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
use core::arch::global_asm;
use core::panic::PanicInfo;
use oneos_core::{validate_memory_map, MemoryMapError};

#[cfg(any(
    all(feature = "test-exception", feature = "test-general-protection"),
    all(feature = "test-exception", feature = "test-page-fault"),
    all(feature = "test-exception", feature = "test-double-fault"),
    all(feature = "test-general-protection", feature = "test-page-fault"),
    all(feature = "test-general-protection", feature = "test-double-fault"),
    all(feature = "test-page-fault", feature = "test-double-fault"),
    all(
        feature = "test-exception",
        any(
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection"
        )
    ),
    all(
        feature = "test-general-protection",
        any(
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection"
        )
    ),
    all(
        feature = "test-page-fault",
        any(
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection"
        )
    ),
    all(
        feature = "test-double-fault",
        any(
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection"
        )
    ),
    all(
        feature = "test-supervisor-write-protection",
        feature = "test-nx-protection"
    )
))]
compile_error!("enable only one exception fault-injection feature at a time");

mod interrupts;
mod memory;
mod paging;

const COM1: u16 = 0x3F8;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.page_table_recursive = Some(Mapping::Dynamic);
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

#[cfg(feature = "test-supervisor-write-protection")]
global_asm!(
    ".global oneos_vm_test_supervisor_write",
    ".global oneos_vm_test_supervisor_write_fault_ip",
    "oneos_vm_test_supervisor_write:",
    "mov rax, rdi",
    "mov rdx, rsi",
    "oneos_vm_test_supervisor_write_fault_ip:",
    "mov qword ptr [rax], rdx",
    "ret",
);

#[cfg(feature = "test-supervisor-write-protection")]
unsafe extern "C" {
    fn oneos_vm_test_supervisor_write(target: u64, value: u64);
    static oneos_vm_test_supervisor_write_fault_ip: u8;
}

#[cfg(feature = "test-nx-protection")]
global_asm!(
    ".global oneos_vm_test_nx_execute",
    ".global oneos_vm_test_nx_recovery",
    "oneos_vm_test_nx_execute:",
    "mov rax, rdi",
    "call rax",
    "oneos_vm_test_nx_recovery:",
    "ret",
);

#[cfg(feature = "test-nx-protection")]
unsafe extern "C" {
    fn oneos_vm_test_nx_execute(target: u64);
    static oneos_vm_test_nx_recovery: u8;
}

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Establish the interrupt state before any peripheral or IDT setup.
    // SAFETY: this is privileged x86_64 kernel entry code. Maskable interrupts
    // stay disabled throughout this bootstrap; the legacy PIC is also masked.
    unsafe {
        asm!("cli", options(nomem, nostack));
        outb(0x21, u8::MAX);
        outb(0xA1, u8::MAX);
        serial_init();
    }

    // SAFETY: bootstrap is single-core, interrupts remain disabled, and the
    // IDT/TSS/GDT setup is performed exactly once before entering the kernel loop.
    unsafe { interrupts::init() };

    // Validate physical memory ranges before reporting a successful boot.
    let region_count = boot_info.memory_regions.len();
    if let Err(error) = validate_memory_map(region_count, |index| {
        let region = &boot_info.memory_regions[index];
        (region.start, region.end)
    }) {
        serial_write(b"\nONE OS MEMORY MAP INVALID\n");
        match error {
            MemoryMapError::Empty => serial_write(b"Memory map has no regions\n"),
            MemoryMapError::InvalidRange { .. } => {
                serial_write(b"Memory map contains an empty or inverted range\n")
            }
            MemoryMapError::Overlap { .. } => {
                serial_write(b"Memory map contains overlapping ranges\n")
            }
        }
        halt_forever()
    }

    // Fault-injection configurations are compiled only for dedicated QEMU
    // tests. The normal BIOS image never executes these paths.
    serial_write(b"\nONE OS kernel booted\n");

    let allocator_stats = match memory::initialize(
        &boot_info.memory_regions,
        boot_info.kernel_addr,
        boot_info.kernel_len,
    ) {
        Ok(stats) => stats,
        Err(error) => {
            serial_write(b"\nONE OS FRAME ALLOCATOR FAILED\n");
            serial_write(error.message());
            halt_forever()
        }
    };

    // Exercise both allocation and release before claiming bootstrap success.
    let probe_frame = match memory::allocate_frame() {
        Ok(frame) => frame,
        Err(error) => {
            serial_write(b"\nONE OS FRAME ALLOCATOR FAILED\n");
            serial_write(error.message());
            halt_forever()
        }
    };
    if let Err((error, _probe_frame)) = memory::free_frame(probe_frame) {
        serial_write(b"\nONE OS FRAME ALLOCATOR FAILED\n");
        serial_write(error.message());
        halt_forever()
    }
    serial_write(b"ONE OS FRAME ALLOCATOR READY\n");
    interrupts::write_hex(
        b"Usable physical frames: ",
        allocator_stats.total_frames as u64,
    );
    interrupts::write_hex(
        b"Usable physical regions: ",
        allocator_stats.usable_regions as u64,
    );

    if let Err(error) = paging::initialize_paging_controls() {
        serial_write(b"\nONE OS PAGING CONTROL INITIALIZATION FAILED\n");
        serial_write(error.message());
        halt_forever()
    }

    let paging_stats = match paging::inspect_boot_mappings(boot_info) {
        Ok(stats) => stats,
        Err(error) => {
            serial_write(b"\nONE OS PAGING INSPECTION FAILED\n");
            serial_write(error.message());
            halt_forever()
        }
    };
    serial_write(b"ONE OS PAGE TABLE INSPECTION READY\n");
    interrupts::write_hex(
        b"Current PML4 physical address: ",
        paging_stats.root_table_physical,
    );
    interrupts::write_hex(
        b"Validated bootstrap mappings: ",
        paging_stats.validated_mappings as u64,
    );

    if let Err(error) = paging::verify_mapping_smoke_test(boot_info) {
        serial_write(b"\nONE OS PAGING MUTATION FAILED\n");
        serial_write(error.message());
        halt_forever()
    }
    serial_write(b"ONE OS VM MAPPING SMOKE TEST READY\n");

    #[cfg(feature = "test-supervisor-write-protection")]
    {
        serial_write(b"ONE OS VM TEST: supervisor-write-protection\n");
        let mapping = match paging::install_supervisor_write_protection_test(boot_info) {
            Ok(mapping) => mapping,
            Err(error) => {
                serial_write(b"ONE OS VM TEST FAILED: setup\n");
                serial_write(error.message());
                halt_forever()
            }
        };
        // SAFETY: this exported assembly label is the exact faulting store in
        // the dedicated test-only write sequence.
        let expected_ip =
            unsafe { core::ptr::addr_of!(oneos_vm_test_supervisor_write_fault_ip) as u64 };
        interrupts::write_hex(b"ONE OS VM TEST TARGET: ", mapping.virtual_address);
        interrupts::write_hex(b"ONE OS VM TEST EXPECTED RIP: ", expected_ip);
        interrupts::arm_expected_protection_page_fault(mapping.virtual_address, expected_ip, 0);
        // SAFETY: this test-only store deliberately writes to the read-only
        // target mapping. The armed handler accepts only its exact RIP, CR2,
        // and complete error_code == 0x3, then exits QEMU via isa-debug-exit.
        unsafe {
            oneos_vm_test_supervisor_write(mapping.virtual_address, 0x4f4e_455f_524f_5750);
        }
        serial_write(b"ONE OS VM TEST FAILED: protected write returned\n");
        halt_forever()
    }

    #[cfg(feature = "test-nx-protection")]
    {
        serial_write(b"ONE OS VM TEST: nx-instruction-fetch\n");
        let mapping = match paging::install_nx_execution_protection_test(boot_info) {
            Ok(mapping) => mapping,
            Err(error) => {
                serial_write(b"ONE OS VM TEST FAILED: setup\n");
                serial_write(error.message());
                halt_forever()
            }
        };
        let expected_ip = mapping.virtual_address;
        interrupts::write_hex(b"ONE OS VM TEST TARGET: ", mapping.virtual_address);
        interrupts::write_hex(b"ONE OS VM TEST EXPECTED RIP: ", expected_ip);
        // SAFETY: the assembly continuation is immediately after the indirect
        // call that attempted instruction fetch at the NX target.
        let recovery_ip = unsafe { core::ptr::addr_of!(oneos_vm_test_nx_recovery) as u64 };
        interrupts::arm_expected_protection_page_fault(
            mapping.virtual_address,
            expected_ip,
            recovery_ip,
        );
        // SAFETY: the target contains UD2 but is mapped NX. The handler checks
        // the exact CR2/RIP and full error_code == 0x11, then redirects only
        // that one saved instruction pointer to the known continuation.
        unsafe { oneos_vm_test_nx_execute(mapping.virtual_address) };
        if !interrupts::expected_protection_page_fault_was_seen() {
            serial_write(b"ONE OS VM TEST FAILED: NX fault was not recovered\n");
            halt_forever()
        }
        serial_write(b"ONE OS VM TEST NX RECOVERY VERIFIED\n");
        serial_write(b"ONE OS VM TEST PASS: nx-instruction-fetch\n");
        unsafe {
            asm!(
                "out dx, al",
                in("dx") 0xf4u16,
                in("al") 0x10u8,
                options(nomem, nostack, preserves_flags)
            );
        }
        halt_forever()
    }

    #[cfg(feature = "test-exception")]
    {
        serial_write(b"ONE OS EXCEPTION TEST: triggering invalid opcode\n");
        // SAFETY: UD2 deliberately raises #UD in the dedicated test image.
        unsafe { asm!("ud2", options(nomem, nostack, noreturn)) }
    }

    #[cfg(feature = "test-general-protection")]
    {
        const NON_CANONICAL_ADDRESS: usize = 0x8000_0000_0000_0000;
        serial_write(b"ONE OS EXCEPTION TEST: triggering non-canonical address access\n");
        // SAFETY: this is a data load from an address that is non-canonical in
        // both 48-bit and 57-bit paging modes, which raises #GP(0) before page
        // translation. This path exists only in the dedicated test image.
        let _fault_value: u64;
        unsafe {
            asm!(
                "mov {value}, qword ptr [{address}]",
                value = out(reg) _fault_value,
                address = in(reg) NON_CANONICAL_ADDRESS,
                options(nostack)
            );
        }
        // This instruction must fault. Do not rely on options(noreturn) to
        // synthesize a fallback UD2 if the test instruction unexpectedly returns.
        serial_write(b"ONE OS EXCEPTION TEST FAILED: non-canonical load returned\n");
        halt_forever()
    }

    #[cfg(feature = "test-page-fault")]
    {
        const FAULT_ADDRESS: usize = 0x0000_4000_0000_0000;
        serial_write(b"ONE OS EXCEPTION TEST: triggering page fault\n");
        // SAFETY: the assembly load deliberately reads this unmapped canonical
        // address only in the dedicated test image, exercising #PF and CR2
        // logging without relying on Rust pointer-dereference semantics.
        let _fault_value: u64;
        unsafe {
            asm!(
                "mov {value}, qword ptr [{address}]",
                value = out(reg) _fault_value,
                address = in(reg) FAULT_ADDRESS,
                options(nostack, readonly)
            );
        }
        halt_forever()
    }

    #[cfg(feature = "test-double-fault")]
    {
        const INVALID_STACK_POINTER: usize = 0x8000_0000_0000_0000;
        serial_write(b"ONE OS EXCEPTION TEST: triggering double fault\n");
        // SAFETY: this test-only image deliberately installs a non-canonical
        // RSP before raising #UD. The failed exception-frame push escalates to
        // #DF, whose handler must switch to the configured IST stack.
        unsafe {
            asm!(
                "mov rsp, {bad_stack}",
                "ud2",
                bad_stack = in(reg) INVALID_STACK_POINTER,
                options(noreturn)
            );
        }
    }

    #[cfg(not(any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault",
        feature = "test-double-fault"
    )))]
    {
        serial_write(b"Architecture: x86_64\n");
        serial_write(b"Milestone: serial bootstrap\n");
        serial_write(b"Memory map: structurally validated\n");
        serial_write(
            b"Status: physical allocation and read-only page-table inspection are available; new mappings, user mode, scheduler, and drivers are not implemented\n",
        );
        // This marker is emitted only after IDT installation, memory-map validation,
        // allocator smoke tests, and mapping/permission validation. CI rejects any failed stage.
        serial_write(b"ONE OS BOOTSTRAP COMPLETE\n");

        halt_forever()
    }
}

unsafe fn serial_init() {
    // Disable UART interrupts while configuring the port.
    // SAFETY: the caller runs in privileged kernel context on x86_64.
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80); // Enable divisor latch.
        outb(COM1, 0x03); // Divisor 3: 38400 baud.
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8 data bits, no parity, one stop bit.
        outb(COM1 + 2, 0xC7); // Enable and clear FIFO.
        outb(COM1 + 4, 0x0B); // DTR, RTS, OUT2.
    }
}

fn serial_write(bytes: &[u8]) {
    for &byte in bytes {
        if byte == b'\n' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(byte);
    }
}

fn serial_write_byte(byte: u8) {
    // Poll the UART line-status register until its transmit buffer is ready.
    loop {
        // SAFETY: COM1 + 5 is the UART line-status register.
        let status = unsafe { inb(COM1 + 5) };
        if status & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // SAFETY: COM1 is the UART transmit register.
    unsafe {
        outb(COM1, byte);
    }
}

unsafe fn outb(port: u16, value: u8) {
    // SAFETY: caller must run at sufficient privilege and provide a valid I/O port.
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: caller must run at sufficient privilege and provide a valid I/O port.
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

fn halt_forever() -> ! {
    loop {
        // SAFETY: HLT is used only from privileged kernel execution.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_write(b"\nONE OS KERNEL PANIC\n");
    halt_forever()
}
