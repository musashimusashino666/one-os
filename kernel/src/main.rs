#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

//! Initial x86_64 kernel entry point.
//!
//! This bootstrap provides serial diagnostics, basic CPU exception handling,
//! and a halt loop. It is not yet a complete or independently bootable OS.

use bootloader_api::{entry_point, BootInfo};
use core::arch::asm;
use core::panic::PanicInfo;
use oneos_core::{validate_memory_map, MemoryMapError};

mod interrupts;

const COM1: u16 = 0x3F8;

entry_point!(kernel_main);

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

    interrupts::init();

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
    #[cfg(feature = "test-exception")]
    {
        serial_write(b"ONE OS EXCEPTION TEST: triggering invalid opcode\n");
        // SAFETY: UD2 deliberately raises #UD in the dedicated test image.
        unsafe { asm!("ud2", options(nomem, nostack, noreturn)) }
    }

    #[cfg(feature = "test-general-protection")]
    {
        serial_write(b"ONE OS EXCEPTION TEST: triggering general protection fault\n");
        // SAFETY: the deliberately invalid selector must raise #GP in this
        // dedicated test image before the next instruction can execute.
        unsafe {
            asm!(
                "mov ds, ax",
                in("ax") 0xffff_u16,
                options(nomem, nostack, noreturn)
            )
        }
    }

    #[cfg(feature = "test-page-fault")]
    {
        const FAULT_ADDRESS: usize = 0x0000_4000_0000_0000;
        serial_write(b"ONE OS EXCEPTION TEST: triggering page fault\n");
        // SAFETY: this unmapped canonical address is deliberately read only in
        // the dedicated fault-injection image to exercise #PF and CR2 logging.
        unsafe {
            core::ptr::read_volatile(FAULT_ADDRESS as *const u64);
        }
        halt_forever()
    }

    #[cfg(not(any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault"
    )))]
    {
        serial_write(b"\nONE OS kernel booted\n");
        serial_write(b"Architecture: x86_64\n");
        serial_write(b"Milestone: serial bootstrap\n");
        serial_write(b"Memory map: structurally validated\n");
        serial_write(
            b"Status: physical allocation, user mode, scheduler, VM, and drivers are not implemented\n",
        );
        // This marker is emitted only after IDT installation and memory-map
        // validation. CI rejects exception, panic, and invalid-map markers.
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
