//! Minimal x86_64 exception and interrupt diagnostics.
//!
//! The IDT is installed during single-core bootstrap, before enabling external
//! interrupts. Handlers are fail-stop: they report the saved machine state and
//! halt rather than attempting recovery from an unknown kernel state.

use core::arch::asm;
use core::mem::size_of;
use core::ptr;

const IDT_ENTRIES: usize = 256;
const GATE_INTERRUPT: u8 = 0x8E;

#[derive(Clone, Copy)]
#[repr(C)]
struct InterruptStackFrame {
    instruction_pointer: u64,
    code_segment: u64,
    cpu_flags: u64,
    stack_pointer: u64,
    stack_segment: u64,
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: usize, selector: u16) -> Self {
        let address = handler as u64;
        Self {
            offset_low: address as u16,
            selector,
            ist: 0,
            attributes: GATE_INTERRUPT,
            offset_middle: (address >> 16) as u16,
            offset_high: (address >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct Idtr {
    limit: u16,
    base: u64,
}

static mut IDT: [IdtEntry; IDT_ENTRIES] = [IdtEntry::MISSING; IDT_ENTRIES];

macro_rules! no_error_handler {
    ($name:ident, $vector:expr, $description:literal) => {
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame) -> ! {
            report_exception(Some($vector), $description, frame, None, None)
        }
    };
}

macro_rules! error_handler {
    ($name:ident, $vector:expr, $description:literal) => {
        extern "x86-interrupt" fn $name(
            frame: InterruptStackFrame,
            error_code: u64,
        ) -> ! {
            report_exception(
                Some($vector),
                $description,
                frame,
                Some(error_code),
                None,
            )
        }
    };
}

extern "x86-interrupt" fn unexpected_interrupt_handler(
    frame: InterruptStackFrame,
) -> ! {
    report_exception(
        None,
        "unclassified interrupt or exception",
        frame,
        None,
        None,
    )
}

no_error_handler!(divide_error_handler, 0, "divide error");
no_error_handler!(debug_handler, 1, "debug exception");
no_error_handler!(non_maskable_interrupt_handler, 2, "non-maskable interrupt");
no_error_handler!(breakpoint_handler, 3, "breakpoint");
no_error_handler!(overflow_handler, 4, "overflow");
no_error_handler!(bound_range_handler, 5, "bound-range exceeded");
no_error_handler!(invalid_opcode_handler, 6, "invalid opcode");
no_error_handler!(device_not_available_handler, 7, "device not available");
error_handler!(double_fault_handler, 8, "double fault");
no_error_handler!(coprocessor_segment_handler, 9, "coprocessor segment overrun");
error_handler!(invalid_tss_handler, 10, "invalid TSS");
error_handler!(segment_not_present_handler, 11, "segment not present");
error_handler!(stack_segment_fault_handler, 12, "stack-segment fault");
error_handler!(general_protection_handler, 13, "general protection fault");

extern "x86-interrupt" fn page_fault_handler(
    frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    let fault_address: u64;
    // SAFETY: CR2 is read in the x86_64 page-fault exception context.
    unsafe {
        asm!(
            "mov {}, cr2",
            out(reg) fault_address,
            options(nomem, nostack, preserves_flags)
        );
    }

    report_exception(
        Some(14),
        "page fault",
        frame,
        Some(error_code),
        Some(fault_address),
    )
}

no_error_handler!(x87_floating_point_handler, 16, "x87 floating-point exception");
error_handler!(alignment_check_handler, 17, "alignment check");
no_error_handler!(machine_check_handler, 18, "machine check");
no_error_handler!(simd_floating_point_handler, 19, "SIMD floating-point exception");
no_error_handler!(virtualization_handler, 20, "virtualization exception");
error_handler!(control_protection_handler, 21, "control-protection exception");
no_error_handler!(reserved_22_handler, 22, "reserved exception vector");
no_error_handler!(reserved_23_handler, 23, "reserved exception vector");
no_error_handler!(reserved_24_handler, 24, "reserved exception vector");
no_error_handler!(reserved_25_handler, 25, "reserved exception vector");
no_error_handler!(reserved_26_handler, 26, "reserved exception vector");
no_error_handler!(reserved_27_handler, 27, "reserved exception vector");
no_error_handler!(reserved_28_handler, 28, "reserved exception vector");
error_handler!(vmm_communication_handler, 29, "VMM communication exception");
error_handler!(security_exception_handler, 30, "security exception");
no_error_handler!(reserved_31_handler, 31, "reserved exception vector");

/// Installs an interrupt gate for the specified vector.
///
/// # Safety
///
/// The vector must be in range and the handler must use the ABI expected by
/// the processor for that vector's stack frame.
unsafe fn install_gate(vector: usize, handler: usize, selector: u16) {
    let entry = IdtEntry::new(handler, selector);
    // SAFETY: the caller supplies a valid vector, and initialization occurs
    // before this IDT is loaded or external interrupts are enabled.
    unsafe {
        ptr::addr_of_mut!(IDT)
            .cast::<IdtEntry>()
            .add(vector)
            .write(entry);
    }
}

/// Installs exception gates and safe fail-stop defaults for other vectors.
pub fn init() {
    let selector: u16;
    // SAFETY: reading CS is valid in the current x86_64 kernel context.
    unsafe {
        asm!(
            "mov {0:x}, cs",
            out(reg) selector,
            options(nomem, nostack, preserves_flags)
        );
    }

    // SAFETY: this function is called once during single-core bootstrap,
    // before loading the IDT or enabling external interrupts.
    unsafe {
        let idt_base = ptr::addr_of_mut!(IDT).cast::<IdtEntry>();
        let default_handler = unexpected_interrupt_handler as *const () as usize;

        for vector in 0..IDT_ENTRIES {
            idt_base
                .add(vector)
                .write(IdtEntry::new(default_handler, selector));
        }

        macro_rules! install {
            ($vector:expr, $handler:ident) => {
                install_gate($vector, $handler as *const () as usize, selector);
            };
        }

        install!(0, divide_error_handler);
        install!(1, debug_handler);
        install!(2, non_maskable_interrupt_handler);
        install!(3, breakpoint_handler);
        install!(4, overflow_handler);
        install!(5, bound_range_handler);
        install!(6, invalid_opcode_handler);
        install!(7, device_not_available_handler);
        install!(8, double_fault_handler);
        install!(9, coprocessor_segment_handler);
        install!(10, invalid_tss_handler);
        install!(11, segment_not_present_handler);
        install!(12, stack_segment_fault_handler);
        install!(13, general_protection_handler);
        install!(14, page_fault_handler);
        install!(16, x87_floating_point_handler);
        install!(17, alignment_check_handler);
        install!(18, machine_check_handler);
        install!(19, simd_floating_point_handler);
        install!(20, virtualization_handler);
        install!(21, control_protection_handler);
        install!(22, reserved_22_handler);
        install!(23, reserved_23_handler);
        install!(24, reserved_24_handler);
        install!(25, reserved_25_handler);
        install!(26, reserved_26_handler);
        install!(27, reserved_27_handler);
        install!(28, reserved_28_handler);
        install!(29, vmm_communication_handler);
        install!(30, security_exception_handler);
        install!(31, reserved_31_handler);

        let idtr = Idtr {
            limit: (size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: idt_base as u64,
        };
        asm!(
            "lidt [{}]",
            in(reg) &idtr,
            options(readonly, nostack, preserves_flags)
        );
    }

    super::serial_write(b"CPU exception IDT installed\n");
}

fn report_exception(
    vector: Option<u8>,
    description: &str,
    frame: InterruptStackFrame,
    error_code: Option<u64>,
    fault_address: Option<u64>,
) -> ! {
    super::serial_write(b"\nONE OS EXCEPTION\n");
    super::serial_write(b"Exception: ");
    super::serial_write(description.as_bytes());
    super::serial_write(b"\n");

    match vector {
        Some(value) => write_hex(b"Exception vector: ", value as u64),
        None => super::serial_write(b"Exception vector: unavailable\n"),
    }

    write_hex(b"Instruction pointer: ", frame.instruction_pointer);
    write_hex(b"Code segment: ", frame.code_segment);
    write_hex(b"CPU flags: ", frame.cpu_flags);
    write_hex(b"Stack pointer: ", frame.stack_pointer);
    write_hex(b"Stack segment: ", frame.stack_segment);

    if let Some(value) = error_code {
        write_hex(b"Error code: ", value);
    }
    if let Some(value) = fault_address {
        write_hex(b"Fault address (CR2): ", value);
    }

    super::serial_write(b"ONE OS EXCEPTION HALTED\n");
    super::halt_forever()
}

fn write_hex(label: &[u8], value: u64) {
    super::serial_write(label);
    super::serial_write(b"0x");

    let mut digits = [b'0'; 16];
    for (index, digit) in digits.iter_mut().enumerate() {
        let shift = (15 - index) * 4;
        let nibble = ((value >> shift) & 0x0f) as u8;
        *digit = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        };
    }

    super::serial_write(&digits);
    super::serial_write(b"\n");
}
