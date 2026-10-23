//! Minimal x86_64 exception and interrupt diagnostics.
//!
//! The IDT is installed during single-core bootstrap, before enabling external
//! interrupts. Handlers are fail-stop: they report the saved machine state and
//! halt rather than attempting recovery from an unknown kernel state.

use core::arch::asm;
use core::mem::size_of;
use core::ptr;
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const IDT_ENTRIES: usize = 256;
const GATE_INTERRUPT: u8 = 0x8E;
const DOUBLE_FAULT_IST_INDEX: u8 = 1;
const DOUBLE_FAULT_STACK_SIZE: usize = 16 * 1024;
const MAX_GDT_ENTRIES: usize = 256;

#[repr(C, packed)]
struct TaskStateSegment {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl TaskStateSegment {
    const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            // Place the I/O-map base beyond the TSS limit: no I/O bitmap exists.
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

// The CPU consumes this buffer through TSS.IST1 rather than Rust field reads.
#[allow(dead_code)]
#[repr(align(16))]
struct DoubleFaultStack([u8; DOUBLE_FAULT_STACK_SIZE]);

#[repr(C, packed)]
struct Gdtr {
    limit: u16,
    base: u64,
}

static mut GDT: [u64; MAX_GDT_ENTRIES] = [0; MAX_GDT_ENTRIES];
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut DOUBLE_FAULT_STACK: DoubleFaultStack = DoubleFaultStack([0; DOUBLE_FAULT_STACK_SIZE]);

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

    fn new(handler: usize, selector: u16, ist: u8) -> Self {
        let address = handler as u64;
        Self {
            offset_low: address as u16,
            selector,
            ist: ist & 0b111,
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
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame, error_code: u64) -> ! {
            report_exception(Some($vector), $description, frame, Some(error_code), None)
        }
    };
}

extern "x86-interrupt" fn unexpected_interrupt_handler(frame: InterruptStackFrame) -> ! {
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
no_error_handler!(
    coprocessor_segment_handler,
    9,
    "coprocessor segment overrun"
);
error_handler!(invalid_tss_handler, 10, "invalid TSS");
error_handler!(segment_not_present_handler, 11, "segment not present");
error_handler!(stack_segment_fault_handler, 12, "stack-segment fault");
error_handler!(general_protection_handler, 13, "general protection fault");

#[cfg(not(any(feature = "test-supervisor-write-protection", feature = "test-nx-protection")))]
extern "x86-interrupt" fn page_fault_handler(frame: InterruptStackFrame, error_code: u64) -> ! {
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

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
static EXPECTED_PROTECTION_FAULT_ADDRESS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
static EXPECTED_PROTECTION_FAULT_RIP: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
static EXPECTED_PROTECTION_FAULT_RECOVERY_RIP: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
static EXPECTED_PROTECTION_FAULT_ARMED: AtomicBool = AtomicBool::new(false);
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
static EXPECTED_PROTECTION_FAULT_SEEN: AtomicBool = AtomicBool::new(false);

/// Arms exactly one known, terminal page-fault expectation in a dedicated QEMU image.
/// The ordinary production page-fault handler remains fail-stop.
#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
pub(super) fn arm_expected_protection_page_fault(
    target: u64,
    instruction_pointer: u64,
    recovery_instruction_pointer: u64,
) {
    EXPECTED_PROTECTION_FAULT_ADDRESS.store(target, Ordering::Relaxed);
    EXPECTED_PROTECTION_FAULT_RIP.store(instruction_pointer, Ordering::Relaxed);
    EXPECTED_PROTECTION_FAULT_RECOVERY_RIP.store(recovery_instruction_pointer, Ordering::Relaxed);
    EXPECTED_PROTECTION_FAULT_SEEN.store(false, Ordering::Relaxed);
    EXPECTED_PROTECTION_FAULT_ARMED.store(true, Ordering::Release);
}

#[cfg(feature = "test-nx-protection")]
pub(super) fn expected_protection_page_fault_was_seen() -> bool {
    EXPECTED_PROTECTION_FAULT_SEEN.load(Ordering::Acquire)
}

#[cfg(any(
    feature = "test-supervisor-write-protection",
    feature = "test-nx-protection"
))]
extern "x86-interrupt" fn page_fault_handler(mut frame: InterruptStackFrame, error_code: u64) {
    let fault_address: u64;
    // SAFETY: CR2 is read in the x86_64 page-fault exception context.
    unsafe {
        asm!(
            "mov {}, cr2",
            out(reg) fault_address,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[cfg(feature = "test-supervisor-write-protection")]
    let expected_error_code = 0x3;
    #[cfg(feature = "test-nx-protection")]
    let expected_error_code = 0x11;

    let armed = EXPECTED_PROTECTION_FAULT_ARMED.swap(false, Ordering::AcqRel);
    let previously_seen = EXPECTED_PROTECTION_FAULT_SEEN.swap(true, Ordering::AcqRel);
    let expected_address = EXPECTED_PROTECTION_FAULT_ADDRESS.load(Ordering::Relaxed);
    let expected_rip = EXPECTED_PROTECTION_FAULT_RIP.load(Ordering::Relaxed);
    let recovery_rip = EXPECTED_PROTECTION_FAULT_RECOVERY_RIP.load(Ordering::Relaxed);

    if armed
        && !previously_seen
        && error_code == expected_error_code
        && fault_address == expected_address
        && frame.instruction_pointer == expected_rip
    {
        super::serial_write(b"\nONE OS VM TEST EXPECTED PAGE FAULT\n");
        write_hex(b"Instruction pointer: ", frame.instruction_pointer);
        write_hex(b"Error code: ", error_code);
        write_hex(b"Fault address (CR2): ", fault_address);

        #[cfg(feature = "test-supervisor-write-protection")]
        {
            if recovery_rip != 0 {
                report_exception(
                    Some(14),
                    "invalid test recovery state",
                    frame,
                    Some(error_code),
                    Some(fault_address),
                );
            }
            super::serial_write(b"ONE OS VM TEST PASS: supervisor-write-protection\n");
            // QEMU is launched with isa-debug-exit. Value 0x10 yields status 33.
            unsafe {
                asm!(
                    "out dx, al",
                    in("dx") 0xf4u16,
                    in("al") 0x10u8,
                    options(nomem, nostack, preserves_flags)
                );
            }
            super::halt_forever()
        }

        #[cfg(feature = "test-nx-protection")]
        {
            if recovery_rip == 0 {
                report_exception(
                    Some(14),
                    "invalid NX test recovery state",
                    frame,
                    Some(error_code),
                    Some(fault_address),
                );
            }
            // SAFETY: the one armed NX test fault matched the exact target VA,
            // saved RIP, and complete error code. This known executable
            // continuation is outside the NX target page; use a volatile write
            // so the hardware-saved instruction pointer is updated before IRETQ.
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(frame.instruction_pointer), recovery_rip);
            }
            super::serial_write(b"ONE OS VM TEST NX FAULT MATCHED\n");
            return;
        }
    }

    report_exception(
        Some(14),
        "page fault",
        frame,
        Some(error_code),
        Some(fault_address),
    )
}

no_error_handler!(
    x87_floating_point_handler,
    16,
    "x87 floating-point exception"
);
error_handler!(alignment_check_handler, 17, "alignment check");
no_error_handler!(machine_check_handler, 18, "machine check");
no_error_handler!(
    simd_floating_point_handler,
    19,
    "SIMD floating-point exception"
);
no_error_handler!(virtualization_handler, 20, "virtualization exception");
error_handler!(
    control_protection_handler,
    21,
    "control-protection exception"
);
no_error_handler!(reserved_22_handler, 22, "reserved exception vector");
no_error_handler!(reserved_23_handler, 23, "reserved exception vector");
no_error_handler!(reserved_24_handler, 24, "reserved exception vector");
no_error_handler!(reserved_25_handler, 25, "reserved exception vector");
no_error_handler!(reserved_26_handler, 26, "reserved exception vector");
no_error_handler!(reserved_27_handler, 27, "reserved exception vector");
no_error_handler!(
    hypervisor_injection_handler,
    28,
    "hypervisor injection exception"
);
error_handler!(vmm_communication_handler, 29, "VMM communication exception");
error_handler!(security_exception_handler, 30, "security exception");
no_error_handler!(reserved_31_handler, 31, "reserved exception vector");
no_error_handler!(reserved_15_handler, 15, "reserved exception vector");

type InterruptHandler = extern "x86-interrupt" fn(InterruptStackFrame) -> !;

macro_rules! default_vector_handler {
    ($name:ident, $vector:expr) => {
        extern "x86-interrupt" fn $name(frame: InterruptStackFrame) -> ! {
            report_exception(
                Some($vector),
                "unexpected interrupt or exception",
                frame,
                None,
                None,
            )
        }
    };
}

default_vector_handler!(interrupt_32_handler, 32);
default_vector_handler!(interrupt_33_handler, 33);
default_vector_handler!(interrupt_34_handler, 34);
default_vector_handler!(interrupt_35_handler, 35);
default_vector_handler!(interrupt_36_handler, 36);
default_vector_handler!(interrupt_37_handler, 37);
default_vector_handler!(interrupt_38_handler, 38);
default_vector_handler!(interrupt_39_handler, 39);
default_vector_handler!(interrupt_40_handler, 40);
default_vector_handler!(interrupt_41_handler, 41);
default_vector_handler!(interrupt_42_handler, 42);
default_vector_handler!(interrupt_43_handler, 43);
default_vector_handler!(interrupt_44_handler, 44);
default_vector_handler!(interrupt_45_handler, 45);
default_vector_handler!(interrupt_46_handler, 46);
default_vector_handler!(interrupt_47_handler, 47);
default_vector_handler!(interrupt_48_handler, 48);
default_vector_handler!(interrupt_49_handler, 49);
default_vector_handler!(interrupt_50_handler, 50);
default_vector_handler!(interrupt_51_handler, 51);
default_vector_handler!(interrupt_52_handler, 52);
default_vector_handler!(interrupt_53_handler, 53);
default_vector_handler!(interrupt_54_handler, 54);
default_vector_handler!(interrupt_55_handler, 55);
default_vector_handler!(interrupt_56_handler, 56);
default_vector_handler!(interrupt_57_handler, 57);
default_vector_handler!(interrupt_58_handler, 58);
default_vector_handler!(interrupt_59_handler, 59);
default_vector_handler!(interrupt_60_handler, 60);
default_vector_handler!(interrupt_61_handler, 61);
default_vector_handler!(interrupt_62_handler, 62);
default_vector_handler!(interrupt_63_handler, 63);
default_vector_handler!(interrupt_64_handler, 64);
default_vector_handler!(interrupt_65_handler, 65);
default_vector_handler!(interrupt_66_handler, 66);
default_vector_handler!(interrupt_67_handler, 67);
default_vector_handler!(interrupt_68_handler, 68);
default_vector_handler!(interrupt_69_handler, 69);
default_vector_handler!(interrupt_70_handler, 70);
default_vector_handler!(interrupt_71_handler, 71);
default_vector_handler!(interrupt_72_handler, 72);
default_vector_handler!(interrupt_73_handler, 73);
default_vector_handler!(interrupt_74_handler, 74);
default_vector_handler!(interrupt_75_handler, 75);
default_vector_handler!(interrupt_76_handler, 76);
default_vector_handler!(interrupt_77_handler, 77);
default_vector_handler!(interrupt_78_handler, 78);
default_vector_handler!(interrupt_79_handler, 79);
default_vector_handler!(interrupt_80_handler, 80);
default_vector_handler!(interrupt_81_handler, 81);
default_vector_handler!(interrupt_82_handler, 82);
default_vector_handler!(interrupt_83_handler, 83);
default_vector_handler!(interrupt_84_handler, 84);
default_vector_handler!(interrupt_85_handler, 85);
default_vector_handler!(interrupt_86_handler, 86);
default_vector_handler!(interrupt_87_handler, 87);
default_vector_handler!(interrupt_88_handler, 88);
default_vector_handler!(interrupt_89_handler, 89);
default_vector_handler!(interrupt_90_handler, 90);
default_vector_handler!(interrupt_91_handler, 91);
default_vector_handler!(interrupt_92_handler, 92);
default_vector_handler!(interrupt_93_handler, 93);
default_vector_handler!(interrupt_94_handler, 94);
default_vector_handler!(interrupt_95_handler, 95);
default_vector_handler!(interrupt_96_handler, 96);
default_vector_handler!(interrupt_97_handler, 97);
default_vector_handler!(interrupt_98_handler, 98);
default_vector_handler!(interrupt_99_handler, 99);
default_vector_handler!(interrupt_100_handler, 100);
default_vector_handler!(interrupt_101_handler, 101);
default_vector_handler!(interrupt_102_handler, 102);
default_vector_handler!(interrupt_103_handler, 103);
default_vector_handler!(interrupt_104_handler, 104);
default_vector_handler!(interrupt_105_handler, 105);
default_vector_handler!(interrupt_106_handler, 106);
default_vector_handler!(interrupt_107_handler, 107);
default_vector_handler!(interrupt_108_handler, 108);
default_vector_handler!(interrupt_109_handler, 109);
default_vector_handler!(interrupt_110_handler, 110);
default_vector_handler!(interrupt_111_handler, 111);
default_vector_handler!(interrupt_112_handler, 112);
default_vector_handler!(interrupt_113_handler, 113);
default_vector_handler!(interrupt_114_handler, 114);
default_vector_handler!(interrupt_115_handler, 115);
default_vector_handler!(interrupt_116_handler, 116);
default_vector_handler!(interrupt_117_handler, 117);
default_vector_handler!(interrupt_118_handler, 118);
default_vector_handler!(interrupt_119_handler, 119);
default_vector_handler!(interrupt_120_handler, 120);
default_vector_handler!(interrupt_121_handler, 121);
default_vector_handler!(interrupt_122_handler, 122);
default_vector_handler!(interrupt_123_handler, 123);
default_vector_handler!(interrupt_124_handler, 124);
default_vector_handler!(interrupt_125_handler, 125);
default_vector_handler!(interrupt_126_handler, 126);
default_vector_handler!(interrupt_127_handler, 127);
default_vector_handler!(interrupt_128_handler, 128);
default_vector_handler!(interrupt_129_handler, 129);
default_vector_handler!(interrupt_130_handler, 130);
default_vector_handler!(interrupt_131_handler, 131);
default_vector_handler!(interrupt_132_handler, 132);
default_vector_handler!(interrupt_133_handler, 133);
default_vector_handler!(interrupt_134_handler, 134);
default_vector_handler!(interrupt_135_handler, 135);
default_vector_handler!(interrupt_136_handler, 136);
default_vector_handler!(interrupt_137_handler, 137);
default_vector_handler!(interrupt_138_handler, 138);
default_vector_handler!(interrupt_139_handler, 139);
default_vector_handler!(interrupt_140_handler, 140);
default_vector_handler!(interrupt_141_handler, 141);
default_vector_handler!(interrupt_142_handler, 142);
default_vector_handler!(interrupt_143_handler, 143);
default_vector_handler!(interrupt_144_handler, 144);
default_vector_handler!(interrupt_145_handler, 145);
default_vector_handler!(interrupt_146_handler, 146);
default_vector_handler!(interrupt_147_handler, 147);
default_vector_handler!(interrupt_148_handler, 148);
default_vector_handler!(interrupt_149_handler, 149);
default_vector_handler!(interrupt_150_handler, 150);
default_vector_handler!(interrupt_151_handler, 151);
default_vector_handler!(interrupt_152_handler, 152);
default_vector_handler!(interrupt_153_handler, 153);
default_vector_handler!(interrupt_154_handler, 154);
default_vector_handler!(interrupt_155_handler, 155);
default_vector_handler!(interrupt_156_handler, 156);
default_vector_handler!(interrupt_157_handler, 157);
default_vector_handler!(interrupt_158_handler, 158);
default_vector_handler!(interrupt_159_handler, 159);
default_vector_handler!(interrupt_160_handler, 160);
default_vector_handler!(interrupt_161_handler, 161);
default_vector_handler!(interrupt_162_handler, 162);
default_vector_handler!(interrupt_163_handler, 163);
default_vector_handler!(interrupt_164_handler, 164);
default_vector_handler!(interrupt_165_handler, 165);
default_vector_handler!(interrupt_166_handler, 166);
default_vector_handler!(interrupt_167_handler, 167);
default_vector_handler!(interrupt_168_handler, 168);
default_vector_handler!(interrupt_169_handler, 169);
default_vector_handler!(interrupt_170_handler, 170);
default_vector_handler!(interrupt_171_handler, 171);
default_vector_handler!(interrupt_172_handler, 172);
default_vector_handler!(interrupt_173_handler, 173);
default_vector_handler!(interrupt_174_handler, 174);
default_vector_handler!(interrupt_175_handler, 175);
default_vector_handler!(interrupt_176_handler, 176);
default_vector_handler!(interrupt_177_handler, 177);
default_vector_handler!(interrupt_178_handler, 178);
default_vector_handler!(interrupt_179_handler, 179);
default_vector_handler!(interrupt_180_handler, 180);
default_vector_handler!(interrupt_181_handler, 181);
default_vector_handler!(interrupt_182_handler, 182);
default_vector_handler!(interrupt_183_handler, 183);
default_vector_handler!(interrupt_184_handler, 184);
default_vector_handler!(interrupt_185_handler, 185);
default_vector_handler!(interrupt_186_handler, 186);
default_vector_handler!(interrupt_187_handler, 187);
default_vector_handler!(interrupt_188_handler, 188);
default_vector_handler!(interrupt_189_handler, 189);
default_vector_handler!(interrupt_190_handler, 190);
default_vector_handler!(interrupt_191_handler, 191);
default_vector_handler!(interrupt_192_handler, 192);
default_vector_handler!(interrupt_193_handler, 193);
default_vector_handler!(interrupt_194_handler, 194);
default_vector_handler!(interrupt_195_handler, 195);
default_vector_handler!(interrupt_196_handler, 196);
default_vector_handler!(interrupt_197_handler, 197);
default_vector_handler!(interrupt_198_handler, 198);
default_vector_handler!(interrupt_199_handler, 199);
default_vector_handler!(interrupt_200_handler, 200);
default_vector_handler!(interrupt_201_handler, 201);
default_vector_handler!(interrupt_202_handler, 202);
default_vector_handler!(interrupt_203_handler, 203);
default_vector_handler!(interrupt_204_handler, 204);
default_vector_handler!(interrupt_205_handler, 205);
default_vector_handler!(interrupt_206_handler, 206);
default_vector_handler!(interrupt_207_handler, 207);
default_vector_handler!(interrupt_208_handler, 208);
default_vector_handler!(interrupt_209_handler, 209);
default_vector_handler!(interrupt_210_handler, 210);
default_vector_handler!(interrupt_211_handler, 211);
default_vector_handler!(interrupt_212_handler, 212);
default_vector_handler!(interrupt_213_handler, 213);
default_vector_handler!(interrupt_214_handler, 214);
default_vector_handler!(interrupt_215_handler, 215);
default_vector_handler!(interrupt_216_handler, 216);
default_vector_handler!(interrupt_217_handler, 217);
default_vector_handler!(interrupt_218_handler, 218);
default_vector_handler!(interrupt_219_handler, 219);
default_vector_handler!(interrupt_220_handler, 220);
default_vector_handler!(interrupt_221_handler, 221);
default_vector_handler!(interrupt_222_handler, 222);
default_vector_handler!(interrupt_223_handler, 223);
default_vector_handler!(interrupt_224_handler, 224);
default_vector_handler!(interrupt_225_handler, 225);
default_vector_handler!(interrupt_226_handler, 226);
default_vector_handler!(interrupt_227_handler, 227);
default_vector_handler!(interrupt_228_handler, 228);
default_vector_handler!(interrupt_229_handler, 229);
default_vector_handler!(interrupt_230_handler, 230);
default_vector_handler!(interrupt_231_handler, 231);
default_vector_handler!(interrupt_232_handler, 232);
default_vector_handler!(interrupt_233_handler, 233);
default_vector_handler!(interrupt_234_handler, 234);
default_vector_handler!(interrupt_235_handler, 235);
default_vector_handler!(interrupt_236_handler, 236);
default_vector_handler!(interrupt_237_handler, 237);
default_vector_handler!(interrupt_238_handler, 238);
default_vector_handler!(interrupt_239_handler, 239);
default_vector_handler!(interrupt_240_handler, 240);
default_vector_handler!(interrupt_241_handler, 241);
default_vector_handler!(interrupt_242_handler, 242);
default_vector_handler!(interrupt_243_handler, 243);
default_vector_handler!(interrupt_244_handler, 244);
default_vector_handler!(interrupt_245_handler, 245);
default_vector_handler!(interrupt_246_handler, 246);
default_vector_handler!(interrupt_247_handler, 247);
default_vector_handler!(interrupt_248_handler, 248);
default_vector_handler!(interrupt_249_handler, 249);
default_vector_handler!(interrupt_250_handler, 250);
default_vector_handler!(interrupt_251_handler, 251);
default_vector_handler!(interrupt_252_handler, 252);
default_vector_handler!(interrupt_253_handler, 253);
default_vector_handler!(interrupt_254_handler, 254);
default_vector_handler!(interrupt_255_handler, 255);

const DEFAULT_INTERRUPT_HANDLERS: [InterruptHandler; 224] = [
    interrupt_32_handler,
    interrupt_33_handler,
    interrupt_34_handler,
    interrupt_35_handler,
    interrupt_36_handler,
    interrupt_37_handler,
    interrupt_38_handler,
    interrupt_39_handler,
    interrupt_40_handler,
    interrupt_41_handler,
    interrupt_42_handler,
    interrupt_43_handler,
    interrupt_44_handler,
    interrupt_45_handler,
    interrupt_46_handler,
    interrupt_47_handler,
    interrupt_48_handler,
    interrupt_49_handler,
    interrupt_50_handler,
    interrupt_51_handler,
    interrupt_52_handler,
    interrupt_53_handler,
    interrupt_54_handler,
    interrupt_55_handler,
    interrupt_56_handler,
    interrupt_57_handler,
    interrupt_58_handler,
    interrupt_59_handler,
    interrupt_60_handler,
    interrupt_61_handler,
    interrupt_62_handler,
    interrupt_63_handler,
    interrupt_64_handler,
    interrupt_65_handler,
    interrupt_66_handler,
    interrupt_67_handler,
    interrupt_68_handler,
    interrupt_69_handler,
    interrupt_70_handler,
    interrupt_71_handler,
    interrupt_72_handler,
    interrupt_73_handler,
    interrupt_74_handler,
    interrupt_75_handler,
    interrupt_76_handler,
    interrupt_77_handler,
    interrupt_78_handler,
    interrupt_79_handler,
    interrupt_80_handler,
    interrupt_81_handler,
    interrupt_82_handler,
    interrupt_83_handler,
    interrupt_84_handler,
    interrupt_85_handler,
    interrupt_86_handler,
    interrupt_87_handler,
    interrupt_88_handler,
    interrupt_89_handler,
    interrupt_90_handler,
    interrupt_91_handler,
    interrupt_92_handler,
    interrupt_93_handler,
    interrupt_94_handler,
    interrupt_95_handler,
    interrupt_96_handler,
    interrupt_97_handler,
    interrupt_98_handler,
    interrupt_99_handler,
    interrupt_100_handler,
    interrupt_101_handler,
    interrupt_102_handler,
    interrupt_103_handler,
    interrupt_104_handler,
    interrupt_105_handler,
    interrupt_106_handler,
    interrupt_107_handler,
    interrupt_108_handler,
    interrupt_109_handler,
    interrupt_110_handler,
    interrupt_111_handler,
    interrupt_112_handler,
    interrupt_113_handler,
    interrupt_114_handler,
    interrupt_115_handler,
    interrupt_116_handler,
    interrupt_117_handler,
    interrupt_118_handler,
    interrupt_119_handler,
    interrupt_120_handler,
    interrupt_121_handler,
    interrupt_122_handler,
    interrupt_123_handler,
    interrupt_124_handler,
    interrupt_125_handler,
    interrupt_126_handler,
    interrupt_127_handler,
    interrupt_128_handler,
    interrupt_129_handler,
    interrupt_130_handler,
    interrupt_131_handler,
    interrupt_132_handler,
    interrupt_133_handler,
    interrupt_134_handler,
    interrupt_135_handler,
    interrupt_136_handler,
    interrupt_137_handler,
    interrupt_138_handler,
    interrupt_139_handler,
    interrupt_140_handler,
    interrupt_141_handler,
    interrupt_142_handler,
    interrupt_143_handler,
    interrupt_144_handler,
    interrupt_145_handler,
    interrupt_146_handler,
    interrupt_147_handler,
    interrupt_148_handler,
    interrupt_149_handler,
    interrupt_150_handler,
    interrupt_151_handler,
    interrupt_152_handler,
    interrupt_153_handler,
    interrupt_154_handler,
    interrupt_155_handler,
    interrupt_156_handler,
    interrupt_157_handler,
    interrupt_158_handler,
    interrupt_159_handler,
    interrupt_160_handler,
    interrupt_161_handler,
    interrupt_162_handler,
    interrupt_163_handler,
    interrupt_164_handler,
    interrupt_165_handler,
    interrupt_166_handler,
    interrupt_167_handler,
    interrupt_168_handler,
    interrupt_169_handler,
    interrupt_170_handler,
    interrupt_171_handler,
    interrupt_172_handler,
    interrupt_173_handler,
    interrupt_174_handler,
    interrupt_175_handler,
    interrupt_176_handler,
    interrupt_177_handler,
    interrupt_178_handler,
    interrupt_179_handler,
    interrupt_180_handler,
    interrupt_181_handler,
    interrupt_182_handler,
    interrupt_183_handler,
    interrupt_184_handler,
    interrupt_185_handler,
    interrupt_186_handler,
    interrupt_187_handler,
    interrupt_188_handler,
    interrupt_189_handler,
    interrupt_190_handler,
    interrupt_191_handler,
    interrupt_192_handler,
    interrupt_193_handler,
    interrupt_194_handler,
    interrupt_195_handler,
    interrupt_196_handler,
    interrupt_197_handler,
    interrupt_198_handler,
    interrupt_199_handler,
    interrupt_200_handler,
    interrupt_201_handler,
    interrupt_202_handler,
    interrupt_203_handler,
    interrupt_204_handler,
    interrupt_205_handler,
    interrupt_206_handler,
    interrupt_207_handler,
    interrupt_208_handler,
    interrupt_209_handler,
    interrupt_210_handler,
    interrupt_211_handler,
    interrupt_212_handler,
    interrupt_213_handler,
    interrupt_214_handler,
    interrupt_215_handler,
    interrupt_216_handler,
    interrupt_217_handler,
    interrupt_218_handler,
    interrupt_219_handler,
    interrupt_220_handler,
    interrupt_221_handler,
    interrupt_222_handler,
    interrupt_223_handler,
    interrupt_224_handler,
    interrupt_225_handler,
    interrupt_226_handler,
    interrupt_227_handler,
    interrupt_228_handler,
    interrupt_229_handler,
    interrupt_230_handler,
    interrupt_231_handler,
    interrupt_232_handler,
    interrupt_233_handler,
    interrupt_234_handler,
    interrupt_235_handler,
    interrupt_236_handler,
    interrupt_237_handler,
    interrupt_238_handler,
    interrupt_239_handler,
    interrupt_240_handler,
    interrupt_241_handler,
    interrupt_242_handler,
    interrupt_243_handler,
    interrupt_244_handler,
    interrupt_245_handler,
    interrupt_246_handler,
    interrupt_247_handler,
    interrupt_248_handler,
    interrupt_249_handler,
    interrupt_250_handler,
    interrupt_251_handler,
    interrupt_252_handler,
    interrupt_253_handler,
    interrupt_254_handler,
    interrupt_255_handler,
];

/// Installs an interrupt gate for the specified vector.
///
/// # Safety
///
/// The vector must be in range and the handler must use the ABI expected by
/// the processor for that vector's stack frame.
unsafe fn install_gate(vector: usize, handler: usize, selector: u16) {
    // SAFETY: callers install a valid vector before this IDT is loaded.
    unsafe { install_gate_with_ist(vector, handler, selector, 0) };
}

/// Installs an interrupt gate using the requested 1-based IST stack index.
///
/// # Safety
///
/// The vector must be in range, the handler must use the processor's stack
/// frame ABI for that vector, and a non-zero IST index must name a configured
/// TSS stack.
unsafe fn install_gate_with_ist(vector: usize, handler: usize, selector: u16, ist: u8) {
    let entry = IdtEntry::new(handler, selector, ist);
    // SAFETY: the caller supplies a valid vector and a valid handler/IST pair.
    unsafe {
        ptr::addr_of_mut!(IDT)
            .cast::<IdtEntry>()
            .add(vector)
            .write(entry);
    }
}

/// Installs the current GDT plus a TSS descriptor and configures the dedicated
/// double-fault IST stack.
///
/// The current GDT entries are copied unchanged so the bootloader-provided CS
/// selector and all existing selectors retain their descriptor indices.
fn initialize_tss_and_gdt() {
    let mut old_gdtr = Gdtr { limit: 0, base: 0 };
    // SAFETY: SGDT writes the active descriptor-table pointer into this buffer.
    unsafe {
        asm!(
            "sgdt [{}]",
            in(reg) ptr::addr_of_mut!(old_gdtr),
            options(nostack, preserves_flags)
        );
    }
    // These fields are packed, so read them without creating aligned references.
    let old_limit = unsafe { ptr::addr_of!(old_gdtr.limit).read_unaligned() };
    let old_base = unsafe { ptr::addr_of!(old_gdtr.base).read_unaligned() };
    let old_bytes = usize::from(old_limit) + 1;

    if old_bytes % size_of::<u64>() != 0 {
        super::serial_write(b"ONE OS TSS INIT FAILED: unaligned GDT limit\n");
        super::halt_forever();
    }
    let old_entries = old_bytes / size_of::<u64>();
    if old_entries == 0 || old_entries + 2 > MAX_GDT_ENTRIES {
        super::serial_write(b"ONE OS TSS INIT FAILED: GDT exceeds bootstrap capacity\n");
        super::halt_forever();
    }

    let gdt_base = ptr::addr_of_mut!(GDT).cast::<u64>();
    let tss_pointer = ptr::addr_of_mut!(TSS);
    // SAFETY: bootstrap runs single-core with the bootloader GDT mapped and
    // accessible. We preserve its descriptors and append two TSS descriptor
    // slots into our writable, statically allocated GDT.
    unsafe {
        ptr::copy_nonoverlapping(old_base as *const u8, gdt_base.cast::<u8>(), old_bytes);

        let stack_base = ptr::addr_of_mut!(DOUBLE_FAULT_STACK).cast::<u8>();
        let stack_top = stack_base.add(size_of::<DoubleFaultStack>()) as u64;
        ptr::addr_of_mut!((*tss_pointer).ist[0]).write_unaligned(stack_top);

        let tss_base = tss_pointer as u64;
        let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;
        // 64-bit available TSS descriptor (type 0x9, present, DPL 0).
        let descriptor_low = (tss_limit & 0xffff)
            | ((tss_base & 0x00ff_ffff) << 16)
            | (0x9 << 40)
            | (1 << 47)
            | ((tss_limit & 0x000f_0000) << 32)
            | ((tss_base & 0xff00_0000) << 32);
        let descriptor_high = tss_base >> 32;
        gdt_base.add(old_entries).write(descriptor_low);
        gdt_base.add(old_entries + 1).write(descriptor_high);
    }

    let tss_selector = (old_entries << 3) as u16;
    let new_gdtr = Gdtr {
        limit: ((old_entries + 2) * size_of::<u64>() - 1) as u16,
        base: gdt_base as u64,
    };
    // SAFETY: the new GDT retains the previous descriptors and contains a valid
    // 64-bit TSS descriptor. LTR marks the descriptor busy as required.
    unsafe {
        asm!(
            "lgdt [{}]",
            in(reg) ptr::addr_of!(new_gdtr),
            options(readonly, nostack, preserves_flags)
        );
        asm!("ltr {0:x}", in(reg) tss_selector, options(nostack, preserves_flags));
    }
}

/// Installs exception gates and safe fail-stop defaults for other vectors.
///
/// # Safety
///
/// Call exactly once during single-core bootstrap, before any code enables
/// external interrupts. This function replaces the active GDT and IDT and
/// loads the task register with the bootstrap TSS.
pub unsafe fn init() {
    initialize_tss_and_gdt();

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
                .write(IdtEntry::new(default_handler, selector, 0));
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
        install_gate_with_ist(
            8,
            double_fault_handler as *const () as usize,
            selector,
            DOUBLE_FAULT_IST_INDEX,
        );
        install!(9, coprocessor_segment_handler);
        install!(10, invalid_tss_handler);
        install!(11, segment_not_present_handler);
        install!(12, stack_segment_fault_handler);
        install!(13, general_protection_handler);
        install!(14, page_fault_handler);
        install!(15, reserved_15_handler);
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
        install!(28, hypervisor_injection_handler);
        install!(29, vmm_communication_handler);
        install!(30, security_exception_handler);
        install!(31, reserved_31_handler);

        for (offset, handler) in DEFAULT_INTERRUPT_HANDLERS.iter().enumerate() {
            install_gate(32 + offset, *handler as *const () as usize, selector);
        }

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

pub(super) fn write_hex(label: &[u8], value: u64) {
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
