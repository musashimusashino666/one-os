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
    feature = "test-nx-protection",
    feature = "test-vm-transitions",
    feature = "test-wx-runtime-audit"
))]
use core::arch::global_asm;
use core::panic::PanicInfo;
use oneos_core::{validate_memory_map, FrameWxAuditSource, MemoryMapError};

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
    ),
    all(
        feature = "test-vm-transitions",
        any(
            feature = "test-exception",
            feature = "test-general-protection",
            feature = "test-page-fault",
            feature = "test-double-fault",
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection",
            feature = "test-ist"
        )
    ),
    all(
        feature = "test-ist",
        any(
            feature = "test-exception",
            feature = "test-general-protection",
            feature = "test-page-fault",
            feature = "test-double-fault",
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection",
            feature = "test-vm-transitions"
        )
    ),
    all(
        feature = "test-wx-runtime-audit",
        any(
            feature = "test-exception",
            feature = "test-general-protection",
            feature = "test-page-fault",
            feature = "test-double-fault",
            feature = "test-ist",
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection",
            feature = "test-vm-transitions",
            feature = "test-root-leak-safety"
        )
    )
))]
compile_error!("enable only one exception fault-injection feature at a time");

#[cfg(any(
    all(
        feature = "test-cr3-switch-guard",
        feature = "test-cr3-activation-guard"
    ),
    all(feature = "test-cr3-switch-guard", feature = "test-exception"),
    all(feature = "test-cr3-switch-guard", feature = "test-general-protection"),
    all(feature = "test-cr3-switch-guard", feature = "test-page-fault"),
    all(feature = "test-cr3-switch-guard", feature = "test-double-fault"),
    all(feature = "test-cr3-switch-guard", feature = "test-ist"),
    all(
        feature = "test-cr3-switch-guard",
        feature = "test-supervisor-write-protection"
    ),
    all(feature = "test-cr3-switch-guard", feature = "test-nx-protection"),
    all(feature = "test-cr3-switch-guard", feature = "test-vm-transitions"),
    all(feature = "test-cr3-switch-guard", feature = "test-root-leak-safety"),
    all(feature = "test-cr3-switch-guard", feature = "test-wx-runtime-audit"),
    all(feature = "test-cr3-switch-guard", feature = "test-nmi-wx-transition"),
    all(feature = "test-cr3-activation-guard", feature = "test-exception"),
    all(
        feature = "test-cr3-activation-guard",
        feature = "test-general-protection"
    ),
    all(feature = "test-cr3-activation-guard", feature = "test-page-fault"),
    all(feature = "test-cr3-activation-guard", feature = "test-double-fault"),
    all(feature = "test-cr3-activation-guard", feature = "test-ist"),
    all(
        feature = "test-cr3-activation-guard",
        feature = "test-supervisor-write-protection"
    ),
    all(feature = "test-cr3-activation-guard", feature = "test-nx-protection"),
    all(feature = "test-cr3-activation-guard", feature = "test-vm-transitions"),
    all(
        feature = "test-cr3-activation-guard",
        feature = "test-root-leak-safety"
    ),
    all(
        feature = "test-cr3-activation-guard",
        feature = "test-wx-runtime-audit"
    ),
    all(
        feature = "test-cr3-activation-guard",
        feature = "test-nmi-wx-transition"
    )
))]
compile_error!("CR3 guard acceptance features must be built individually");

#[cfg(all(
    feature = "test-nmi-wx-transition",
    any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault",
        feature = "test-double-fault",
        feature = "test-ist",
        feature = "test-supervisor-write-protection",
        feature = "test-nx-protection",
        feature = "test-vm-transitions",
        feature = "test-root-leak-safety",
        feature = "test-wx-runtime-audit"
    )
))]
compile_error!("test-nmi-wx-transition must be enabled by itself");

mod address_space;
mod interrupts;
mod memory;
mod paging;

const COM1: u16 = 0x3F8;

const KERNEL_VIRTUAL_BASE: u64 = 0xffff_8000_0000_0000;
const DYNAMIC_KERNEL_MAPPING_START: u64 = 0xffff_9000_0000_0000;
const DYNAMIC_KERNEL_MAPPING_END: u64 = 0xffff_ffff_ffff_f000;

pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    // Place the kernel and every bootloader-created dynamic mapping in the
    // upper canonical half, where future process roots can share them with
    // supervisor-only PML4 ancestors.
    config.mappings.kernel_base = Mapping::FixedAddress(KERNEL_VIRTUAL_BASE);
    config.mappings.dynamic_range_start = Some(DYNAMIC_KERNEL_MAPPING_START);
    config.mappings.dynamic_range_end = Some(DYNAMIC_KERNEL_MAPPING_END);
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
    "jmp rax",
    "oneos_vm_test_nx_recovery:",
    "ret",
);

#[cfg(feature = "test-nx-protection")]
unsafe extern "C" {
    fn oneos_vm_test_nx_execute(target: u64);
    static oneos_vm_test_nx_recovery: u8;
}

#[cfg(feature = "test-vm-transitions")]
global_asm!(
    ".global oneos_vm_test_transition_first_read",
    ".global oneos_vm_test_transition_first_fault_ip",
    ".global oneos_vm_test_transition_first_recovery",
    ".global oneos_vm_test_transition_second_read",
    ".global oneos_vm_test_transition_second_fault_ip",
    ".global oneos_vm_test_transition_second_recovery",
    "oneos_vm_test_transition_first_read:",
    "mov rax, rdi",
    "oneos_vm_test_transition_first_fault_ip:",
    "mov rax, qword ptr [rax]",
    "oneos_vm_test_transition_first_recovery:",
    "ret",
    "oneos_vm_test_transition_second_read:",
    "mov rax, rdi",
    "oneos_vm_test_transition_second_fault_ip:",
    "mov rax, qword ptr [rax]",
    "oneos_vm_test_transition_second_recovery:",
    "ret",
);

#[cfg(feature = "test-vm-transitions")]
unsafe extern "C" {
    fn oneos_vm_test_transition_first_read(target: u64);
    fn oneos_vm_test_transition_second_read(target: u64);
    static oneos_vm_test_transition_first_fault_ip: u8;
    static oneos_vm_test_transition_first_recovery: u8;
    static oneos_vm_test_transition_second_fault_ip: u8;
    static oneos_vm_test_transition_second_recovery: u8;
}

#[cfg(feature = "test-wx-runtime-audit")]
global_asm!(
    ".global oneos_vm_test_wx_directmap_write",
    ".global oneos_vm_test_wx_directmap_fault_ip",
    ".global oneos_vm_test_wx_directmap_recovery",
    "oneos_vm_test_wx_directmap_write:",
    "mov rax, rdi",
    "mov rdx, rsi",
    "oneos_vm_test_wx_directmap_fault_ip:",
    "mov qword ptr [rax], rdx",
    "oneos_vm_test_wx_directmap_recovery:",
    "ret",
);

#[cfg(feature = "test-wx-runtime-audit")]
unsafe extern "C" {
    fn oneos_vm_test_wx_directmap_write(target: u64, value: u64);
    static oneos_vm_test_wx_directmap_fault_ip: u8;
    static oneos_vm_test_wx_directmap_recovery: u8;
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

    // SAFETY: bootstrap is single-core; init verifies that maskable interrupts
    // are disabled, validates the current RSP against BootInfo's stack interval,
    // and fails closed if the one-time IDT/TSS/GDT setup is repeated.
    unsafe { interrupts::init(boot_info.kernel_stack_bottom, boot_info.kernel_stack_len) };

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

    if let Err(error) = paging::initialize_paging_controls() {
        serial_write(b"\nONE OS PAGING CONTROL INITIALIZATION FAILED\n");
        serial_write(error.message());
        halt_forever()
    }

    // Inspect and permanently reserve every PT_LOAD frame before the first
    // allocation. Some loader-created frames can reside in Usable map regions.
    let paging_stats = match paging::inspect_boot_mappings(boot_info) {
        Ok(stats) => stats,
        Err(error) => {
            serial_write(b"\nONE OS PAGING INSPECTION FAILED\n");
            serial_write(error.message());
            halt_forever()
        }
    };

    // The bootloader may place writable PT_LOAD pages far from executable code.
    // The dedicated test therefore allocates an owned RX test frame and a writable
    // sibling frame in a controlled 2 MiB physical region with an original large leaf.
    #[cfg(feature = "test-wx-runtime-audit")]
    let mut wx_sibling_test = match paging::verify_wx_sibling_large_page_precondition(boot_info) {
        Ok(test) => test,
        Err(error) => {
            serial_write(b"\nONE OS W^X LARGE-PAGE PRECONDITION FAILED\n");
            serial_write(error.message());
            halt_forever()
        }
    };
    #[cfg(feature = "test-wx-runtime-audit")]
    {
        interrupts::write_hex(
            b"ONE OS W^X TEST EXECUTABLE PHYSICAL PAGE: ",
            wx_sibling_test.executable_physical_page,
        );
        interrupts::write_hex(
            b"ONE OS W^X SIBLING DATA FRAME PHYSICAL: ",
            wx_sibling_test.sibling_physical_page,
        );
        interrupts::write_hex(
            b"ONE OS W^X SIBLING PHYSICAL REGION START: ",
            wx_sibling_test.executable_physical_page & !((1u64 << 21) - 1),
        );
        interrupts::write_hex(
            b"ONE OS W^X SIBLING PHYSICAL REGION END: ",
            (wx_sibling_test.executable_physical_page & !((1u64 << 21) - 1)) + (1u64 << 21),
        );
        interrupts::write_hex(
            b"ONE OS W^X SIBLING ORIGINAL DIRECT-MAP LARGE PAGE: ",
            wx_sibling_test.original_large_page_size,
        );
        serial_write(b"ONE OS W^X SIBLING PRE-DEMOTION LARGE PAGE PASS\n");
    }

    // Exercise both allocation and release only after loaded kernel frames
    // have been excluded from the allocator bitmap.
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

    serial_write(b"ONE OS PAGE TABLE INSPECTION READY\n");
    interrupts::write_hex(
        b"Current PML4 physical address: ",
        paging_stats.root_table_physical,
    );
    interrupts::write_hex(
        b"Validated bootstrap mappings: ",
        paging_stats.validated_mappings as u64,
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT ALIAS MAPPINGS: ",
        paging_stats.wx_audit.tracked_alias_mappings,
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT TRACKED RANGES: ",
        paging_stats.wx_audit.tracked_ranges as u64,
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT CONFLICT EVENTS: ",
        paging_stats.wx_audit.conflicting_overlap_events,
    );
    serial_write(b"ONE OS DIRECT-MAP COVERAGE: COMPLETE FOR DECLARED MEMORY RANGE\n");
    interrupts::write_hex(
        b"ONE OS DIRECT-MAP VIRTUAL OFFSET: ",
        paging_stats.wx_direct_map_coverage.virtual_offset,
    );
    interrupts::write_hex(
        b"ONE OS DIRECT-MAP PHYSICAL END: ",
        paging_stats.wx_direct_map_coverage.physical_end,
    );
    interrupts::write_hex(
        b"ONE OS DIRECT-MAP COVERED VIRTUAL END: ",
        paging_stats.wx_direct_map_coverage.covered_virtual_end,
    );
    interrupts::write_hex(
        b"ONE OS DIRECT-MAP COVERED LEAF MAPPINGS: ",
        paging_stats.wx_direct_map_coverage.covered_leaf_mappings,
    );
    serial_write(b"ONE OS W^X ALIAS WALK FINISHED (DECLARED ROOTS)\n");
    interrupts::write_hex(
        b"ONE OS W^X AUDIT ROOT INVENTORY SEALED: ",
        if paging_stats.wx_audit_scope.root_inventory_sealed {
            1
        } else {
            0
        },
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT ROOTS DECLARED: ",
        paging_stats.wx_audit_scope.declared_roots as u64,
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT ROOTS WALKED: ",
        paging_stats.wx_audit_scope.audited_roots as u64,
    );
    for root in
        paging_stats.wx_audit_scope.roots[..paging_stats.wx_audit_scope.declared_roots].iter()
    {
        interrupts::write_hex(b"ONE OS W^X AUDIT ROOT PHYSICAL: ", root.physical_address);
        interrupts::write_hex(
            b"ONE OS W^X AUDIT ROOT COMPLETE: ",
            if root.audited { 1 } else { 0 },
        );
    }
    interrupts::write_hex(
        b"ONE OS W^X AUDIT ACCOUNTED SOURCE MASK: ",
        paging_stats.wx_audit_scope.accounted_sources as u64,
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT DIRECT MAP SOURCE ACCOUNTED: ",
        if paging_stats.wx_audit_scope.accounted_sources
            & FrameWxAuditSource::PhysicalMemoryOffsetAlias.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT RECURSIVE VIEW SOURCE ACCOUNTED: ",
        if paging_stats.wx_audit_scope.accounted_sources
            & FrameWxAuditSource::RecursivePageTableView.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT SHARED KERNEL SOURCE ACCOUNTED: ",
        if paging_stats.wx_audit_scope.accounted_sources
            & FrameWxAuditSource::SharedKernelMappings.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT LARGE PAGE SOURCE ACCOUNTED: ",
        if paging_stats.wx_audit_scope.accounted_sources
            & FrameWxAuditSource::LargePageLeaves.mask()
            != 0
        {
            1
        } else {
            0
        },
    );
    interrupts::write_hex(
        b"ONE OS W^X AUDIT MISSING SOURCE MASK: ",
        paging_stats.wx_audit_scope.missing_sources as u64,
    );
    if !paging_stats.wx_audit_scope.complete {
        serial_write(b"ONE OS W^X GLOBAL COVERAGE INCOMPLETE\n");
    }
    if paging_stats.wx_audit.conflicting_overlap_events > 0 {
        serial_write(b"ONE OS W^X PRE-ACTIVATION READ-ONLY AUDIT DETECTED OVERLAPS\n");
        if let Some(conflict) = paging_stats.wx_audit.first_conflict {
            print_wx_conflict_diagnostic(0, conflict);
        }
    }

    if let Err(error) = paging::verify_mapping_smoke_test(boot_info) {
        serial_write(b"\nONE OS PAGING MUTATION FAILED\n");
        serial_write(error.message());
        halt_forever()
    }
    serial_write(b"ONE OS VM MAPPING SMOKE TEST READY\n");

    // Exercise the live large-page demotion transaction on the normal boot only.
    // Dedicated fault/TLB acceptance images retain their isolated setup and exact
    // fault/log contracts; the regular three-boot CI path validates this editor
    // integration against the bootloader's physical-memory-offset large leaves.
    #[cfg(not(any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault",
        feature = "test-double-fault",
        feature = "test-ist",
        feature = "test-supervisor-write-protection",
        feature = "test-nx-protection",
        feature = "test-vm-transitions",
        feature = "test-root-leak-safety",
        feature = "test-wx-runtime-audit",
        feature = "test-nmi-wx-transition",
        feature = "test-cr3-switch-guard",
        feature = "test-cr3-activation-guard"
    )))]
    {
        match paging::verify_large_page_demotion_smoke_test(boot_info) {
            Ok(true) => serial_write(b"ONE OS LARGE PAGE DEMOTION SMOKE TEST READY\n"),
            Ok(false) => serial_write(
                b"ONE OS LARGE PAGE DEMOTION SMOKE TEST SKIPPED (DIRECT MAP ALREADY 4K)\n",
            ),
            Err(error) => {
                serial_write(b"\nONE OS LARGE PAGE DEMOTION SMOKE TEST FAILED\n");
                serial_write(error.message());
                halt_forever()
            }
        }
    }

    // Restrict every validated executable PT_LOAD frame's physical-offset alias
    // before a private kernel root is constructed. The later post-activation audit
    // verifies that the shared upper-half aliases are conflict-free across roots.
    #[cfg(not(any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault",
        feature = "test-double-fault",
        feature = "test-ist",
        feature = "test-supervisor-write-protection",
        feature = "test-nx-protection",
        feature = "test-vm-transitions",
        feature = "test-root-leak-safety",
        feature = "test-cr3-switch-guard",
        feature = "test-cr3-activation-guard"
    )))]
    {
        let executable_pages = match paging::enforce_kernel_executable_alias_wx(boot_info) {
            Ok(count) => count,
            Err(error) => {
                serial_write(b"\nONE OS KERNEL W^X DIRECT-MAP TRANSITION FAILED\n");
                serial_write(error.message());
                halt_forever()
            }
        };
        interrupts::write_hex(
            b"ONE OS KERNEL W^X EXECUTABLE PAGES CHECKED: ",
            executable_pages as u64,
        );
        serial_write(b"ONE OS KERNEL W^X DIRECT-MAP TRANSITION PASS\n");
    }

    #[cfg(feature = "test-wx-runtime-audit")]
    if let Err(error) = paging::apply_wx_sibling_test_transition(boot_info, &mut wx_sibling_test) {
        serial_write(b"\nONE OS W^X SIBLING DEMOTION SETUP FAILED\n");
        serial_write(error.message());
        halt_forever()
    }

    if let Err(error) = address_space::verify_root_initialization_smoke_test(boot_info) {
        serial_write(b"\nONE OS ADDRESS SPACE ROOT INITIALIZATION FAILED\n");
        serial_write(error.message());
        halt_forever()
    }
    serial_write(b"ONE OS ADDRESS SPACE ROOT INITIALIZATION READY\n");

    #[cfg(feature = "test-vm-transitions")]
    serial_write(b"ONE OS VM TEST: mapping-transitions\n");

    // Dedicated acceptance images remain on the bootloader root. They must
    // exercise this path before their test-specific control flow; normal boot
    // repeats it after activating the private kernel root.
    #[cfg(any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault",
        feature = "test-double-fault",
        feature = "test-ist",
        feature = "test-supervisor-write-protection",
        feature = "test-nx-protection",
        feature = "test-vm-transitions"
    ))]
    {
        if let Err(error) = paging::verify_user_frame_zeroing_test(boot_info) {
            serial_write(b"ONE OS USER FRAME ZERO TEST FAILED\n");
            serial_write(error.message());
            halt_forever()
        }
    }

    #[cfg(feature = "test-vm-transitions")]
    {
        let mut transition = match paging::prepare_mapping_transition_test(boot_info) {
            Ok(test) => test,
            Err(error) => {
                serial_write(b"ONE OS VM TEST FAILED: transition setup\n");
                serial_write(error.message());
                halt_forever()
            }
        };
        let first_fault_ip =
            unsafe { core::ptr::addr_of!(oneos_vm_test_transition_first_fault_ip) as u64 };
        let first_recovery_ip =
            unsafe { core::ptr::addr_of!(oneos_vm_test_transition_first_recovery) as u64 };
        let second_fault_ip =
            unsafe { core::ptr::addr_of!(oneos_vm_test_transition_second_fault_ip) as u64 };
        let second_recovery_ip =
            unsafe { core::ptr::addr_of!(oneos_vm_test_transition_second_recovery) as u64 };
        interrupts::write_hex(b"ONE OS VM TRANSITION TARGET: ", transition.virtual_address);
        interrupts::write_hex(
            b"ONE OS VM TRANSITION FIRST FRAME: ",
            transition.first_physical_address,
        );
        interrupts::write_hex(
            b"ONE OS VM TRANSITION SECOND FRAME: ",
            transition.second_physical_address,
        );
        interrupts::write_hex(b"ONE OS VM TRANSITION FIRST EXPECTED RIP: ", first_fault_ip);
        interrupts::write_hex(
            b"ONE OS VM TRANSITION SECOND EXPECTED RIP: ",
            second_fault_ip,
        );

        interrupts::arm_expected_transition_page_fault(
            transition.virtual_address,
            first_fault_ip,
            first_recovery_ip,
            1,
        );
        // SAFETY: the dedicated assembly helper performs exactly one load from
        // an address which setup confirmed is not present. The handler only
        // resumes this exact fault at its paired recovery label.
        unsafe { oneos_vm_test_transition_first_read(transition.virtual_address) };
        if !interrupts::transition_page_fault_was_seen(1) {
            serial_write(b"ONE OS VM TEST FAILED: initial not-present fault did not recover\n");
            halt_forever()
        }
        serial_write(b"ONE OS VM TRANSITION RECOVERY VERIFIED: initial-unmapped\n");

        if let Err(error) = transition.map_first(boot_info) {
            serial_write(b"ONE OS VM TEST FAILED: first map\n");
            serial_write(error.message());
            halt_forever()
        }
        if let Err(error) = transition.verify_first(boot_info) {
            serial_write(b"ONE OS VM TEST FAILED: first mapping access\n");
            serial_write(error.message());
            halt_forever()
        }
        serial_write(b"ONE OS VM TRANSITION FIRST MAPPING VERIFIED\n");
        if let Err(error) = transition.unmap_first(boot_info) {
            serial_write(b"ONE OS VM TEST FAILED: first unmap\n");
            serial_write(error.message());
            halt_forever()
        }

        interrupts::arm_expected_transition_page_fault(
            transition.virtual_address,
            second_fault_ip,
            second_recovery_ip,
            2,
        );
        // SAFETY: this load must fault after the first mapping was removed and
        // its local TLB entry invalidated. Only its exact fault can recover.
        unsafe { oneos_vm_test_transition_second_read(transition.virtual_address) };
        if !interrupts::transition_page_fault_was_seen(2) {
            serial_write(b"ONE OS VM TEST FAILED: post-unmap fault did not recover\n");
            halt_forever()
        }
        serial_write(b"ONE OS VM TRANSITION RECOVERY VERIFIED: after-unmap\n");

        if let Err(error) = transition.map_second(boot_info) {
            serial_write(b"ONE OS VM TEST FAILED: remap second frame\n");
            serial_write(error.message());
            halt_forever()
        }
        if let Err(error) = transition.verify_second(boot_info) {
            serial_write(b"ONE OS VM TEST FAILED: stale TLB or second-frame mismatch\n");
            serial_write(error.message());
            halt_forever()
        }
        serial_write(b"ONE OS VM TRANSITION REMAP SECOND FRAME VERIFIED\n");
        if let Err(error) = transition.unmap_second(boot_info) {
            serial_write(b"ONE OS VM TEST FAILED: second unmap\n");
            serial_write(error.message());
            halt_forever()
        }
        if let Err(error) = transition.finish() {
            serial_write(b"ONE OS VM TEST FAILED: release transition frames\n");
            serial_write(error.message());
            halt_forever()
        }

        serial_write(b"ONE OS VM TEST PASS: mapping-transitions\n");
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

    #[cfg(feature = "test-ist")]
    {
        serial_write(b"ONE OS IST TEST: triggering vector 2 through software INT\n");
        // SAFETY: CPL0 may invoke this ring-0 IDT gate. The test handler returns
        // only after recording whether its live RSP is inside the TSS.IST2 stack.
        unsafe {
            asm!("int 2");
        }
        if !interrupts::test_nmi_ist_passed() {
            serial_write(b"ONE OS IST TEST FAILED: vector 2 did not use the NMI IST stack\n");
            halt_forever()
        }
        serial_write(b"ONE OS IST TEST PASS: NMI IST2 stack selection verified\n");

        serial_write(b"ONE OS IST TEST: triggering vector 18 through software INT\n");
        // SAFETY: CPL0 may invoke the ring-0 vector-18 IDT gate. This validates
        // IST3 selection only; it does not simulate a hardware machine-check event.
        unsafe {
            asm!("int 18");
        }
        if !interrupts::test_machine_check_ist_passed() {
            serial_write(
                b"ONE OS IST TEST FAILED: vector 18 did not use the machine-check IST stack\n",
            );
            halt_forever()
        }
        serial_write(b"ONE OS IST TEST PASS: Machine Check IST3 stack selection verified\n");

        // isa-debug-exit maps value 0x10 to process status 33; CI requires that
        // status as well as both per-handler stack-range checks above.
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

    #[cfg(feature = "test-cr3-activation-guard")]
    {
        const PASS: &[u8] = b"ONE OS CR3 INITIAL ACTIVATION UNREGISTERED ROOT REJECT PASS\n";
        const FAIL: &[u8] = b"ONE OS CR3 INITIAL ACTIVATION UNREGISTERED ROOT REJECT FAIL\n";
        match address_space::activate_supervisor_kernel_root(boot_info) {
            Err(address_space::AddressSpaceError::RootNotRegistered)
                if address_space::cr3_activation_guard_test_passed() =>
            {
                address_space::cr3_guard_test_exit(true, PASS, FAIL)
            }
            _ => address_space::cr3_guard_test_exit(false, PASS, FAIL),
        }
    }

    #[cfg(not(any(
        feature = "test-exception",
        feature = "test-general-protection",
        feature = "test-page-fault",
        feature = "test-double-fault",
        feature = "test-ist",
        feature = "test-cr3-activation-guard"
    )))]
    {
        // Only the normal boot path activates a second root. All existing
        // mutation/protection acceptance images retain the bootloader root so
        // their diagnostics continue to exercise the same source mapping.
        let active_root = match address_space::activate_supervisor_kernel_root(boot_info) {
            Ok(root) => root,
            Err(error) => {
                serial_write(b"ONE OS KERNEL ADDRESS SPACE ACTIVATION FAILED\n");
                serial_write(error.message());
                halt_forever()
            }
        };
        serial_write(b"ONE OS KERNEL ADDRESS SPACE ACTIVATED\n");

        #[cfg(feature = "test-wx-runtime-audit")]
        let address_space_test_result = {
            let executable_virtual_address = match wx_sibling_test.executable_virtual_address {
                Some(address) => address,
                None => {
                    serial_write(b"ONE OS W^X CROSS-ROOT TEST FAILED: RX alias missing\n");
                    halt_forever()
                }
            };
            address_space::verify_runtime_address_space_switch_smoke_test_with_wx_probe(
                boot_info,
                active_root,
                wx_sibling_test.executable_physical_page,
                executable_virtual_address,
            )
        };
        #[cfg(not(feature = "test-wx-runtime-audit"))]
        let address_space_test_result =
            address_space::verify_runtime_address_space_switch_smoke_test(boot_info, active_root);

        let _active_root = match address_space_test_result {
            Ok(root) => root,
            Err(error) => {
                serial_write(b"ONE OS ADDRESS SPACE SWITCH FAILED\n");
                serial_write(error.message());
                halt_forever()
            }
        };
        serial_write(b"ONE OS ADDRESS SPACE SWITCH PASS\n");
        #[cfg(feature = "test-wx-runtime-audit")]
        {
            let executable_address =
                paging::enforce_kernel_executable_alias_wx as *const () as usize as u64;
            let direct_alias = match paging::kernel_executable_direct_alias_for_test(
                boot_info,
                executable_address,
                _active_root.recursive_index(),
            ) {
                Ok(address) => address,
                Err(error) => {
                    serial_write(b"\nONE OS W^X DIRECT-MAP WRITE PROTECTION SETUP FAILED\n");
                    serial_write(error.message());
                    halt_forever()
                }
            };
            let expected_ip =
                unsafe { core::ptr::addr_of!(oneos_vm_test_wx_directmap_fault_ip) as u64 };
            let recovery_ip =
                unsafe { core::ptr::addr_of!(oneos_vm_test_wx_directmap_recovery) as u64 };
            interrupts::arm_expected_protection_page_fault(direct_alias, expected_ip, recovery_ip);

            // SAFETY: the dedicated test deliberately writes through the
            // validated RO/NX direct-map alias of an executable kernel page.
            // The handler recovers only from the exact supervisor #PF (0x3).
            unsafe {
                oneos_vm_test_wx_directmap_write(direct_alias, 0x4f4e_455f_5758_5752);
            }
            if !interrupts::expected_protection_page_fault_was_seen() {
                serial_write(b"\nONE OS W^X DIRECT-MAP WRITE PROTECTION FAILED\n");
                halt_forever()
            }
            serial_write(b"ONE OS W^X DIRECT-MAP WRITE PROTECTION PASS\n");

            if let Err(error) = paging::verify_wx_sibling_test_after_transition(
                boot_info,
                &mut wx_sibling_test,
                _active_root.recursive_index(),
            ) {
                serial_write(b"\nONE OS W^X WRITABLE SIBLING DIRECT-MAP FAILED\n");
                serial_write(error.message());
                halt_forever()
            }
            serial_write(b"ONE OS W^X LARGE-PAGE DEMOTION VERIFIED PASS\n");
            serial_write(b"ONE OS W^X WRITABLE SIBLING DIRECT-MAP PASS\n");
            serial_write(b"ONE OS W^X SIBLING ALIAS DATA CONSISTENCY PASS\n");
        }

        // The active handle carries the private recursive index installed in
        // the new root. Exercise the exact initializer path after CR3 changes.
        #[cfg(not(any(
            feature = "test-exception",
            feature = "test-general-protection",
            feature = "test-page-fault",
            feature = "test-double-fault",
            feature = "test-ist",
            feature = "test-supervisor-write-protection",
            feature = "test-nx-protection",
            feature = "test-vm-transitions",
            feature = "test-cr3-switch-guard"
        )))]
        {
            if let Err(error) = paging::verify_user_frame_zeroing_test_with_recursive_index(
                boot_info,
                _active_root.recursive_index(),
            ) {
                serial_write(b"ONE OS USER FRAME ZERO TEST FAILED\n");
                serial_write(error.message());
                halt_forever()
            }
        }

        serial_write(b"Architecture: x86_64\n");
        serial_write(b"Milestone: serial bootstrap\n");
        serial_write(b"Memory map: structurally validated\n");
        serial_write(
            b"Status: physical allocation, page-table inspection, and a limited active map/unmap smoke test are available; general-purpose VM, user mode, scheduler, and drivers are not implemented\n",
        );
        // This marker is emitted only after IDT installation, memory-map validation,
        // allocator smoke tests, and mapping/permission validation. CI rejects any failed stage.
        serial_write(b"ONE OS BOOTSTRAP COMPLETE\n");

        halt_forever()
    }
}

fn print_wx_conflict_diagnostic(index: u64, conflict: oneos_core::FrameWxAuditConflict) {
    interrupts::write_hex(b"ONE OS W^X CONFLICT INDEX: ", index);
    interrupts::write_hex(
        b"ONE OS W^X CONFLICT PHYSICAL START: ",
        conflict.physical_start,
    );
    interrupts::write_hex(b"ONE OS W^X CONFLICT LENGTH: ", conflict.length);
    interrupts::write_hex(b"ONE OS W^X CONFLICT VA A: ", conflict.first_virtual_start);
    interrupts::write_hex(b"ONE OS W^X CONFLICT VA B: ", conflict.second_virtual_start);
    let rights_a = (conflict.first_permissions.writable as u64)
        | ((conflict.first_permissions.executable as u64) << 1);
    let rights_b = (conflict.second_permissions.writable as u64)
        | ((conflict.second_permissions.executable as u64) << 1);
    interrupts::write_hex(b"ONE OS W^X CONFLICT RIGHTS A (W=1,X=2): ", rights_a);
    interrupts::write_hex(b"ONE OS W^X CONFLICT RIGHTS B (W=1,X=2): ", rights_b);
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

struct SerialFmtWriter;

impl core::fmt::Write for SerialFmtWriter {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        serial_write(value.as_bytes());
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    serial_write(b"\nONE OS KERNEL PANIC\n");
    let mut writer = SerialFmtWriter;
    let _ = core::fmt::Write::write_fmt(
        &mut writer,
        format_args!("Panic message: {}\n", info.message()),
    );
    if let Some(location) = info.location() {
        serial_write(b"Panic location file: ");
        serial_write(location.file().as_bytes());
        serial_write(b"\n");
        interrupts::write_hex(b"Panic location line: ", u64::from(location.line()));
    }
    halt_forever()
}
