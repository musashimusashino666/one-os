//! Host-testable x86_64 paging preconditions.
//!
//! These pure checks let the kernel reject missing CPU capabilities and required
//! control bits before it invokes the active-page-table mutation path.

const NX_FEATURE: u32 = 1 << 20;
const CR0_WP: u64 = 1 << 16;
const CR0_PG: u64 = 1 << 31;
const CR4_LA57: u64 = 1 << 12;
const CR4_PCIDE: u64 = 1 << 17;
const EFER_NXE: u64 = 1 << 11;
const RFLAGS_IF: u64 = 1 << 9;
const KERNEL_HALF_START: u64 = 0xffff_8000_0000_0000;

/// A CPU capability or control-state precondition required by active page-table mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingPreconditionError {
    /// The reported maximum extended CPUID leaf is below the required leaf.
    ExtendedLeafUnavailable {
        /// The minimum extended leaf the kernel requires.
        required_leaf: u32,
        /// The maximum extended leaf reported by CPUID.80000000H.
        maximum_leaf: u32,
    },
    /// The processor does not advertise the architectural NX feature.
    NxUnsupported,
    /// The physical-address width is outside the supported architectural range.
    InvalidPhysicalAddressWidth {
        /// The reported MAXPHYADDR value.
        bits: u8,
    },
    /// CR0.WP is not enabled, so supervisor writes can bypass read-only PTEs.
    SupervisorWriteProtectionDisabled,
    /// EFER.NXE is not enabled, so NX page-table entries cannot be relied upon.
    NxEnableDisabled,
    /// Maskable interrupts are enabled during a single-CPU root switch.
    MaskableInterruptsEnabled,
    /// CR0.PG is clear, so paging is not active.
    PagingDisabled,
    /// CR4.LA57 enables five-level paging, which this kernel does not support.
    FiveLevelPagingUnsupported,
    /// CR4.PCIDE enables PCID-tagged CR3 behavior outside this contract.
    PcidUnsupported,
}

impl PagingPreconditionError {
    /// Stable, allocation-free diagnostic for bootstrap failure paths.
    pub const fn message(self) -> &'static [u8] {
        match self {
            Self::ExtendedLeafUnavailable { .. } => {
                b"Required extended CPUID leaf is unavailable\n"
            }
            Self::NxUnsupported => b"CPU does not advertise NX support\n",
            Self::InvalidPhysicalAddressWidth { .. } => {
                b"CPU reported an unsupported physical-address width\n"
            }
            Self::SupervisorWriteProtectionDisabled => {
                b"CR0.WP is disabled; supervisor writes may bypass read-only entries\n"
            }
            Self::NxEnableDisabled => b"EFER.NXE is disabled\n",
            Self::MaskableInterruptsEnabled => {
                b"Maskable interrupts must remain disabled during the root switch\n"
            }
            Self::PagingDisabled => b"CR0.PG is disabled; paging is not active\n",
            Self::FiveLevelPagingUnsupported => {
                b"CR4.LA57 is enabled; five-level paging is not supported\n"
            }
            Self::PcidUnsupported => {
                b"CR4.PCIDE is enabled; PCID-tagged CR3 switching is not supported\n"
            }
        }
    }
}

/// Requires the extended CPUID leaf needed to query MAXPHYADDR.
///
/// Check this before querying that leaf; unsupported CPUID leaves must never be
/// read speculatively by the kernel.
pub fn validate_extended_cpuid_leaf(
    maximum_leaf: u32,
    required_leaf: u32,
) -> Result<(), PagingPreconditionError> {
    if maximum_leaf < required_leaf {
        return Err(PagingPreconditionError::ExtendedLeafUnavailable {
            required_leaf,
            maximum_leaf,
        });
    }
    Ok(())
}

/// Validates the processor's NX feature bit and reported physical-address width.
pub fn validate_paging_cpu_capabilities(
    extended_feature_edx: u32,
    physical_address_bits: u8,
) -> Result<(), PagingPreconditionError> {
    if extended_feature_edx & NX_FEATURE == 0 {
        return Err(PagingPreconditionError::NxUnsupported);
    }
    if !(32..=52).contains(&physical_address_bits) {
        return Err(PagingPreconditionError::InvalidPhysicalAddressWidth {
            bits: physical_address_bits,
        });
    }
    Ok(())
}

/// Validates the read-back value of CR0 after the kernel enables write protection.
pub fn validate_cr0_write_protect(cr0: u64) -> Result<(), PagingPreconditionError> {
    if cr0 & CR0_WP == 0 {
        return Err(PagingPreconditionError::SupervisorWriteProtectionDisabled);
    }
    Ok(())
}

/// Validates the read-back value of EFER after the kernel enables NX support.
pub fn validate_efer_nx_enable(efer: u64) -> Result<(), PagingPreconditionError> {
    if efer & EFER_NXE == 0 {
        return Err(PagingPreconditionError::NxEnableDisabled);
    }
    Ok(())
}

/// Validates the bootloader-provided kernel stack range before using it as TSS.RSP0.
///
/// Returns the exclusive stack top when the interval is nonempty, canonical,
/// wholly in the four-level kernel half, 16-byte aligned at its top, and contains
/// the current stack pointer. An invalid interval is rejected without mutation.
pub fn validate_kernel_entry_stack(
    bottom: u64,
    length: u64,
    current_stack_pointer: u64,
) -> Option<u64> {
    if length == 0 || bottom < KERNEL_HALF_START || !crate::is_canonical_4level(bottom) {
        return None;
    }
    let top = bottom.checked_add(length)?;
    let last = top.checked_sub(1)?;
    if top & 0xf != 0
        || top < KERNEL_HALF_START
        || !crate::is_canonical_4level(top)
        || !crate::is_canonical_4level(last)
        || current_stack_pointer < bottom
        || current_stack_pointer >= top
    {
        return None;
    }
    Some(top)
}

/// Validates the CPU state immediately before activating a new kernel root.
///
/// The current activation contract is a single CPU with maskable interrupts
/// disabled, four-level paging enabled, CR0.WP and EFER.NXE enabled, and PCID
/// disabled. Read these registers at the point of use instead of relying only
/// on initialization having enabled them earlier.
pub fn validate_kernel_root_activation_state(
    cr0: u64,
    cr4: u64,
    efer: u64,
    rflags: u64,
) -> Result<(), PagingPreconditionError> {
    if rflags & RFLAGS_IF != 0 {
        return Err(PagingPreconditionError::MaskableInterruptsEnabled);
    }
    if cr0 & CR0_PG == 0 {
        return Err(PagingPreconditionError::PagingDisabled);
    }
    validate_cr0_write_protect(cr0)?;
    if cr4 & CR4_LA57 != 0 {
        return Err(PagingPreconditionError::FiveLevelPagingUnsupported);
    }
    if cr4 & CR4_PCIDE != 0 {
        return Err(PagingPreconditionError::PcidUnsupported);
    }
    validate_efer_nx_enable(efer)
}

#[cfg(test)]
mod tests {
    use super::{
        validate_cr0_write_protect, validate_efer_nx_enable, validate_extended_cpuid_leaf,
        validate_paging_cpu_capabilities, PagingPreconditionError,
    };

    const REQUIRED_WIDTH_LEAF: u32 = 0x8000_0008;
    const NX_FEATURE: u32 = 1 << 20;
    const CR0_WP: u64 = 1 << 16;
    const EFER_NXE: u64 = 1 << 11;

    #[test]
    fn rejects_cpu_missing_the_required_extended_cpuid_leaf() {
        assert_eq!(
            validate_extended_cpuid_leaf(0x8000_0001, REQUIRED_WIDTH_LEAF),
            Err(PagingPreconditionError::ExtendedLeafUnavailable {
                required_leaf: REQUIRED_WIDTH_LEAF,
                maximum_leaf: 0x8000_0001,
            })
        );
    }

    #[test]
    fn rejects_missing_nx_and_invalid_physical_address_widths() {
        assert_eq!(
            validate_paging_cpu_capabilities(0, 48),
            Err(PagingPreconditionError::NxUnsupported)
        );
        for bits in [0, 31, 53, 255] {
            assert_eq!(
                validate_paging_cpu_capabilities(NX_FEATURE, bits),
                Err(PagingPreconditionError::InvalidPhysicalAddressWidth { bits })
            );
        }
        assert_eq!(validate_paging_cpu_capabilities(NX_FEATURE, 32), Ok(()));
        assert_eq!(validate_paging_cpu_capabilities(NX_FEATURE, 52), Ok(()));
    }

    #[test]
    fn rejects_cr0_without_wp_and_efer_without_nxe() {
        assert_eq!(
            validate_cr0_write_protect(0),
            Err(PagingPreconditionError::SupervisorWriteProtectionDisabled)
        );
        assert_eq!(
            validate_efer_nx_enable(0),
            Err(PagingPreconditionError::NxEnableDisabled)
        );
        assert_eq!(validate_cr0_write_protect(CR0_WP), Ok(()));
        assert_eq!(validate_efer_nx_enable(EFER_NXE), Ok(()));
    }

    #[test]
    fn validates_kernel_entry_stack_top_and_rejects_invalid_intervals() {
        let bottom = 0xffff_8000_1000_0000;
        let length = 0x8000;
        let top = bottom + length;
        assert_eq!(
            super::validate_kernel_entry_stack(bottom, length, top - 8),
            Some(top)
        );
        assert_eq!(super::validate_kernel_entry_stack(bottom, 0, top - 8), None);
        assert_eq!(
            super::validate_kernel_entry_stack(bottom, u64::MAX, top - 8),
            None
        );
        assert_eq!(
            super::validate_kernel_entry_stack(bottom, length + 1, top - 8),
            None
        );
        assert_eq!(
            super::validate_kernel_entry_stack(bottom, length, bottom - 1),
            None
        );
        assert_eq!(super::validate_kernel_entry_stack(bottom, length, top), None);
        assert_eq!(super::validate_kernel_entry_stack(0x1000, length, 0x2000), None);
        assert_eq!(
            super::validate_kernel_entry_stack(0xffff_7fff_ffff_f000, length, top - 8),
            None
        );
    }

    #[test]
    fn kernel_root_activation_requires_the_complete_cpu_state() {
        const CR0_PG: u64 = 1 << 31;
        const CR4_PGE: u64 = 1 << 7;
        let cr0 = CR0_PG | CR0_WP;
        let efer = EFER_NXE;

        assert_eq!(
            super::validate_kernel_root_activation_state(cr0, CR4_PGE, efer, 0x2),
            Ok(())
        );
        assert_eq!(
            super::validate_kernel_root_activation_state(cr0, CR4_PGE, efer, 1 << 9),
            Err(PagingPreconditionError::MaskableInterruptsEnabled)
        );
        assert_eq!(
            super::validate_kernel_root_activation_state(CR0_WP, CR4_PGE, efer, 0),
            Err(PagingPreconditionError::PagingDisabled)
        );
        assert_eq!(
            super::validate_kernel_root_activation_state(CR0_PG, CR4_PGE, efer, 0),
            Err(PagingPreconditionError::SupervisorWriteProtectionDisabled)
        );
        assert_eq!(
            super::validate_kernel_root_activation_state(cr0, 1 << 12, efer, 0),
            Err(PagingPreconditionError::FiveLevelPagingUnsupported)
        );
        assert_eq!(
            super::validate_kernel_root_activation_state(cr0, 1 << 17, efer, 0),
            Err(PagingPreconditionError::PcidUnsupported)
        );
        assert_eq!(
            super::validate_kernel_root_activation_state(cr0, CR4_PGE, 0, 0),
            Err(PagingPreconditionError::NxEnableDisabled)
        );
    }

    #[test]
    fn validates_the_complete_paging_precondition_sequence() {
        assert_eq!(
            validate_extended_cpuid_leaf(REQUIRED_WIDTH_LEAF, REQUIRED_WIDTH_LEAF),
            Ok(())
        );
        assert_eq!(validate_paging_cpu_capabilities(NX_FEATURE, 48), Ok(()));
        assert_eq!(validate_cr0_write_protect(CR0_WP), Ok(()));
        assert_eq!(validate_efer_nx_enable(EFER_NXE), Ok(()));
    }
}
