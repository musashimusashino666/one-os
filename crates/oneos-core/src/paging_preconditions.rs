//! Host-testable x86_64 paging preconditions.
//!
//! These pure checks let the kernel reject missing CPU capabilities and required
//! control bits before it invokes the active-page-table mutation path.

const REQUIRED_PHYSICAL_WIDTH_LEAF: u32 = 0x8000_0008;
const NX_FEATURE: u32 = 1 << 20;
const CR0_WP: u64 = 1 << 16;
const EFER_NXE: u64 = 1 << 11;

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
    fn validates_the_complete_paging_precondition_sequence() {
        assert_eq!(
            validate_extended_cpuid_leaf(REQUIRED_WIDTH_LEAF, REQUIRED_WIDTH_LEAF),
            Ok(())
        );
        assert_eq!(
            validate_paging_cpu_capabilities(NX_FEATURE, 48),
            Ok(())
        );
        assert_eq!(validate_cr0_write_protect(CR0_WP), Ok(()));
        assert_eq!(validate_efer_nx_enable(EFER_NXE), Ok(()));
    }
}
