use super::{validate_memory_map, MemoryMapError};

const PAGE_SIZE: u64 = 4096;

/// Why boot-time memory ownership validation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootMemoryPolicyError {
    /// The physical memory map is empty, inverted, or overlapping.
    MemoryMap(MemoryMapError),
    /// The kernel ELF physical range is empty or overflows the address space.
    InvalidKernelImageRange,
    /// A region marked usable overlaps the kernel ELF physical range.
    KernelImageOverlapsUsableMemory,
    /// Adding region or frame counts overflowed.
    CapacityOverflow,
    /// More usable region segments are present than bootstrap metadata supports.
    UsableRegionCapacityExceeded { required: usize, maximum: usize },
    /// More usable frames are present than the bootstrap bitmap supports.
    UsableFrameCapacityExceeded { required: usize, maximum: usize },
}

impl BootMemoryPolicyError {
    /// A stable diagnostic suitable for early kernel serial output.
    pub const fn message(&self) -> &'static [u8] {
        match self {
            Self::MemoryMap(_) => b"Physical memory map is invalid\n",
            Self::InvalidKernelImageRange => b"Kernel physical image range is invalid\n",
            Self::KernelImageOverlapsUsableMemory => b"Kernel image overlaps allocatable memory\n",
            Self::CapacityOverflow => b"Physical allocator capacity calculation overflowed\n",
            Self::UsableRegionCapacityExceeded { .. } => {
                b"Physical region metadata capacity exceeded\n"
            }
            Self::UsableFrameCapacityExceeded { .. } => {
                b"Physical frame bitmap capacity exceeded\n"
            }
        }
    }
}

/// Counts computed while checking the bootstrap memory ownership policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootMemoryPolicyStats {
    /// Usable regions that contain at least one complete non-zero 4 KiB frame.
    pub usable_regions: usize,
    /// Number of complete non-zero 4 KiB frames in those regions.
    pub usable_frames: usize,
}

/// Validates kernel exclusion and fixed metadata capacity before allocator setup.
///
/// The kernel passes the same memory-map classification used to construct the
/// frame allocator. Only regions with usable=true can become allocatable. The
/// kernel image must not overlap them, and their aligned frame/region counts
/// must fit the caller-provided static metadata limits.
pub fn validate_boot_memory_policy<F>(
    region_count: usize,
    region_bounds: F,
    kernel_physical_start: u64,
    kernel_physical_len: u64,
    max_usable_regions: usize,
    max_usable_frames: usize,
) -> Result<BootMemoryPolicyStats, BootMemoryPolicyError>
where
    F: Fn(usize) -> (u64, u64, bool),
{
    validate_memory_map(region_count, |index| {
        let (start, end, _) = region_bounds(index);
        (start, end)
    })
    .map_err(BootMemoryPolicyError::MemoryMap)?;

    let kernel_physical_end = kernel_physical_start
        .checked_add(kernel_physical_len)
        .filter(|_| kernel_physical_len != 0)
        .ok_or(BootMemoryPolicyError::InvalidKernelImageRange)?;

    let mut usable_regions = 0usize;
    let mut usable_frames = 0usize;

    for index in 0..region_count {
        let (start, end, usable) = region_bounds(index);
        if !usable {
            continue;
        }

        if start < kernel_physical_end && kernel_physical_start < end {
            return Err(BootMemoryPolicyError::KernelImageOverlapsUsableMemory);
        }

        let Some((_, frame_count)) = aligned_frame_range(start, end)? else {
            continue;
        };

        usable_regions = usable_regions
            .checked_add(1)
            .ok_or(BootMemoryPolicyError::CapacityOverflow)?;
        if usable_regions > max_usable_regions {
            return Err(BootMemoryPolicyError::UsableRegionCapacityExceeded {
                required: usable_regions,
                maximum: max_usable_regions,
            });
        }

        usable_frames = usable_frames
            .checked_add(frame_count)
            .ok_or(BootMemoryPolicyError::CapacityOverflow)?;
        if usable_frames > max_usable_frames {
            return Err(BootMemoryPolicyError::UsableFrameCapacityExceeded {
                required: usable_frames,
                maximum: max_usable_frames,
            });
        }
    }

    Ok(BootMemoryPolicyStats {
        usable_regions,
        usable_frames,
    })
}

fn aligned_frame_range(
    start: u64,
    end: u64,
) -> Result<Option<(u64, usize)>, BootMemoryPolicyError> {
    let start = start.max(PAGE_SIZE);
    let Some(aligned_start) = start
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
    else {
        return Ok(None);
    };
    let aligned_end = end & !(PAGE_SIZE - 1);
    if aligned_start >= aligned_end {
        return Ok(None);
    }

    let frame_count = usize::try_from((aligned_end - aligned_start) / PAGE_SIZE)
        .map_err(|_| BootMemoryPolicyError::CapacityOverflow)?;
    if frame_count == 0 {
        return Ok(None);
    }
    Ok(Some((aligned_start, frame_count)))
}

#[cfg(test)]
mod tests {
    use super::{validate_boot_memory_policy, BootMemoryPolicyError, BootMemoryPolicyStats};
    use crate::MemoryMapError;

    fn validate(
        regions: &[(u64, u64, bool)],
        kernel_start: u64,
        kernel_len: u64,
        max_regions: usize,
        max_frames: usize,
    ) -> Result<BootMemoryPolicyStats, BootMemoryPolicyError> {
        validate_boot_memory_policy(
            regions.len(),
            |index| regions[index],
            kernel_start,
            kernel_len,
            max_regions,
            max_frames,
        )
    }

    #[test]
    fn rejects_kernel_image_overlapping_a_usable_region() {
        let regions = [(0x1000, 0x9000, true)];
        assert_eq!(
            validate(&regions, 0x3000, 0x2000, 8, 64),
            Err(BootMemoryPolicyError::KernelImageOverlapsUsableMemory)
        );
    }

    #[test]
    fn rejects_empty_or_overflowing_kernel_image_ranges() {
        let regions = [(0x1000, 0x9000, true)];
        assert_eq!(
            validate(&regions, 0x1000, 0, 8, 64),
            Err(BootMemoryPolicyError::InvalidKernelImageRange)
        );
        assert_eq!(
            validate(&regions, u64::MAX - 0x7ff, 0x1000, 8, 64),
            Err(BootMemoryPolicyError::InvalidKernelImageRange)
        );
    }

    #[test]
    fn rejects_usable_region_metadata_capacity_exceeded() {
        let regions = [(0x1000, 0x3000, true), (0x4000, 0x6000, true)];
        assert_eq!(
            validate(&regions, 0x8000, 0x1000, 1, 64),
            Err(BootMemoryPolicyError::UsableRegionCapacityExceeded {
                required: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn rejects_usable_frame_bitmap_capacity_exceeded() {
        let regions = [(0x1000, 0x6000, true)];
        assert_eq!(
            validate(&regions, 0x8000, 0x1000, 8, 4),
            Err(BootMemoryPolicyError::UsableFrameCapacityExceeded {
                required: 5,
                maximum: 4,
            })
        );
    }

    #[test]
    fn accepts_reserved_kernel_region_and_counts_only_usable_frames() {
        let regions = [(0x1000, 0x9000, false), (0xA000, 0xE000, true)];
        assert_eq!(
            validate(&regions, 0x2000, 0x3000, 8, 4),
            Ok(BootMemoryPolicyStats {
                usable_regions: 1,
                usable_frames: 4,
            })
        );
    }

    #[test]
    fn rejects_invalid_map_before_capacity_checks() {
        let regions = [(0x1000, 0x5000, true), (0x3000, 0x7000, false)];
        assert_eq!(
            validate(&regions, 0x8000, 0x1000, 8, 64),
            Err(BootMemoryPolicyError::MemoryMap(MemoryMapError::Overlap {
                first_region: 0,
                second_region: 1,
            }))
        );
    }
}
