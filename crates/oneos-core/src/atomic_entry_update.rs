//! Bounded compare-exchange retry logic for hardware-updated x86 page entries.
//!
//! x86 hardware may monotonically set the Accessed and Dirty bits while a
//! page-table entry is being updated. This module isolates the retry decision
//! from privileged pointer access so its failure paths can be tested on the host.
//! It does not perform atomics, mutate page tables, invalidate TLB entries, or
//! prove that an in-flight hardware page walk has quiesced.

const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const ACCESSED_DIRTY_MASK: u64 = ACCESSED | DIRTY;

/// Maximum strong CAS attempts used by the kernel editor's non-mutating smoke check.
pub const ATOMIC_ENTRY_CAS_MAX_ATTEMPTS: usize = 8;

/// Failure returned by the bounded page-entry compare-exchange retry algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicEntryCasRetryError {
    /// The failed CAS observed a non-A/D change, an A/D bit clearing, or no A/D progress.
    UnexpectedEntryChange,
    /// Every allowed attempt observed a valid monotonic A/D update but no CAS succeeded.
    RetryLimitExceeded,
}

/// Attempts a strong CAS and retries only when hardware monotonic A/D updates explain failure.
///
/// `initial` is the entry value validated by the caller before entering this helper.
/// `replacement_for` computes the replacement from the current expected value, allowing
/// callers to preserve newly observed A/D bits while changing other entry bits.
/// `compare_exchange` returns `Ok(())` on success or the exact value observed on failure.
///
/// A failed compare-exchange is retryable only when:
/// - all non-A/D bits still match the original entry;
/// - every A/D bit already observed in `expected` remains set; and
/// - at least one additional A/D bit became set.
///
/// A strong CAS that fails without observable A/D progress is treated as an invariant
/// violation, not as a spurious failure. The retry budget counts total CAS attempts.
pub fn compare_exchange_entry_with_ad_retry<C, R>(
    initial: u64,
    max_attempts: usize,
    mut replacement_for: R,
    mut compare_exchange: C,
) -> Result<u64, AtomicEntryCasRetryError>
where
    C: FnMut(u64, u64) -> Result<(), u64>,
    R: FnMut(u64) -> u64,
{
    if max_attempts == 0 {
        return Err(AtomicEntryCasRetryError::RetryLimitExceeded);
    }

    let original_non_ad = initial & !ACCESSED_DIRTY_MASK;
    let mut expected = initial;

    for _ in 0..max_attempts {
        let replacement = replacement_for(expected);
        match compare_exchange(expected, replacement) {
            Ok(()) => return Ok(replacement),
            Err(observed) => {
                let expected_ad = expected & ACCESSED_DIRTY_MASK;
                let observed_ad = observed & ACCESSED_DIRTY_MASK;
                if observed & !ACCESSED_DIRTY_MASK != original_non_ad
                    || observed_ad & expected_ad != expected_ad
                    || observed_ad == expected_ad
                {
                    return Err(AtomicEntryCasRetryError::UnexpectedEntryChange);
                }
                expected = observed;
            }
        }
    }

    Err(AtomicEntryCasRetryError::RetryLimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::{
        compare_exchange_entry_with_ad_retry, AtomicEntryCasRetryError,
        ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
    };
    use std::vec::Vec;

    const PRESENT: u64 = 1;
    const WRITABLE: u64 = 1 << 1;
    const ACCESSED: u64 = 1 << 5;
    const DIRTY: u64 = 1 << 6;
    const NO_EXECUTE: u64 = 1 << 63;
    const INITIAL_ENTRY: u64 = 0x12_3000 | PRESENT | WRITABLE | NO_EXECUTE;

    #[test]
    fn retries_when_hardware_sets_accessed_then_dirty() {
        let mut attempts = Vec::new();
        let result = compare_exchange_entry_with_ad_retry(
            INITIAL_ENTRY,
            ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
            |expected| expected & !PRESENT,
            |expected, replacement| {
                attempts.push((expected, replacement));
                match attempts.len() {
                    1 => Err(expected | ACCESSED),
                    2 => Err(expected | DIRTY),
                    3 => Ok(()),
                    _ => unreachable!("CAS succeeded within the expected retry sequence"),
                }
            },
        );

        assert_eq!(result, Ok((INITIAL_ENTRY | ACCESSED | DIRTY) & !PRESENT));
        assert_eq!(
            attempts,
            std::vec![
                (INITIAL_ENTRY, INITIAL_ENTRY & !PRESENT),
                (
                    INITIAL_ENTRY | ACCESSED,
                    (INITIAL_ENTRY | ACCESSED) & !PRESENT,
                ),
                (
                    INITIAL_ENTRY | ACCESSED | DIRTY,
                    (INITIAL_ENTRY | ACCESSED | DIRTY) & !PRESENT,
                ),
            ]
        );
    }

    #[test]
    fn aborts_when_a_non_ad_bit_changes() {
        let mut calls = 0;
        let result = compare_exchange_entry_with_ad_retry(
            INITIAL_ENTRY,
            ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
            |expected| expected,
            |_, _| {
                calls += 1;
                Err(INITIAL_ENTRY ^ WRITABLE)
            },
        );

        assert_eq!(result, Err(AtomicEntryCasRetryError::UnexpectedEntryChange));
        assert_eq!(calls, 1, "must not retry an unexpected non-A/D mutation");
    }

    #[test]
    fn aborts_when_an_ad_bit_is_cleared_or_no_ad_progress_occurs() {
        let initial_with_ad = INITIAL_ENTRY | ACCESSED | DIRTY;
        let lost_dirty = compare_exchange_entry_with_ad_retry(
            initial_with_ad,
            ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
            |expected| expected,
            |_, _| Err(initial_with_ad & !DIRTY),
        );
        assert_eq!(
            lost_dirty,
            Err(AtomicEntryCasRetryError::UnexpectedEntryChange)
        );

        let no_progress = compare_exchange_entry_with_ad_retry(
            INITIAL_ENTRY,
            ATOMIC_ENTRY_CAS_MAX_ATTEMPTS,
            |expected| expected,
            |expected, _| Err(expected),
        );
        assert_eq!(
            no_progress,
            Err(AtomicEntryCasRetryError::UnexpectedEntryChange)
        );
    }

    #[test]
    fn returns_retry_limit_error_when_budget_is_exhausted() {
        let mut calls = 0;
        let result = compare_exchange_entry_with_ad_retry(
            INITIAL_ENTRY,
            2,
            |expected| expected & !PRESENT,
            |expected, _| {
                calls += 1;
                if calls == 1 {
                    Err(expected | ACCESSED)
                } else {
                    Err(expected | DIRTY)
                }
            },
        );

        assert_eq!(result, Err(AtomicEntryCasRetryError::RetryLimitExceeded));
        assert_eq!(calls, 2, "must never exceed the configured attempt budget");
    }

    #[test]
    fn zero_attempt_budget_fails_without_calling_compare_exchange() {
        let mut called = false;
        let result = compare_exchange_entry_with_ad_retry(
            INITIAL_ENTRY,
            0,
            |expected| expected,
            |_, _| {
                called = true;
                Ok(())
            },
        );

        assert_eq!(result, Err(AtomicEntryCasRetryError::RetryLimitExceeded));
        assert!(!called);
    }
}
