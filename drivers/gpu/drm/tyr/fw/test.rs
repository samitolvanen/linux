// SPDX-License-Identifier: GPL-2.0 or MIT

//! Self-tests for the firmware shared section allocator.

use super::SharedSection;
use kernel::prelude::*;
use kernel::sync::Arc;

macro_rules! assert_eq {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    pr_err!(
                        "Assertion failed: `(left == right)`\n left: `{:?}`,\nright: `{:?}`\n",
                        left_val,
                        right_val
                    );
                    return Err(EINVAL);
                }
            }
        }
    };
}

macro_rules! assert_matches {
    ($expression:expr, $pattern:pat) => {
        match $expression {
            $pattern => {}
            _ => {
                pr_err!(
                    "Assertion failed: `{}` does not match `{}`\n",
                    stringify!($expression),
                    stringify!($pattern)
                );
                return Err(EINVAL);
            }
        }
    };
}

/// Runs all self-tests for the `SharedSection` allocator.
///
/// This function is designed to be called during driver initialization to verify the correctness
/// of the borrow logic.
pub(crate) fn run_all(section: &Arc<SharedSection>) -> Result {
    pr_info!("Running SharedSection self-tests...\n");

    test_exclusive_borrow(section)?;
    test_shared_borrow(section)?;
    test_concurrent_shared_borrows(section)?;
    test_mixed_borrows(section)?;
    test_out_of_bounds(section)?;
    test_node_cache_exceedance(section)?;
    test_partially_overlapping_shared_borrows(section)?;

    pr_info!("All SharedSection self-tests passed.\n");
    Ok(())
}

/// Tests basic exclusive borrow and release.
fn test_exclusive_borrow(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_exclusive_borrow: start\n");
    let base_va = u64::from(section.section.va.start);

    // 1. Borrow a range exclusively.
    let guard1 = section.borrow_mut_bytes(base_va, 1024)?;

    // 2. Try to borrow an overlapping range exclusively, which should fail.
    let result = section.borrow_mut_bytes(base_va + 512, 1024);
    assert_matches!(result, Err(ENOSPC));

    // 3. Drop the first guard.
    drop(guard1);

    // 4. Borrow the original range again, which should now succeed.
    let _guard2 = section.borrow_mut_bytes(base_va, 1024)?;

    pr_info!("test_exclusive_borrow: pass\n");
    Ok(())
}

/// Tests basic shared borrow and release.
fn test_shared_borrow(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_shared_borrow: start\n");
    let base_va = u64::from(section.section.va.start);

    // 1. Borrow a range shared.
    let guard1 = section.borrow_bytes(base_va, 1024)?;

    // 2. Try to borrow an overlapping range exclusively, which should fail.
    let result = section.borrow_mut_bytes(base_va + 512, 1024);
    assert_matches!(result, Err(ENOSPC));

    // 3. Drop the shared guard.
    drop(guard1);

    // 4. Borrow the same range exclusively, which should now succeed.
    let _guard2 = section.borrow_mut_bytes(base_va, 1024)?;

    pr_info!("test_shared_borrow: pass\n");
    Ok(())
}

/// Tests that multiple concurrent shared borrows on the same range are allowed.
fn test_concurrent_shared_borrows(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_concurrent_shared_borrows: start\n");
    let base_va = u64::from(section.section.va.start);

    // 1. Acquire two separate shared borrows for the same range.
    let guard1 = section.borrow_bytes(base_va, 1024)?;
    let guard2 = section.borrow_bytes(base_va, 1024)?;

    // 2. Attempting an exclusive borrow should fail.
    let result = section.borrow_mut_bytes(base_va, 1024);
    assert_matches!(result, Err(ENOSPC));

    // 3. Drop one of the shared guards.
    drop(guard1);

    // 4. The exclusive borrow should still fail as one shared guard remains.
    let result = section.borrow_mut_bytes(base_va, 1024);
    assert_matches!(result, Err(ENOSPC));

    // 5. Drop the final shared guard.
    drop(guard2);

    // 6. The exclusive borrow should now succeed.
    let _guard3 = section.borrow_mut_bytes(base_va, 1024)?;

    pr_info!("test_concurrent_shared_borrows: pass\n");
    Ok(())
}

/// Tests collisions between shared and exclusive borrows.
fn test_mixed_borrows(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_mixed_borrows: start\n");
    let base_va = u64::from(section.section.va.start);

    // 1. Acquire an exclusive borrow.
    let guard_mut = section.borrow_mut_bytes(base_va, 1024)?;

    // 2. Attempting a shared borrow on an overlapping range should fail.
    let result = section.borrow_bytes(base_va + 512, 1024);
    assert_matches!(result, Err(ENOSPC));

    // 3. Drop the exclusive guard.
    drop(guard_mut);

    // 4. The shared borrow should now succeed.
    let _guard_shared = section.borrow_bytes(base_va + 512, 1024)?;

    pr_info!("test_mixed_borrows: pass\n");
    Ok(())
}

/// Tests that out-of-bounds borrows are rejected.
fn test_out_of_bounds(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_out_of_bounds: start\n");
    let section_va = &section.section.va;
    let section_size = section.section.mem.size() as u64;

    // 1. Try to borrow a range that starts within bounds but extends beyond the end.
    let result = section.borrow_bytes(u64::from(section_va.start) + section_size - 512, 1024);
    assert_matches!(result, Err(EINVAL));

    // 2. Try to borrow a range that starts exactly at the end.
    let result = section.borrow_bytes(u64::from(section_va.end), 1);
    assert_matches!(result, Err(EINVAL));

    // 3. Try to borrow a range that starts far beyond the end.
    let result = section.borrow_bytes(u64::from(section_va.end) + 1024, 1024);
    assert_matches!(result, Err(EINVAL));

    pr_info!("test_out_of_bounds: pass\n");
    Ok(())
}

/// Tests that the node cache correctly handles being filled and overflowing.
fn test_node_cache_exceedance(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_node_cache_exceedance: start\n");
    let base_va = u64::from(section.section.va.start);
    let mut guards = KVec::new();

    // Borrow one more than the cache size to force an overflow.
    for i in 0..(super::SharedSection::NODE_CACHE_SIZE + 1) {
        // Use non-overlapping ranges to ensure we get new nodes each time.
        let guard = section.borrow_mut_bytes(base_va + (i as u64 * 64), 64)?;
        guards.push(guard, GFP_KERNEL)?;
    }

    // Dropping the vector will release all guards. The logs should show that the cache fills up
    // and the last node is freed instead of cached.
    drop(guards);

    // Verify the cache is now full.
    assert_eq!(
        section.node_cache.lock().len(),
        super::SharedSection::NODE_CACHE_SIZE
    );

    pr_info!("test_node_cache_exceedance: pass\n");
    Ok(())
}

/// Tests that partially overlapping shared borrows are not allowed.
fn test_partially_overlapping_shared_borrows(section: &Arc<SharedSection>) -> Result {
    pr_info!("test_partially_overlapping_shared_borrows: start\n");
    let base_va = u64::from(section.section.va.start);

    // 1. Acquire a shared borrow.
    let _guard1 = section.borrow_bytes(base_va + 1024, 1024)?;

    // 2. Attempt to acquire another shared borrow that partially overlaps. This should fail
    //    because only identical ranges can be borrowed multiple times for shared access.
    let result = section.borrow_bytes(base_va + 512, 1024);
    assert_matches!(result, Err(ENOSPC));

    pr_info!("test_partially_overlapping_shared_borrows: pass\n");
    Ok(())
}
