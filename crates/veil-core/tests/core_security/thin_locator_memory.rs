//! BUG-1149: a thin clone's locator at its bound, measured with the
//! counting allocator of `adversarial7_core::pack` (this thread's
//! allocations): what it holds, and its peak while its maps grow.

use veil_core::promisor::LocatorProbe;

use crate::adversarial7_core::pack::{live, peak_of};

const MIB: usize = 1 << 20;

/// Under the 512 MiB client gate with room for the rest of a command: at
/// most 72 MiB held and 112 MiB at the peak, for directories of 1, 10 and
/// 100 entries.
#[test]
fn thin_locator_memory_at_its_bound() {
    for per_tree in [1u64, 10, 100] {
        let before = live();
        let (probe, peak) = peak_of(|| LocatorProbe::fill(per_tree));
        let held = live() - before;
        assert!(probe.places() > 0);
        eprintln!("{per_tree} a tree: {} places, {} MiB held, {} MiB at the peak", probe.places(), held / MIB, peak / MIB);
        assert!(held <= 72 * MIB, "{per_tree} a tree: the locator holds {} MiB at its bound", held / MIB);
        assert!(peak <= 112 * MIB, "{per_tree} a tree: the locator peaks at {} MiB", peak / MIB);
        drop(probe);
    }
}
