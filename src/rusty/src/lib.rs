mod os_rng;

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

// We keep track of all memory allocated by Rust code, refusing new allocations if it exceeds
// 128MB.
//
// Note that while Rust's std, in general, should panic in response to a null allocation, it
// is totally conceivable that some code will instead dereference this null pointer, which
// would violate our guarantees that Rust modules should never crash the entire application.
//
// In the future, as upstream Rust explores a safer allocation API (eg the Alloc API which
// returns Results instead of raw pointers, or redefining the GlobalAlloc API to allow
// panic!()s inside of alloc calls), we should switch to those, however these APIs are
// currently unstable.
const TOTAL_MEM_LIMIT_BYTES: usize = 128 * 1024 * 1024;
static TOTAL_MEM_ALLOCD: AtomicUsize = AtomicUsize::new(0);
struct MemoryLimitingAllocator;
unsafe impl GlobalAlloc for MemoryLimitingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let len = layout.size();
        if len > TOTAL_MEM_LIMIT_BYTES {
            return ptr::null_mut();
        }
        if TOTAL_MEM_ALLOCD.fetch_add(len, Ordering::AcqRel) + len > TOTAL_MEM_LIMIT_BYTES {
            TOTAL_MEM_ALLOCD.fetch_sub(len, Ordering::AcqRel);
            return ptr::null_mut();
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        TOTAL_MEM_ALLOCD.fetch_sub(layout.size(), Ordering::AcqRel);
    }
}

#[global_allocator]
static ALLOC: MemoryLimitingAllocator = MemoryLimitingAllocator;
