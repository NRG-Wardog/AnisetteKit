# Defensive B: allocation and selected transfer boundaries

## Scope

This is a narrow defensive change based on the shipped source audit. It does not identify or repair the reported constructor47 cause. No dependency loading, import ABI implementation, constructor skipping, permission relaxation, or proprietary-library execution is included.

- PageAllocator checks the existing overflow/capacity predicate before arithmetic or mutation and returns zero instead of aborting the host.
- EmulatorVM owns requested allocation extents. Its checked allocation method handles padding overflow, exhausted arenas, and bookkeeping allocation exceptions by poisoning/stopping the VM.
- malloc, calloc, realloc, C++ new, exception allocation, and write_bytes use that method. calloc checks multiplication. Existing zero-size policies remain: distinct arena slots; throwing C++ zero-size new reserves one byte.
- realloc accepts null or a known allocation base; it copies min(old requested size, new requested size). Old bookkeeping remains until replacement and return-register write succeed. Failed replacement does not invalidate the old extent.
- free/delete remove bookkeeping but retain monotonic arena storage until engine close. No storage reuse, allocator ABI layout, or inferred guest object layout is added.
- calloc/fill, realloc/copy, memcpy, memset, and memcmp use fixed 4KiB scratch buffers. strcpy/strncpy check transfers and arithmetic instead of pretending a failed read was a terminator. These changes do not add memmove support or make overlapping memcpy valid.
- New checked transfer helpers reject address overflow and the existing protected `[0,0x10000)` region, then check Unicorn API results. No page map or permission change is made. This explicitly prevents the updated host-mediated copies from treating the protected low page as normal transfer memory.
- read/write preserve their existing host call counts and requested sizes. read records a failed guest copy, poisons/stops, and does not publish the successful host byte count to the guest. write stops before host output if its guest-source transfer fails.
- The import callback catches standard host exceptions, poisons/stops, and never supplies a fabricated success return after the exception. Already-failed VMs do not dispatch another import.

All C allocation exhaustion/overflow paths now stop the VM; they do not attempt a guessed guest errno, guest exception ABI, or ordinary nullable allocation-recovery contract. This is intentional fail-closed containment. A stopped operation can leave a partial copy or a consumed monotonic arena reservation, but no later import/procedure is allowed to continue normally in that failed VM.

## Explicit residual scope

This is not a universal memory-API or ABI audit repair. Unchanged raw guest transfer sites remain in:

- strlen, strcmp, strncmp, and memchr
- open/path parsing, mkdir/chmod/lstat/fstat, the read-only-denial errno/result writes, and assorted filesystem result registers
- system properties, gettimeofday, dlsym string reads, C++ guard acquire/release
- strtoll/strtol, strtoull, strtod, atof, Android log string reads, and lock-init output writes
- run_vm_procedure register preparation, its diagnostic first-instruction read, and final W0 read
- generic import fallback and unrelated result registers

The loader's checked segment/relocation/import-stub operations remain as before. Unknown imports, dummy data symbols, dependency completeness, unsupported relocation encodings, broad RWX mappings, and unmapped-page recovery are outside B.

read/write retain guest-count-sized host vectors to preserve their existing I/O behavior. Catching std::bad_alloc/length_error contains normal C++ allocation failure; it is not an OS out-of-memory-kill guarantee. The VM's monotonic heap and host bookkeeping still consume resources until VM destruction. Fixed scratch size does not create a CPU/time budget for enormous valid transfer lengths or unterminated strings. Low-page enforcement in the updated helpers is not a general VM-region permission query.

The allocator predicate's existing comment in elf_metadata_bounds.h still mentions its historical abort-avoidance/loader-only use; the predicate implementation is unchanged, and PageAllocator now invokes it directly for every reservation.

## Host-only verification

Run from the repository:

    python3 .ci/native-tests/test_memory_boundaries_host.py --unicorn-include HEADERS --output RESULTS

The fixture compiles the actual production loader against sparse API doubles and never links a real engine. Its uc_emu_start aborts if called. It checks:

- allocation/size/padding overflow, invalid alignment and arena exhaustion without process abort
- calloc zeroing, requested-size bookkeeping, distinct zero-sized allocations
- realloc growth/shrink/null/zero cases, neighbor exclusion, unknown/interior pointers, preservation on copy/reservation failure
- free/delete bookkeeping and C++/exception allocation tracking
- injected bookkeeping-allocation, guest-read, guest-write, and register failures
- bounded copy/fill/compare chunks and string-copy success/failure
- address overflow and low-page rejection before any API transfer
- file-read copy failure and write failure before host output
- callback containment of a host allocation exception
- zero engine starts and no proprietary inputs

Current result: 403 assertions per variant in normal, O2/NDEBUG, and ASan+UBSan, 1,209 assertions total. LeakSanitizer is disabled explicitly in the driver; ASan/UBSan remain fail-fast. The maintained C++ regression also passes 32 allocator plus 51 hook assertions per variant, 249 total. These host results establish defensive boundary behavior only; they do not establish native-fork/device compatibility or successful login.

Existing extraction fixtures were updated to include the exact new helpers. Their consumer addresses now sit above the protected low page, and the failed-copy case expects VM poisoning rather than a successful guest read result. Passive observer enabled/disabled runs still have identical host I/O counts. A separate fresh VM now exercises open ownership after the old deliberately-poisoned loader VM; production does not reset its failure state.
