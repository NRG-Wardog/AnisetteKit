# Temporary ADI staging-order and consumer experiment

This local experiment starts at AnisetteKit commit `e530b84687ebea2e7d1115119e1a6d18372de14b` (tree `ca63e018a2ef7e3f0ba759860dfa5f5e6c854065`). Setup-before-staging is inherited upstream behavior. Successful staging followed by native OTP `-45061` motivates this experiment; it does not establish that the ordering caused the failure or that the experiment fixes it. Publication and a coordinated device test require separate review.

## One ordering change

Under the existing `g_vm_mutex`, normal OTP preserves its original null guard and invalid-library-directory rejection, then safely creates the UUID child with the existing checked helper and stages the exact supplied bytes before native VM construction, library loading, constructors, path selection or Android ID setup. All checked staging failures return before native setup or OTP.

Cold VMs can now observe the promoted `adi.pb` throughout native setup. Reused VMs retain their existing library, path and Android ID caches. A freshly provisioned VM is already initialized; this ordering cannot retroactively reset its context. Start/end provisioning and the already-prestaged isolated OTP route retain their prior setup behavior. There is one OTP call, with the inherited result and error handling, no automatic recovery, identity change, VM reset or retry.

A native setup failure after a successful rename now leaves the newly staged bytes in the normal UUID cache by design. The supplied input is unchanged, and existing cleanup ownership is unchanged: checked staging owns its temporary file, while normal UUID-directory cleanup remains the caller's responsibility. The existing Swift cleanup race is outside this experiment.

## Bounds and wire schema

The central `ADI_CONSUMER_DEBUG_ENABLED` switch defaults to 1 in `Native/Loader/adi_consumption_debug.h`; compile it as 0 or remove the isolated component after diagnosis. A thread-local pointer is scoped to one normal invocation under the existing native mutex and restored on exit. Recording uses fixed storage, 32 events and 64 descriptor entries. It reserves 16 rows for setup (first observations) and 16 for OTP (latest observations); either overflow sets the truncated bit. Retained events stay in original order. Serialization is capped at 2048 bytes and 36 components.

Private JSON key `v3_native_consumption` contains `v2|truncated|comparison|coverage|row...`. The SDK also accepts the prior `v1|truncated|row...` schema.

- `truncated`: 0 or 1, retaining its event/descriptor-loss meaning.
- `comparison`: 0 means unavailable or no comparable host bytes observed; 1 means all compared host bytes match so far; 2 means a sticky mismatch, including observed bytes beyond the supplied input.
- `coverage`: 0 or 1. A 1 requires comparison 1 and one tracked expected-path descriptor stream covering the entire supplied input, with every guest copy successful. It never establishes EOF, whole-file length, inode equality or ADI/identity validity.

The observer compares the immutable supplied input directly to bytes already held in the imported read hook's host temporary buffer. It never re-reads the host file or guest memory. Only the exact expected `adi.pb` path is compared. Input must have 1 through 1,048,576 bytes, and total byte comparisons across all streams are capped at 1,048,576 per invocation. Zero-length and oversized inputs keep normal OTP admission unchanged and report comparison 0, coverage 0.

An observed open establishes offset zero, including O_RDWR/O_APPEND opens. Close/reuse starts a separate stream rather than joining prefixes. An observed successful write invalidates that stream's offset for comparison; it adds no event or syscall. Unknown offsets, untracked descriptors, tracking/event loss, or exhausted comparison budget cannot establish complete coverage. Guest-copy failure can retain host comparison 1 but forces coverage 0. Matching partial reads followed by EOF remain comparison 1, coverage 0. Mismatch remains 2 even if a later stream matches.

Each event row retains eight canonical decimal integers:

1. Phase: 0 unknown, 1 constructors, 2 library initialization, 3 provisioning path, 4 Android ID, 5 OTP.
2. Operation: 0 open, 1 read.
3. Target: 0 other absolute path, 1 exact expected adi.pb, 2 relative path, 3 unreadable or expected path unavailable, 4 untracked descriptor.
4. Result: -1 failure, 0 EOF, 1 success/data.
5. Immediate host errno on an actual open/read failure, 1 through 4095; 0 unknown/not applicable. An absent FD does not invent EBADF.
6. Requested read count; 0 for open.
7. Returned positive read count; 0 for open/error/EOF.
8. Actual guest-memory-copy Unicorn status 0 through 32; -1 not attempted/unknown.

Counts above 1,048,576 are represented by 1,048,577 (saturated, not exact). Descriptor numbers, pointers, paths, identifiers, file contents and hashes are never serialized. Expected-path formatting occurs only after the original null guard. Close only clears internal descriptor ownership and emits no host-close-success claim.

The SDK removes this metadata before constructing successful headers. Failed responses include it only after finite/range/canonical-number validation in a separate `DEBUG_TEMPORARY_ADI_CONSUMPTION` suffix. A matching, separately reviewed SideStore/LC v2 decoder is required for device delivery. Existing native-stage suffix behavior remains intact.

## Limits of observation

The evidence can show imported opens/reads at the expected path, host read bytes relative to the supplied input, host errors, and guest-copy status. Original hook results and errno behavior are preserved, including positive read counts despite guest-copy failure and stale guest errno after read failure. No extra host syscalls or guest probes are introduced.

Only the supported imported hooks are observed; this does not prove that an unsupported or direct syscall did not execute. Opaque ADI parsing, cryptography and identity checks remain outside source-visible proof. Comparison 1 with coverage 1 is input coverage evidence, not proof of accepted or valid ADI state.

## Validation

Run `python3 .ci/native-tests/run_tests.py`. Existing native/core/loader/staging tests remain, with normal-order expectations updated. Actual production bodies compile against synthetic VM/I/O doubles. Expanded fixtures cover cold/new UUID staging, reused same/different identities, actual synthetic start/end provisioning followed by cached OTP, all staging faults before native calls, invalid library paths, setup failure after promotion, caller input preservation, normal concurrency and unchanged isolated behavior.

Actual imported-hook fixtures cover exact/chunked/mismatched/partial/EOF/extra bytes, FD reuse and unknown offsets, O_RDWR reads, write invalidation, positive reads with failed guest copy, sticky mismatch, input/cumulative budgets, overflow, event/descriptor limits, errno/result preservation and secret canaries. Enabled and disabled observers produce identical intercepted host-I/O counts. The actual Swift v1/v2 decoder fixture executes when `swiftc` is present; absence is an explicit skip, not a pass.

No real Apple/ADI library, account, provisioning data or network is used. Full Swift/macOS native compilation and coordinated device behavior remain unverified.
