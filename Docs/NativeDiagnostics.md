# Native diagnostics for the 6.0 diagnostic build

## Two deliberately different controls

`AnisetteKitLogging.setLogging(_:)` remains the existing mutable switch for
Swift verbose messages and AnisetteKit native-wrapper messages. Its behavior is
not changed to enable all Unicorn logging.

For the pinned Unicorn artifact, the separate opt-in is the process environment
variable `ANISETTEKIT_UNICORN_DIAGNOSTICS=errors`. Set it during application
startup, before **any** code in the process first uses Unicorn. The AnisetteKit
emulator samples it once, immediately before its first `uc_open`. Missing,
`off`, numeric, and unrecognized values select off. There is no arbitrary mask
input. The SideStore diagnostic integration samples its existing AltSign verbose
logging preference at launch to set `errors` or `off`, before configuring its
normal mutable loggers. A preference change needs a full app termination and
relaunch to affect Unicorn; changing the live verbose switch is insufficient.
A DEBUG build's existing global-logging defaults may enable that launch preference.

The wrapper installs `UNICORN_LOG_LEVEL=0xC10` for the opt-in, otherwise `0`, and
`UNICORN_LOG_DETAIL_LEVEL=2`, overriding unmanaged launch values such as an
all-bits mask. An environment-write failure fails VM initialization before
`uc_open`; it does not continue with an unknown mask. Configuration is shared
across concurrent AnisetteKit VM creation and not retried or changed in-process.
The original native setup error handling still applies.

**Restart is required to enable or disable Unicorn diagnostics.** The pinned
logger caches the mask and detail independently per translation unit at first
use. `setLogging(false)` cannot clear those caches. This is a category-bounded,
process-lifetime option, not a per-attempt switch or a byte/event volume cap.
Do not mutate the raw Unicorn environment afterward or let another consumer
initialize Unicorn before this configuration. This wrapper cannot undo caches
created by another consumer, nor control an unrelated library changing process
environment variables.

## Fields kept and fields omitted

The mask is `CPU_LOG_INT | LOG_UNIMP | LOG_GUEST_ERROR` (`0xC10`). It excludes
TCG IR/assembly, MMU and strace categories. Detail 2 adds source basename and
line, not full source paths or additional payload detail. The known ARM sites
emit exception/transition descriptions, instruction encodings, PCs/fault
addresses and numeric control/error fields. Addresses and encodings can still
be sensitive diagnostic context; keep diagnostics private and inspect before
sharing. This is not a full linked-runtime non-secret-output certification.

The emulator wrapper independently retains fixed phase names, numeric native
results, lengths/presence, known library identity and existing numeric execution
diagnostics. Existing structured timing and bounded traces remain unchanged.
File/container/provisioning paths are omitted. Library labels are restricted to
`libstoreservicescore.so`, `libCoreADI.so`, or `other`. Android guest log tags and
format strings are not read or printed, even if wrapper logging is enabled;
only numeric priority and argument presence remain. Library parser failure
reasons are fixed source literals, not arbitrary guest strings.

These changes do not log device IDs, UUID paths, OTP/MID/provisioning payloads,
request/response bodies, or headers. They do not change auth, library acquisition,
WorkQueue ABI, VM execution, provisioning, or state-cleanup behavior. They do not
make the unrelated host loader or the full application log stream an audited
allowlist. Native output goes directly to stdout/stderr and may be captured
before downstream Swift formatting, so that formatter is not the privacy boundary.

## Pin and evidence limits

The package URL/checksum stay unchanged:

- Unicorn commit: `a53ddc9ac6d65b24936d4a37917333fcd816cfd0`
- Release: `2.1.4-xcf-a53ddc9`
- SHA-256: `52e4ac9e2d704c4941adc2c381df8706aabf673dc843611a90b33ad349d562db`
- [Pinned logger implementation](https://github.com/mahee96/unicorn/blob/a53ddc9ac6d65b24936d4a37917333fcd816cfd0/qemu/include/qemu/log.h)
- [Pinned AArch64 helper](https://github.com/mahee96/unicorn/blob/a53ddc9ac6d65b24936d4a37917333fcd816cfd0/qemu/target/arm/helper-a64.c)

The source review covered discovered mask sites in seven ARM files: `helper.c`,
`helper-a64.c`, `translate-a64.h`, `arm-powerctl.c`, `m_helper.c`, `arm-semi.c`,
and `vfp_helper.c`. It was not an exhaustive source or linked-binary audit. No
runtime trace proves that every possible emitted value is nonsecret. The
all-bits upstream toggle is deliberately not restored, without claiming it
was demonstrated to dump passwords or OTPs. A native success followed by an
HTTP 503 before password proof does not establish the reason for that response;
these diagnostics are not a diagnosis of the network/authentication failure.

## Source-owned verification

Run `python3 .ci/native-logging/test_native_logging_contract.py` from the repo.
The tests compile only a policy harness, fake engine-register hook and actual
log statements with fake values. They check default/off, exact opt-in,
unrecognized inputs, the all-bits cap, failure-before-open, concurrent
initialization, immutable lifetime, POSIX and fake Windows environment paths,
and output field omission/preservation. No Unicorn binary, APK, guest ELF,
account, pairing/provisioning data or authentication is used. The Windows test
checks branch logic with a fake setter, not a native Windows toolchain build.

The existing maintained native test suite remains a separate required check.
These contracts are not iOS build verification or a real guest/runtime test.
