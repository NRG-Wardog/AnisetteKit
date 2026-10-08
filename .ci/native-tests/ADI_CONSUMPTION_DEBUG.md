# Temporary ADI consumer observation (local diagnostic branch)

This is an observer-only experiment based on maintained AnisetteKit62ce85c. It does not fix ADI, change identities, retry OTP, reorder setup/staging, modify native return values or repair errno propagation. It must not be merged into parity migration or selected by integration pins without review.

The actual device141776 trace proves successful temporary-file readback and rename, followed by native OTP -45061. That host staging path is separate from ADI's imported open/read hooks. This observer records those actual hooks during one normal OTP invocation, including its setup calls.

## Bounds and wire schema

The central `ADI_CONSUMER_DEBUG_ENABLED` switch defaults to1 in `Native/Loader/adi_consumption_debug.h`; compile it as0 or remove the isolated component after diagnosis. A thread-local pointer is scoped to an invocation under the existing native mutex and restored on exit. Recording uses fixed storage, 32 events and64 descriptor-category entries. It reserves16 rows for setup (first observations) and16 for OTP (latest observations); early setup cannot consume the OTP budget, and repeated OTP reads cannot hide a later failure. Either overflow sets the explicit truncated bit. Retained events stay in their original order. Serialization is capped at2048 bytes.

Private JSON key `v3_native_consumption` contains `v1|truncated|row...`. Each row has eight canonical decimal integers:

1. Phase:0unknown,1constructors,2library initialization,3provisioning path,4Android ID,5OTP.
2. Operation:0open,1read.
3. Target:0other absolute path,1exact expected adi.pb,2relative path,3unreadable or expected path unavailable,4untracked descriptor (including an FD opened before this observer or tracking overflow).
4. Result:−1failure,0EOF,1success/data.
5. Immediate host errno on an actual open/read failure,1..4095;0unknown/not applicable. An absent FD does not invent EBADF.
6. Requested read count;0for open.
7. Returned positive read count;0for open/error/EOF.
8. Actual guest-memory-copy Unicorn status0..32;−1not attempted/unknown.

Counts above1,048,576 are represented by1,048,577 (saturated, not exact). Descriptor numbers, pointers, paths, identifiers, file contents and hashes are never serialized. Tracking overflow also sets the truncated flag; untracked never implies an observed other path. Expected-path formatting occurs only after the original null-argument guard. Close only clears internal descriptor-category ownership; it emits no misleading host-close-success claim.

The SDK removes the metadata before constructing successful headers. Failed responses include it only after strict finite/range/canonical-number validation in a separate `DEBUG_TEMPORARY_ADI_CONSUMPTION` suffix. **Current SideStore does not yet decode this suffix. A separately reviewed source-owned SideStore decoder and privacy/round-trip tests are required before device delivery.** Existing native-stage suffix behavior is retained, but consumers must strip the new suffix before their existing classification.

## What this establishes and what it cannot

It can show whether ADI opens/reads the expected final path during setup or only OTP, whether host open/read fails, and whether guest-memory copying fails. The original inherited hook behavior is preserved, including positive read counts despite a guest-copy failure and stale guest errno after read failure.

No extra filesystem reads or guest-memory probes are introduced. Path equality is not inode/content equality. Only imported open/read are observed; absence of events is not proof that lstat/fstat or an unsupported/direct syscall did not execute. Opaque ADI parsing, encryption and identity checks remain outside source-visible proof.

## Validation

Run `python3 .ci/native-tests/run_tests.py`. Existing native/core/loader/staging tests remain. The new fixture compiles actual maintained hook bodies and tests enabled/disabled observation, exact/relative/other/unreadable path classification, normal copy, EOF, host EBADF, missing-file ENOENT, injected guest-copy failure, preserved original results/guest errno, finite saturation, event overflow, nested observer restoration and secret canaries. The actual Swift decoder is extracted and executed when swiftc is available; absence is an explicit skip, not a pass.

No real Apple/ADI library, provisioning data, account or network is used in these tests. macOS native compilation and a coordinated device experiment remain pending.
