# Owned ODA attempt qualification

Offline native command, runnable from any working directory:

    python /path/to/AnisetteKit/.ci/owned-attempt/run.py --unicorn-archive /path/to/Unicorn.xcframework.zip

The runner verifies the existing Package.swift SHA256 before extracting headers
or the macOS static library. It does not fetch or execute guest ADI libraries.
Linux runs lifecycle, confined-filesystem and real C ABI/mock-engine fixtures.
macOS additionally runs actual pinned Unicorn against source-owned synthetic
ARM64 return/loop/cancellation/constructor procedures.

On macOS, compile and execute the owned Swift fixtures (NOT the legacy online
provisioning tests):

    swift test --filter OwnedOnDeviceAnisetteAttemptTests

Swift fixtures use synthetic bytes only on paths cancelled before native entry,
and a protocol fixture for memory-only client policy. An internal per-attempt
URLProtocol configuration also covers fresh lookup failure and cancellation
while the lookup is in flight. These fixtures never contact Apple.
These are not proof of real Apple provisioning or device authentication.

Ownership review scope:
- Control owns absolute deadline, single admission, cancellation and drain state.
- AnisetteOwnedAttempt owns independent VM/session/identity, retained descriptors
  and immutable exact-two-library snapshot. Only the native owner touches Unicorn.
- Native cleanup recursively traverses held descriptors, never follows symlinks,
  requires the owned root identity and private parent; a replacement root produces
  cleanup failure and remains untouched.
- Swift fetch always drains before returning, including cancellation or Apple
  network failure; memory-only client never reads/writes/deletes disk state.
- SideSign's enclosing attempt context must keep provider admission closed until
  fetch returns and commit staged data only after stable-identity auth success.

A blocked regular-file syscall can delay drain. No timeout claims that such a
worker is quiescent; no thread killing or early VM destruction is used.

## Trusted built-in startup compatibility

After synthetic native success, the focused workflow downloads the existing
recognized Apple Music APK from Apple's HTTPS endpoint. The APK byte count is
checked and its observed SHA is recorded, not represented as an independently
expected APK digest. Only the two reviewed library entries are extracted after
unique-entry, exact-size and exact SHA256 checks. The C++ fixture checks those
same immutable byte buffers again immediately before native staging.

`run_verified_startup.py` then runs the actual pinned engine and actual core with
a random synthetic UUID and deliberately invalid three-byte blob. It requires
library initialization, provisioning-path and Android-ID setup, invalid-input
rejection, native drain and owned cleanup. The fixture contains no account or
network transport. This is startup/syscall compatibility, not successful Apple
provisioning, authentication or device validation. The external fixture timeout
is 90 seconds, independent of the 60-second native budget. Receipts contain only
fixed outcomes, synthetic-fixture diagnostics and verified dependency digests.
