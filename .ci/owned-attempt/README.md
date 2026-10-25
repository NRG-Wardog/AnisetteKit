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
