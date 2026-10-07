# Maintained Anisette native tests

Run `python3 .ci/native-tests/run_tests.py` with Python 3 and a C++17 compiler.
The suite compiles the maintained native wrapper and selected actual loader
functions against synthetic I/O/Unicorn test doubles. It reads production Swift
metadata directly for finite allowlist and no-provisioning checks.

Covered: checked normal staging faults, prior-blob preservation, saved-input
handling, normal/isolated boundaries, concurrent requests, bounded/disabled
trace, VM lifetime/resource cleanup and read-only isolated containment.

The trace-disabled case edits only a disposable compiler input, never product
source. No historical source transform is imported or invoked. Fixtures use
synthetic data and do not call Apple. The existing Swift cleanup lifetime race
is intentionally unchanged. Full `swift test`, Xcode/iOS and real-device Apple
authentication remain separate required checks.

Provenance: the runtime fault matrices and test doubles were ported from
NRG-Wardog/sidestore-auto-refresh at
141776ba6ba38fc04a5e77f68b0cfc4e6c8842ee. The original MIT attribution is in
NOTICE-NRG-Wardog. Upstream source remains under its original LICENSE.
