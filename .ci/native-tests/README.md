# Maintained Anisette native tests

Defensive ELF metadata checks: run
`python3 .ci/native-tests/test_elf_metadata_bounds.py --output RESULTS`.
This compiles the production metadata helper and runs 713 ordinary host-only
checks in normal, optimized and fail-fast ASan/UBSan modes. The sample contains
only metadata and data objects, with no executable segment, guest instructions,
constructor pointers, proprietary input or Unicorn engine. It tests valid
metadata, count/name/index limits, checked arithmetic, allocator-capacity
predicates and boundary rejection. `--disable-leak-sanitizer` is an explicit
reported override only for executors where LSan cannot run, such as ptrace;
ASan and UBSan still run and any stderr or nonzero exit fails the driver.

The bounded loader requires checked DT_HASH/DT_SYMENT metadata. GNU-hash-only
objects, recognized DT_REL/DT_RELSZ tags with nonzero values, unsupported nonzero
types within the recognized RELA/JMPREL tables, overlapping PT_LOAD ranges and
unsupported reserved symbol definitions fail closed. RELA requires its address,
size and entry-size tags together; JMPREL requires its address, size and format
tags together. Complete zero-sized groups are valid and perform no table reads;
missing companions or an invalid entry format fail even when size is zero.
The unit matrix covers every presence combination for both groups at zero and
nonzero sizes. Valid named imports and zero-valued/absolute definitions remain
supported.

This narrow parser does not interpret or validate RELR (DT_RELR/DT_RELRSZ/
DT_RELRENT), Android packed DT_ANDROID_REL/DT_ANDROID_RELA and related size tags,
or other unrecognized dynamic relocation encodings. Such tags remain ignored;
this is not universal rejection of every unsupported relocation format.
These checks establish host parser behavior, not iOS TCI or device login.

Run `python3 .ci/native-tests/run_tests.py` with Python 3 and a C++17 compiler.
The suite compiles the maintained native wrapper and selected actual loader
functions against synthetic I/O/Unicorn test doubles. It reads production Swift
metadata directly for finite allowlist and no-provisioning checks.

Covered: checked normal staging faults, prior-blob preservation, saved-input
handling, normal/isolated boundaries, concurrent requests, bounded/disabled
trace, VM lifetime/resource cleanup and read-only isolated containment. The local
staging-order experiment adds cold/reused/freshly-provisioned ordering coverage,
pre-native fault checks and passive v2 input comparison/coverage fixtures; see
[ADI_CONSUMPTION_DEBUG.md](ADI_CONSUMPTION_DEBUG.md) for limits and wire semantics.

The trace-disabled case edits only a disposable compiler input, never product
source. No historical source transform is imported or invoked. Fixtures use
synthetic data and do not call Apple. The existing Swift cleanup lifetime race
is intentionally unchanged. Full `swift test`, Xcode/iOS and real-device Apple
authentication remain separate required checks.

Constructor diagnostics: `test_constructor_diagnostics.py --unicorn-root PATH`
links the full production loader to an explicitly selected installed Unicorn
engine and runs only owned synthetic AArch64 instructions. Add `--sanitizers`
for ASan/UBSan, and `--output FILE` for hashes and results. Only use
`--disable-leak-sanitizer` when the executor prevents LSan; the result discloses
that override. The platform gate can compile `fixtures/constructor_diagnostics.cpp`
directly against the same pinned native framework used for the existing
83-check `android_tls_constructor.cpp` fixture. Its stdout is one JSON line:
schema 1, positive `checks`, zero `failures` and `skipped`, finite `case_ids`,
`ADI_executed=false`, and `device_validation=false`.
The standalone driver enforces the sealed 2,105-check/15-case result exactly,
including types and keys, and rejects any fixture stderr. Sanitizer builds use
`-fno-sanitize-recover=all` and fail-fast runtime options. Run
`python3 .ci/native-tests/test_constructor_diagnostics_driver.py` for the separate
six-case parser/sanitizer-option rejection suite; it does not change the
eight-case aggregate suite.

The new observer is caller-owned and does not change constructor success, which
still requires normal return regardless of incidental W0. It captures first
failure before poisoning; later calls keep the existing fail-closed behavior.
The actual wrapper JSON-boundary test covers the canonical error, appended
trace, no ADI execution, unchanged identity caches, and poisoned retry rejection.
See [CONSTRUCTOR_DIAGNOSTICS.md](CONSTRUCTOR_DIAGNOSTICS.md) for the finite wire
contract. Synthetic or upstream-engine results never establish native-fork or
real-device compatibility.

Provenance: the runtime fault matrices and test doubles were ported from
NRG-Wardog/sidestore-auto-refresh at
141776ba6ba38fc04a5e77f68b0cfc4e6c8842ee. The original MIT attribution is in
NOTICE-NRG-Wardog. Upstream source remains under its original LICENSE.
