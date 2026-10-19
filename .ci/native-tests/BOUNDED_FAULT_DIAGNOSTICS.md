# Bounded constructor-fault successor (not deployed)

Base: AnisetteKit e72d04b84123823c93e9162daffa73b7afcfd2c9, tree
a03f5a4284b67560629cdb52b8e6b246b835a56a. This candidate is separate from the
frozen A+B build/capture. No guest fault has been diagnosed or repaired here.

## Runtime scope

A separate READ_PROT | WRITE_PROT | FETCH_PROT hook records only the first
protection fault of each procedure. It always returns false. It makes no engine
calls, reads no memory, and never maps, protects, retries, logs, allocates, or
changes the emulation status. The existing UNMAPPED handler is unchanged.
A fixed per-VM pending record is reset before every procedure (including invalid
calls). Its internal target address is never serialized. Returned observations
are caller-owned copies. Existing caller synchronization requirements are unchanged.

After failure, the existing checked final PC read is reused. Only a uniquely
containing loaded-library mapping can produce an ordinal and PC-minus-base
(the mapped base represents min_vaddr). This is one final observation, not a
history or evidence of pointer origin. Width is 1...256 or unknown. Crossing or
overflowing regions are unknown. No target address or target offset is emitted.

After stop, uc_mem_regions is inspected for the low guard. At most 256 metadata
entries are inspected; the API result is always freed. The complete list is
checked for invalid ranges, unknown permission bits and overlapping regions
before deciding, so malformed/ambiguous metadata takes precedence regardless
of order (including a malformed unrelated tail). A single complete
PROT_NONE low region yields intact; accessible low metadata yields changed;
missing/split/ambiguous/malformed/failed metadata is unknown. This describes the
low guard only; it does not claim every VM mapping is correct. No memory is read
by this inspection. A diagnostic API failure cannot replace the saved original
engine or existing PC-read failure, return encoding, completion bit, or poison.

The exact already-read load buffer is hashed before guest writes. No path is
reopened. Apple builds use the system CommonCrypto SHA-256 streaming primitive,
with checked chunks no larger than 65536 bytes. Other production platforms
explicitly return unknown without adding a crypto dependency. Failure returns
unknown and cannot fail a load. A fixed digest is retained per loaded library;
only ordinals 0 and 1 are exported. Last-import classification is deliberately
deferred; no import names, arguments, pointers or guest strings are added.

## Separate wire and compatibility

The original constructor v1 error description, reason, engine, library, and
initializer are byte-for-byte unchanged. Public C ABI/function signatures are
unchanged. Internal C++ VM/LibraryInfo/ProcedureFailure/ConstructorFailure layouts
change and require recompiling all consumers; mixing old/new native objects is
unsupported.

A separate optional JSON string, v3_constructor_fault, is appended through the
existing caller-owned NativeOTPTrace only on a constructor procedure failure.
The formatter uses a fixed 256-byte buffer and emits fewer than 256 ASCII bytes:

    v1;p0_fault_diag1;access;width;region;pc_library;pc_offset;guard;asset0;asset1

Exactly ten fields and fixed order. Source marker p0_fault_diag1 is a diagnostic
schema/implementation label, NOT a binary SHA or proof of deployed provenance.
Any future capture must bind this label and asset ordinals/digests to its exact
source commit/tree, manifest, build/capture IDs and input hashes. This local
candidate does not create or modify that capture envelope.

- access: 0 unknown, 1 read protection, 2 write protection, 3 fetch protection
- width: -1 unknown or 1...256
- region: 0 unknown, 1 low guard, 2 heap, 3 stack, 4 TLS, 5 errno, 6 loaded library,
  7 other (no arbitrary address)
- pc_library: -1 unknown or 0...65535
- pc_offset: -1 unknown or 0...805306367; both PC fields must be known together
- guard: 0 unknown, 1 intact, 2 changed
- asset0/asset1: '-' unknown or exactly 64 lowercase SHA-256 hexadecimal bytes

Unknown access forces width/region unknown; unknown width forces region unknown.
Unknown enum and out-of-range values normalize to unknown. No enum is stringified
from arbitrary input. The Swift consumer rejects unknown schema/marker, extra
fields, noncanonical or oversized numbers, incoherent tuples, uppercase/invalid
hashes, non-ASCII and over-budget strings. It removes the private field in all
three response paths before returning headers/provisioning results, and adds
only the accepted bounded value to an error suffix. Legacy description() remains
unchanged. Optional trace allocation failure leaves the original error JSON intact.

## Host-only verification and explicit remaining gates

Run test_bounded_fault_host.py with --unicorn-include pointing at trusted HEADERS
only and --output outside the repository. The full production loader is compiled
against synthetic API outcome doubles, never a Unicorn library. It calls no
instruction interpreter. Each of six variants (normal, optimized, fail-fast
ASan/UBSan; production unknown hash and explicit host Apple-hash adapter) checks:
first event/reset/separate VMs; false callback/no engine or memory calls;
hook-registration unwind; original engine13 and read-error preservation; metadata
read failures; unchanged mappings; bounded/crossing/overflow/ambiguous regions
and PC; exact legacy error; poison; finite wire; digest vectors/chunking/failure;
each synthetic asset-byte mutation; and replacement of the file after read while
the loaded bytes and digest remain tied to the original buffer.

The OpenSSL adapter exists only under .ci fixtures and never enters production.
It checks the production CommonCrypto call shape and buffer flow, NOT Apple ABI
or linkage. Native CommonCrypto SDK/link checks remain mandatory before a future
native build; no Apple link success is claimed. The exact Swift parser's negative
harness runs if swiftc exists; absence is recorded as not_run, never a pass. Source
flow checks alone are not runtime proof. ASan/UBSan run with leak sanitizer
explicitly disabled in this executor, as reported. Existing host setup, memory,
C++ allocation, metadata, wrapper/trace, and constructor-driver suites remain
required. Do not run the unfiltered package or real-engine constructor fixture
without separate authorization. Native/device execution and initializer47 repair
remain unproven. Independent review and source-inventory composition are gates.
