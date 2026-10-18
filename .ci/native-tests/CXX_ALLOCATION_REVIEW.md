# C++ allocation import correction

Basis: AnisetteKit 9c876820d102affe2f55ee4b7f735fff6abd990a, selected by
builder c477b44ad47f5e87e6a05b16dfb165c0065adc73.

Device report: constructor library 0 / array ordinal 1 failed with Unicorn
engine 12. The exact selected Unicorn 2.1.4-multiarch header defines 12 as
UC_ERR_WRITE_PROT. The loader maps its zero page [0,65536) UC_PROT_NONE;
all other regions are writable. The report has no fault address or program
counter, so it does not by itself identify the offending instruction.

Static corroboration, not device identity proof:
The current default metadata URL is https://zzz.haus/oda.json.
Downloaded 2026-10-18. Decoded ZIP SHA256:
a2f9aeef4cc31efda69ecdceeadd0f1bbd04199e6339b880636c14a3ecba2b96.
The metadata's declared SHA256 differs:
9d412b76953098ad5b4dccb9337e31652b9f29140ab2ec554bd9003ae226ee3f.
Do not treat that archive as a verified device input or execute its contents.
Read-only ELF parsing/disassembly only was performed.

libstoreservicescore.so SHA256:
bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4
Its DT_INIT_ARRAY[1] relocation addend is 0xdaad8. The function calls
PLT 0x233450 at 0xdadf4 with W0=32. That PLT uses GOT 0x242690, whose
R_AARCH64_JUMP_SLOT symbol is _Znwm. At 0xdae10 the function stores a byte
at [X0+0x1a]. The prior import router returns zero for _Znwm because it has
no handler. With these library bytes that creates a write to address 0x1a.
This is a concrete independent implementation defect consistent with the
reported protection fault, not proof of exact cached bytes on the device.

Correction:
- Handle exact 64-bit Itanium throwing operator new/new[] (_Znwm/_Znam).
- Use the production VM monotonic allocator with 64-byte alignment.
- Zero size consumes a distinct allocation; overflow/exhaustion is rejected
  before PageAllocator's abort path. Stop and poison the VM on allocation or
  register access failure. Guest exception unwinding is not implemented, so
  failure is deliberately fail-closed rather than pretending new succeeded.
- Explicit ordinary/sized delete uses the existing monotonic free behavior.
- The procedure driver rejects a poisoned initialization even if a host callback
  stops execution with an otherwise successful engine return and sentinel PC.
- Do not alias aligned/nothrow overloads, skip constructors, relax null-page
  protection, fabricate identities, or change unrelated fallback imports.

Validation: test_cxx_allocation.py compiles the actual production loader,
links retained PageAllocator code into one host-only harness (32 checks), and
uses host API doubles in a second harness invoking the actual import router,
allocation hook and procedure driver (51 checks). Both pass in normal,
optimized, and ASan/UBSan variants: 249 checks total. Hook checks cover exact
new/delete routing, zero-size allocation, exhaustion/overflow, register read
and write failures, poison-and-stop behavior, and rejection of a poisoned
procedure despite a synthetic successful engine result and return PC. No Unicorn engine is
linked or executed, no downloaded executable is run, and no authentication
is attempted. Leak sanitizer is explicitly disabled for this environment.
The driver currently uses ELF linker garbage collection (Linux), so it is
not a macOS CI integration until the appropriate dead-strip option is added.

Independent review on 2026-10-18 cleared this candidate for normal platform
integration after independently rerunning all 249 allocation/hook checks and
713 metadata checks in each of three variants. Device login is not verified.
An ordinary platform build, fresh immutable source seal, and device validation
are still required before any release claim.
