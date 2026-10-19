# Checked VM setup host regression

`test_vm_setup_host.py --unicorn-include /trusted/headers --output /tmp/vm-setup-checks`
compiles the entire production loader against sparse host API doubles. It needs
headers only, does not link Unicorn, and aborts if `uc_emu_start` is called.
The wrapper's exact setup prefix (through assignment of the shared VM) and
`IsolatedOTPVM` declaration, and OTP/provisioning output-buffer preparation
blocks are extracted unchanged into the test translation unit. Library loading,
constructors, provisioning operations and guest instructions are not executed.

The test injects failure at each of 16 setup API calls in both legacy constructor
argument modes. Every failure throws a controlled exception, and any successfully
opened engine is closed exactly once. The low protected page remains `UC_PROT_NONE`.
It checks that a failed normal construction latches before a shared VM exists,
subsequent normal setup does not retry, and an isolated scope restores the normal
failure latch. It also checks post-open wrapper failure latching and preservation
of populated normal state when isolated construction fails, plus successful
construction/destruction.

The driver runs normal, optimized (`-O2 -DNDEBUG`), and ASan/UBSan variants,
records exact source hashes, and rejects source changes during validation.
LeakSanitizer is explicitly disabled for executor compatibility; engine ownership
is independently counted by the fixture. This does not establish native device,
real-engine, proprietary-library compatibility or a fix for initializer 47.

Output-buffer cases exhaust every OTP/provisioning reservation position and inject
failures into the SPIM transfer and each provisioning zero-fill. They require a
latched controlled error, no low-page write, and no guest execution. Success paths
are also exercised. These block tests do not execute the full wrapper.
