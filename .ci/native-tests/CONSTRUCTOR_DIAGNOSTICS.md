# Constructor failure diagnostic, version 1

Exact ASCII format (fixed order, no inner whitespace):

`Library constructor execution failed [v1;kind=dt_init;reason=engine_error;engine=13;library=0;initializer=0]`

Only constructor failure emits this description. Success still depends on
`execution_completed`, never the incidental W0 value. `engine` is the actual
Unicorn API scalar (including zero after an unsupported interrupt stopped the
engine), not the synthetic procedure return encoding or an ADI status.

Every numeric field is decimal. `engine` permits -1 or 0...255; library and
initializer permit -1 or 0...65535, zero-based. -1 means unavailable or outside
the bounded range. DT_INIT has initializer 0. An init-array entry-read failure
reports its actual read status and index, without its address or pointer value.

Coherent tuples:

- `unknown` + `unknown`, `invalid_vm`, or `previously_failed`: all numeric fields -1
- `dt_init` or `dt_init_array` + `engine_error`: engine 1...255 or -1
- `dt_init` or `dt_init_array` + `unsupported_interrupt`: engine 0...255 or -1
- `dt_init` or `dt_init_array` + `unexpected_return`: engine 0
- `array_entry_read` + `entry_read`: engine 1...255 or -1

Unknown enum values and incoherent tuples normalize to unknown/unknown with all
numeric fields -1. Invalid/reused VM reasons discard all unrelated fields.
Out-of-range numeric values normalize to -1. Nonzero DT_INIT initializer or
nonzero unexpected-return engine normalizes the entire tuple to unknown.

The observer is a caller-owned copy, initialized every call; no diagnostic data
is retained in the VM or a global. The first result is copied before the VM is
poisoned. Reusing that VM remains blocked. The wrapper's existing string
`VM initialization previously failed; restart required` remains unchanged.

No raw pointer, register, instruction, address, library name, filename/path,
guard, device identity, blob, guest string, or arbitrary engine error text is
accepted by the serializer. No identity reset, reprovisioning, retry workaround,
emulator behavior fix, or fail-closed bypass is part of this diagnostic change.
