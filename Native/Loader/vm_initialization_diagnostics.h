#ifndef VM_INITIALIZATION_DIAGNOSTICS_H
#define VM_INITIALIZATION_DIAGNOSTICS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include "bounded_fault_diagnostics.h"

// Caller-owned observations only. The legacy description is unchanged. The
// separate fault snapshot permits a bounded relative PC, never raw addresses,
// registers, guest strings, identities, filenames or arbitrary error text.
namespace vm_initialization_diagnostics {
enum class Kind { Unknown, DTInit, DTInitArray, ArrayEntryRead };
enum class Reason {
    Unknown, EngineError, UnsupportedInterrupt, UnexpectedReturn, EntryRead,
    InvalidVM, PreviouslyFailed
};
struct ProcedureFailure {
    Reason reason = Reason::Unknown;
    int engine = -1;
    bounded_fault_diagnostics::Snapshot fault = {};
};
struct ConstructorFailure {
    Kind kind = Kind::Unknown;
    Reason reason = Reason::Unknown;
    int engine = -1;
    int library = -1;
    int initializer = -1;
    bounded_fault_diagnostics::Snapshot fault = {};
};
inline int ordinal(size_t value) noexcept { return value <= 65535 ? static_cast<int>(value) : -1; }
inline int bounded(int value, int maximum) noexcept { return value >= 0 && value <= maximum ? value : -1; }

// Normalize all fields, including cross-field coherence, before serialization.
// Unknown values never become arbitrary strings or invented engine statuses.
inline ConstructorFailure normalized(ConstructorFailure value) noexcept {
    if (value.reason == Reason::InvalidVM || value.reason == Reason::PreviouslyFailed)
        return {Kind::Unknown, value.reason, -1, -1, -1};
    if (value.kind == Kind::DTInit || value.kind == Kind::DTInitArray) {
        if (value.kind == Kind::DTInit && value.initializer != 0) return {};
        switch (value.reason) {
        case Reason::EngineError:
            if (value.engine == 0) return {};
            break;
        case Reason::UnsupportedInterrupt: break;
        case Reason::UnexpectedReturn:
            if (value.engine != 0) return {};
            break;
        default: return {};
        }
    } else if (value.kind == Kind::ArrayEntryRead) {
        if (value.reason != Reason::EntryRead || value.engine == 0) return {};
    } else {
        return {};
    }
    value.engine = bounded(value.engine, 255);
    value.library = bounded(value.library, 65535);
    value.initializer = bounded(value.initializer, 65535);
    value.fault = bounded_fault_diagnostics::normalized(value.fault);
    return value;
}
inline std::string description(ConstructorFailure value) {
    value = normalized(value);
    const char *kind = "unknown", *reason = "unknown";
    switch (value.kind) {
    case Kind::DTInit: kind = "dt_init"; break;
    case Kind::DTInitArray: kind = "dt_init_array"; break;
    case Kind::ArrayEntryRead: kind = "array_entry_read"; break;
    default: break;
    }
    switch (value.reason) {
    case Reason::EngineError: reason = "engine_error"; break;
    case Reason::UnsupportedInterrupt: reason = "unsupported_interrupt"; break;
    case Reason::UnexpectedReturn: reason = "unexpected_return"; break;
    case Reason::EntryRead: reason = "entry_read"; break;
    case Reason::InvalidVM: reason = "invalid_vm"; break;
    case Reason::PreviouslyFailed: reason = "previously_failed"; break;
    default: break;
    }
    return std::string("Library constructor execution failed [v1;kind=") + kind +
        ";reason=" + reason + ";engine=" + std::to_string(value.engine) +
        ";library=" + std::to_string(value.library) +
        ";initializer=" + std::to_string(value.initializer) + "]";
}
} // namespace vm_initialization_diagnostics
#endif
