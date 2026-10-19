#include "vm_initialization_diagnostics.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>

// Pure value/header contract: no loader, engine, guest, files or network.
using namespace vm_initialization_diagnostics;
namespace bf = bounded_fault_diagnostics;
static unsigned checks = 0;
#define CHECK(value) do { ++checks; if (!(value)) return 1; } while (0)
static bool empty(const bf::Snapshot &value) {
    if (value.available || value.access != bf::Access::Unknown || value.width != -1 ||
        value.region != bf::Region::Unknown || value.pc_library != -1 ||
        value.pc_offset != -1 || value.guard != bf::Guard::Unknown) return false;
    for (const auto &asset : value.assets) {
        if (asset.known) return false;
        for (const auto byte : asset.bytes) if (byte != 0) return false;
    }
    return true;
}
static_assert(std::is_aggregate<ProcedureFailure>::value, "procedure remains aggregate");
static_assert(std::is_aggregate<ConstructorFailure>::value, "constructor remains aggregate");
int main() {
    ProcedureFailure default_procedure;
    ConstructorFailure default_constructor;
    CHECK(empty(default_procedure.fault));
    CHECK(empty(default_constructor.fault));
    const ProcedureFailure old_procedure{Reason::EngineError, 13};
    const ConstructorFailure old_constructor{Kind::DTInitArray, Reason::EngineError, 13, 0, 47};
    CHECK(empty(old_procedure.fault));
    CHECK(empty(old_constructor.fault));
    CHECK(description(old_constructor) == "Library constructor execution failed [v1;kind=dt_init_array;reason=engine_error;engine=13;library=0;initializer=47]");
    char wire[bf::wire_capacity] = {};
    CHECK(!bf::encode(old_constructor.fault, wire) && wire[0] == 0);
    bf::Snapshot snapshot;
    snapshot.available = true; snapshot.access = bf::Access::ReadProtection;
    snapshot.width = 8; snapshot.region = bf::Region::LowGuard;
    snapshot.pc_library = 0; snapshot.pc_offset = 32; snapshot.guard = bf::Guard::Intact;
    snapshot.assets[0].known = true;
    const ProcedureFailure explicit_procedure{Reason::EngineError, 13, snapshot};
    const ConstructorFailure explicit_constructor{Kind::DTInitArray, Reason::EngineError, 13, 0, 47, snapshot};
    CHECK(explicit_procedure.fault.available && explicit_procedure.fault.width == 8);
    CHECK(explicit_constructor.fault.available && explicit_constructor.fault.pc_offset == 32);
    const auto normalized_constructor = normalized(explicit_constructor);
    CHECK(normalized_constructor.fault.assets[0].known);
    CHECK(normalized_constructor.fault.access == bf::Access::ReadProtection);
    CHECK(bf::encode(normalized_constructor.fault, wire));
    CHECK(std::string(wire) == "v1;p0_fault_diag1;1;8;1;0;32;1;" + std::string(64, '0') + ";-");
    CHECK(description(explicit_constructor) == description(old_constructor));
    auto copy = explicit_constructor;
    copy.fault.width = 16;
    CHECK(explicit_constructor.fault.width == 8 && copy.fault.width == 16);
    copy.reason = Reason::InvalidVM;
    CHECK(empty(normalized(copy).fault));
    copy.reason = Reason::PreviouslyFailed;
    CHECK(empty(normalized(copy).fault));
    const auto legacy_invalid = normalized({Kind::Unknown, Reason::InvalidVM, -1, -1, -1});
    CHECK(empty(legacy_invalid.fault) && legacy_invalid.reason == Reason::InvalidVM);
    CHECK(checks == 18);
    std::printf("{\"checks\":%u,\"guest_execution\":false,\"engine_linked\":false}\n", checks);
}
