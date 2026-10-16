// Own synthetic AArch64 instructions only. Links the full production loader.
// Does not load Apple ADI, provision, or execute device authentication.
#include "elf_loader_emulator.h"
#include <unicorn/arm64.h>
#include <cassert>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <limits>

thread_local bool g_isolated_otp_logging_suppressed = true;
extern "C" void anisetteCoreLog(const char *, ...) {}
using namespace vm_initialization_diagnostics;
static int checks = 0;
static void check(bool value) {
    if (!value) { std::fprintf(stderr, "Synthetic diagnostic check failed after %d checks\n", checks); std::abort(); }
    ++checks;
}
static constexpr uint64_t code = 0x10000000;
static constexpr uint64_t ordinary = code, error_shaped = code + 0x10;
static constexpr uint64_t protected_read = code + 0x20, interrupt = code + 0x30;
static constexpr uint64_t early = code + 0x40, entries_at = code + 0x100;

static void install(EmulatorVM &vm) {
    check(uc_mem_map(vm.uc, code, 0x10000, UC_PROT_ALL) == UC_ERR_OK);
    const uint32_t nonzero[] = {0x12960080, 0xd65f03c0}; // MOV W0,#-45061; RET
    const uint32_t encoded[] = {0x12807e80, 0xd65f03c0}; // MOV W0,#-1013; RET
    const uint32_t fault = 0xf9400008; // LDR X8,[X0], protected null after reset
    const uint32_t trap = 0xd4200000; // BRK #0 (unsupported interrupt)
    const uint32_t stopped[] = {0xd503201f, 0xd65f03c0}; // NOP; RET
    check(uc_mem_write(vm.uc, ordinary, nonzero, sizeof(nonzero)) == UC_ERR_OK);
    check(uc_mem_write(vm.uc, error_shaped, encoded, sizeof(encoded)) == UC_ERR_OK);
    check(uc_mem_write(vm.uc, protected_read, &fault, sizeof(fault)) == UC_ERR_OK);
    check(uc_mem_write(vm.uc, interrupt, &trap, sizeof(trap)) == UC_ERR_OK);
    check(uc_mem_write(vm.uc, early, stopped, sizeof(stopped)) == UC_ERR_OK);
}
static void stop_early(uc_engine *uc, uint64_t, uint32_t, void *) { uc_emu_stop(uc); }
static void expect(const ConstructorFailure &actual, Kind kind, Reason reason,
                   int engine, int library, int initializer) {
    check(actual.kind == kind && actual.reason == reason && actual.engine == engine &&
          actual.library == library && actual.initializer == initializer);
}
static void expect_empty(const ProcedureFailure &actual) {
    check(actual.reason == Reason::Unknown && actual.engine == -1);
}

static void procedure_cases(bool checked) {
    EmulatorVM vm(checked); install(vm);
    ProcedureFailure failure{Reason::EntryRead, 199}; bool completed = false;
    check(run_vm_procedure(&vm, ordinary, {}, 0, 0, &completed, &failure) == -45061);
    check(completed); expect_empty(failure);
    check(run_vm_procedure(&vm, error_shaped, {}, 0, 0, &completed, &failure) == -1013);
    check(completed); expect_empty(failure);
    check(run_vm_procedure(&vm, protected_read, {}, 0, 0, &completed, &failure) == -1000 - UC_ERR_READ_PROT);
    check(!completed && failure.reason == Reason::EngineError && failure.engine == UC_ERR_READ_PROT);
    check(run_vm_procedure(&vm, interrupt, {}, 0, 0, &completed, &failure) == -1000 - UC_ERR_EXCEPTION);
    check(!completed && failure.reason == Reason::UnsupportedInterrupt && failure.engine == UC_ERR_OK);
    check(run_vm_procedure(&vm, early, {}, 0, 1, &completed, &failure) == -1000);
    check(!completed && failure.reason == Reason::UnexpectedReturn && failure.engine == UC_ERR_OK);
    check(!vm.initialization_failed);
    // A later successful procedure resets the observer, including interrupt state.
    check(run_vm_procedure(&vm, ordinary, {}, 0, 0, &completed, &failure) == -45061);
    check(completed && !vm.unsupported_interrupt); expect_empty(failure);
    check(run_vm_procedure(&vm, 0, {}, 0, 0, &completed, &failure) == -1);
    check(!completed && failure.reason == Reason::InvalidVM && failure.engine == -1);
}

static void constructor_success(bool checked) {
    EmulatorVM vm(checked); install(vm);
    EmulatorVM::LibraryInfo lib{};
    lib.name = "SECRET-PATH-IDENTITY-BLOB-DO-NOT-REPORT";
    lib.init_func = error_shaped; lib.init_array = entries_at;
    const uint64_t entries[] = {0, ordinary, error_shaped};
    lib.init_arraysz = sizeof(entries);
    check(uc_mem_write(vm.uc, entries_at, entries, sizeof(entries)) == UC_ERR_OK);
    vm.loaded_libraries.push_back(lib);
    ConstructorFailure failure{Kind::DTInitArray, Reason::EntryRead, 42, 42, 42};
    check(run_library_constructors(&vm, &failure));
    expect(failure, Kind::Unknown, Reason::Unknown, -1, -1, -1);
    check(!vm.initialization_failed);
}

static void constructor_failure(bool checked, uint64_t address, Reason reason, int engine,
                                bool array, size_t index) {
    EmulatorVM vm(checked); install(vm);
    vm.loaded_libraries.emplace_back(); // report zero-based library ordinal 1
    EmulatorVM::LibraryInfo lib{};
    lib.name = "/PRIVATE/UUID/adi.pb?SECRET-TOKEN";
    lib.init_func = array ? ordinary : address;
    if (array) {
        const uint64_t entries[] = {index == 0 ? address : ordinary, address, interrupt};
        lib.init_array = entries_at; lib.init_arraysz = sizeof(entries);
        check(uc_mem_write(vm.uc, entries_at, entries, sizeof(entries)) == UC_ERR_OK);
    }
    vm.loaded_libraries.push_back(lib);
    uc_hook hook = 0;
    if (address == early)
        check(uc_hook_add(vm.uc, &hook, UC_HOOK_CODE, (void *)stop_early, nullptr, early, early) == UC_ERR_OK);
    ConstructorFailure failure;
    check(!run_library_constructors(&vm, &failure));
    expect(failure, array ? Kind::DTInitArray : Kind::DTInit, reason, engine, 1, array ? static_cast<int>(index) : 0);
    check(vm.initialization_failed);
    const ConstructorFailure first = failure;
    const std::string first_text = description(first);
    check(first_text.find("PRIVATE") == std::string::npos && first_text.find("SECRET") == std::string::npos);
    // Retrying with a different constructor cannot claim a new execution or
    // mutate the already returned first snapshot. No retained VM/global state.
    vm.loaded_libraries[1].init_func = interrupt;
    check(!run_library_constructors(&vm, &failure));
    expect(failure, Kind::Unknown, Reason::PreviouslyFailed, -1, -1, -1);
    expect(first, array ? Kind::DTInitArray : Kind::DTInit, reason, engine, 1, array ? static_cast<int>(index) : 0);
    check(description(first) == first_text);
    ProcedureFailure procedure; bool completed = true;
    check(run_vm_procedure(&vm, ordinary, {}, 0, 0, &completed, &procedure) == -1);
    check(!completed && procedure.reason == Reason::PreviouslyFailed && procedure.engine == -1);
    if (hook) check(uc_hook_del(vm.uc, hook) == UC_ERR_OK);
    EmulatorVM separate(checked); ConstructorFailure other = first;
    check(run_library_constructors(&separate, &other));
    expect(other, Kind::Unknown, Reason::Unknown, -1, -1, -1);
}

static void entry_read_failure(bool checked, bool second) {
    EmulatorVM vm(checked); install(vm);
    EmulatorVM::LibraryInfo lib{};
    // Last eight mapped bytes: first constructor succeeds, second read fails.
    lib.init_array = second ? code + 0xfff8 : code + 0x10000;
    lib.init_arraysz = second ? 16 : 8;
    if (second) check(uc_mem_write(vm.uc, lib.init_array, &ordinary, 8) == UC_ERR_OK);
    vm.loaded_libraries.push_back(lib);
    ConstructorFailure failure;
    check(!run_library_constructors(&vm, &failure));
    expect(failure, Kind::ArrayEntryRead, Reason::EntryRead, UC_ERR_READ_UNMAPPED, 0, second ? 1 : 0);
    check(vm.initialization_failed);
}

static void invalid_cases() {
    ConstructorFailure failure{Kind::DTInit, Reason::EngineError, 13, 0, 0};
    check(!run_library_constructors(nullptr, &failure));
    expect(failure, Kind::Unknown, Reason::InvalidVM, -1, -1, -1);
    ProcedureFailure procedure; bool completed = true;
    check(run_vm_procedure(nullptr, ordinary, {}, 0, 0, &completed, &procedure) == -1);
    check(!completed && procedure.reason == Reason::InvalidVM && procedure.engine == -1);
    EmulatorVM vm(true); uc_engine *saved = vm.uc; vm.uc = nullptr;
    check(!run_library_constructors(&vm, &failure));
    expect(failure, Kind::Unknown, Reason::InvalidVM, -1, -1, -1);
    check(run_vm_procedure(&vm, ordinary, {}, 0, 0, &completed, &procedure) == -1);
    check(!completed && procedure.reason == Reason::InvalidVM && procedure.engine == -1);
    vm.uc = saved; vm.initialization_failed = true;
    check(!run_library_constructors(&vm, &failure));
    expect(failure, Kind::Unknown, Reason::PreviouslyFailed, -1, -1, -1);
}

static void serialization_cases() {
    const std::string unknown = "Library constructor execution failed [v1;kind=unknown;reason=unknown;engine=-1;library=-1;initializer=-1]";
    check(description({}) == unknown);
    check(description({Kind::DTInit, Reason::EngineError, 13, 0, 0}) ==
        "Library constructor execution failed [v1;kind=dt_init;reason=engine_error;engine=13;library=0;initializer=0]");
    check(description({Kind::DTInitArray, Reason::UnsupportedInterrupt, 0, 65535, 65535}) ==
        "Library constructor execution failed [v1;kind=dt_init_array;reason=unsupported_interrupt;engine=0;library=65535;initializer=65535]");
    check(description({Kind::ArrayEntryRead, Reason::EntryRead, 255, 65536, INT_MAX}) ==
        "Library constructor execution failed [v1;kind=array_entry_read;reason=entry_read;engine=255;library=-1;initializer=-1]");
    check(description({Kind::DTInitArray, Reason::EngineError, 256, INT_MIN, -2}) ==
        "Library constructor execution failed [v1;kind=dt_init_array;reason=engine_error;engine=-1;library=-1;initializer=-1]");
    for (int engine : {-1, -2, INT_MIN, INT_MAX}) {
        auto normalized_value = normalized({Kind::DTInitArray, Reason::EngineError, engine, 1, 2});
        check(normalized_value.engine == -1 && normalized_value.library == 1 && normalized_value.initializer == 2);
    }
    check(ordinal(65535) == 65535 && ordinal(65536) == -1 && ordinal(std::numeric_limits<size_t>::max()) == -1);
    for (ConstructorFailure value : {
            ConstructorFailure{Kind::DTInit, Reason::EngineError, 0, 0, 0},
            ConstructorFailure{Kind::DTInit, Reason::EngineError, 13, 0, 1},
            ConstructorFailure{Kind::DTInitArray, Reason::UnexpectedReturn, 13, 0, 0},
            ConstructorFailure{Kind::ArrayEntryRead, Reason::EntryRead, 0, 0, 0},
            ConstructorFailure{Kind::ArrayEntryRead, Reason::EngineError, 13, 0, 0},
            ConstructorFailure{Kind::DTInitArray, Reason::EntryRead, 13, 0, 0},
            ConstructorFailure{static_cast<Kind>(INT_MAX), Reason::EngineError, 13, 0, 0},
            ConstructorFailure{Kind::DTInit, static_cast<Reason>(INT_MAX), 13, 0, 0},
            ConstructorFailure{Kind::Unknown, Reason::Unknown, 13, 99, 99}}) {
        check(description(value) == unknown);
    }
    for (Reason reason : {Reason::InvalidVM, Reason::PreviouslyFailed}) {
        const auto normalized_value = normalized({Kind::DTInit, reason, 13, 123, 456});
        expect(normalized_value, Kind::Unknown, reason, -1, -1, -1);
    }
    // Enumerate the entire supported tuple space at all numeric boundaries.
    // No arbitrary source string is accepted; output is bounded ASCII only.
    for (int kind = -1; kind <= 4; ++kind) for (int reason = -1; reason <= 7; ++reason)
        for (int value : {INT_MIN, -2, -1, 0, 1, 255, 256, 65535, 65536, INT_MAX}) {
            const auto text = description({static_cast<Kind>(kind), static_cast<Reason>(reason), value, value, value});
            check(text.size() <= 160);
            check(text.find('\n') == std::string::npos && text.find("0x") == std::string::npos);
            bool ascii = true;
            for (unsigned char character : text) ascii = ascii && character >= 32 && character < 127;
            check(ascii);
        }
}

int main() {
    for (bool checked : {false, true}) {
        procedure_cases(checked); constructor_success(checked);
        for (bool array : {false, true}) for (size_t index = 0; index < (array ? 2u : 1u); ++index) {
            constructor_failure(checked, protected_read, Reason::EngineError, UC_ERR_READ_PROT, array, index);
            constructor_failure(checked, interrupt, Reason::UnsupportedInterrupt, UC_ERR_OK, array, index);
            constructor_failure(checked, early, Reason::UnexpectedReturn, UC_ERR_OK, array, index);
        }
        entry_read_failure(checked, false); entry_read_failure(checked, true);
    }
    invalid_cases(); serialization_cases();
    std::printf("{\"schema\":1,\"checks\":%d,\"failures\":0,\"skipped\":0,\"case_ids\":["
        "\"normal_nonzero_w0\",\"normal_error_shaped_w0\",\"protected_access\","
        "\"unsupported_interrupt\",\"abnormal_stop\",\"dt_init_failure\","
        "\"dt_init_array_first_failure\",\"dt_init_array_second_failure\","
        "\"array_entry_read_first\",\"array_entry_read_second\",\"invalid_vm\","
        "\"poisoned_vm\",\"caller_snapshot_independence\",\"serialization_bounds\","
        "\"serialization_privacy\"],\"ADI_executed\":false,\"device_validation\":false}\n", checks);
}
