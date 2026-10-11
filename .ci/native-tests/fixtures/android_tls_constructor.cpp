// Own synthetic AArch64 instructions only. Never reads or executes an ADI ELF.
#include "elf_loader_emulator.h"
#include "android_tls_runtime.h"
#include <cassert>
#include <cstdio>
#include <cstdarg>
#include <stdexcept>
#include <chrono>
thread_local bool g_isolated_otp_logging_suppressed = true;
extern "C" void anisetteCoreLog(const char *, ...) {}
static int checks = 0;
static void check(bool value) { assert(value); ++checks; }
static constexpr uint64_t code_address = 0x10000000;
static void install_synthetic(EmulatorVM &vm) {
    check(uc_mem_map(vm.uc, code_address, 0x10000, UC_PROT_ALL) == UC_ERR_OK);
    // MRS X21,TPIDR_EL0; LDR X8,[X21,#40]; MOV W0,#-45061; RET.
    const uint32_t own_code[] = {0xd53bd055,0xf94016a8,0x12960080,0xd65f03c0};
    check(uc_mem_write(vm.uc, code_address, own_code, sizeof(own_code)) == UC_ERR_OK);
    const uint32_t trap = 0xf9400008; // LDR X8,[X0]: runner clears X0; protected-null failure.
    check(uc_mem_write(vm.uc, code_address + 0x40, &trap, sizeof(trap)) == UC_ERR_OK);
}
int main() {
    // Full production VM constructor, helper, procedure runner, and constructor
    // loop linked from the real source translation unit; no engine API doubles.
    for (bool checked : {false, true}) {
        EmulatorVM vm(checked);
        install_synthetic(vm);
        uint64_t tp = 0, guard = 0;
        check(uc_reg_read(vm.uc, UC_ARM64_REG_TPIDR_EL0, &tp) == UC_ERR_OK);
        check(tp == android_tls_runtime::thread_pointer);
        check(uc_mem_read(vm.uc, tp + 40, &guard, sizeof(guard)) == UC_ERR_OK);
        check(guard != 0 && (guard & 255) == 0);
        const uint64_t zero = 0;
        check(uc_reg_write(vm.uc, UC_ARM64_REG_TPIDR_EL0, &zero) == UC_ERR_OK);
        bool completed = true;
        check(run_vm_procedure(&vm, code_address, {}, 0, 0, &completed) == -1000 - UC_ERR_READ_PROT);
        check(!completed);
        uint64_t stopped = 0;
        check(uc_reg_read(vm.uc, UC_ARM64_REG_PC, &stopped) == UC_ERR_OK);
        check(stopped == code_address + 4);
        check(uc_reg_write(vm.uc, UC_ARM64_REG_TPIDR_EL0, &tp) == UC_ERR_OK);
        check(run_vm_procedure(&vm, code_address, {}, 0, 0, &completed) == -45061);
        check(completed);
        check(run_vm_procedure(&vm, code_address, {}, 0, 0, &completed) == -45061);
        check(completed);
        uint64_t after = 0;
        check(uc_mem_read(vm.uc, tp + 40, &after, sizeof(after)) == UC_ERR_OK);
        check(after == guard);
        EmulatorVM::LibraryInfo library{};
        library.name = "synthetic"; library.init_func = code_address;
        vm.loaded_libraries.push_back(library);
        check(run_library_constructors(&vm));
        check(!vm.initialization_failed);
        vm.loaded_libraries[0].init_func = code_address + 0x40;
        check(!run_library_constructors(&vm));
        check(vm.initialization_failed);
        check(!run_library_constructors(&vm));
        completed = true;
        check(run_vm_procedure(&vm, code_address, {}, 0, 0, &completed) == -1);
        check(!completed);
    }
    {
        EmulatorVM vm(true); install_synthetic(vm);
        const uint64_t entries[] = {code_address + 0x40, code_address};
        check(uc_mem_write(vm.uc, code_address + 0x100, entries, sizeof(entries)) == UC_ERR_OK);
        EmulatorVM::LibraryInfo library{};library.init_array = code_address + 0x100;library.init_arraysz = sizeof(entries);
        vm.loaded_libraries.push_back(library);
        check(!run_library_constructors(&vm));check(vm.initialization_failed);
    }
    {
        EmulatorVM vm(true);EmulatorVM::LibraryInfo library{};
        library.init_array = 0x99000000;library.init_arraysz = 8;
        vm.loaded_libraries.push_back(library);
        check(!run_library_constructors(&vm));check(vm.initialization_failed);
    }
 for(bool checked:{false,true}) {
  EmulatorVM vm(checked);
  constexpr uint64_t base=0x10000000;
  check(uc_mem_map(vm.uc,base,0x10000,UC_PROT_ALL)==UC_ERR_OK);
  const uint32_t code[]={0xd4200000,0xd65f03c0}; // BRK #0; RET
  check(uc_mem_write(vm.uc,base,code,sizeof(code))==UC_ERR_OK);
  bool completed=true;
  auto start=std::chrono::steady_clock::now();
  check(run_vm_procedure(&vm,base,{},0,0,&completed)==-1000-UC_ERR_EXCEPTION);
  check(std::chrono::steady_clock::now()-start<std::chrono::seconds(2));
  check(!completed && vm.unsupported_interrupt);
  uint64_t pc=0;check(uc_reg_read(vm.uc,UC_ARM64_REG_PC,&pc)==UC_ERR_OK);
  check(pc==base); // actual upstream BRK retains faulting PC
  check(run_vm_procedure(&vm,base+4,{},0,0,&completed)==0);
  check(completed && !vm.unsupported_interrupt);
  EmulatorVM::LibraryInfo library{};library.init_func=base;
  vm.loaded_libraries.push_back(library);
  check(!run_library_constructors(&vm));check(vm.initialization_failed);
 }

    int attempts = 0;bool failed = false;
    try {android_tls_runtime::make_guard([&]() {++attempts;return uint64_t(0);});}
    catch (const std::runtime_error &) {failed=true;}
    check(failed && attempts == 8);
    std::printf("PASS %d full-production-loader synthetic checks; no ADI executed\n", checks);
}
