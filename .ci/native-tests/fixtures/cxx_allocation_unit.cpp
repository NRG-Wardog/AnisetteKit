#include "elf_loader_emulator.h"
#include "cxx_allocation_runtime.h"
#include <cstdio>
#include <cstdlib>
#include <limits>
thread_local bool g_isolated_otp_logging_suppressed = true;
extern "C" void anisetteCoreLog(const char *, ...) {}
// Use production PageAllocator logic, linked separately with discarded VM code.
static int checks=0;
static void check(bool ok) { ++checks; if (!ok) { std::fprintf(stderr,"failed %d\n",checks); std::exit(1); } }
int main() {
    using namespace cxx_allocation_runtime;
    for (const char *name: {"_Znwm","_Znam"}) check(classify(name)==Operation::New);
    for (const char *name: {"_ZdlPv","_ZdaPv","_ZdlPvm","_ZdaPvm"}) check(classify(name)==Operation::Delete);
    for (const char *name: {"malloc","_Znwj","_ZnwmSt11align_val_t","_ZnwmRKSt9nothrow_t","_Znwm_extra","","_ZdlPv_extra"}) check(classify(name)==Operation::Other);
    PageAllocator heap(0x48000000,256,64); uint64_t a=999,b=999;
    check(allocate(heap,32,a)); check(a==0x48000000); check(a%64==0);
    check(allocate(heap,0,b)); check(b==a+64);
    check(allocate(heap,1,a)); check(a==0x48000080);
    check(allocate(heap,64,b)); check(b==0x480000c0);
    check(!allocate(heap,1,a)); check(a==0);
    PageAllocator fresh(0x48000000,256,64);
    check(!allocate(fresh,std::numeric_limits<uint64_t>::max(),a)); check(a==0);
    check(!allocate(fresh,257,a)); check(a==0);
    check(allocate(fresh,256,a)); check(a==0x48000000);
    check(!allocate(fresh,0,b)); check(b==0);
    std::printf("{\"checks\":%d,\"failures\":0,\"guest_execution\":false}\n",checks);
}
