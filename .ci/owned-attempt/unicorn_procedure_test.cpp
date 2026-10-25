#include "elf_loader_emulator.h"
#include <cassert>
#include <condition_variable>
#include <mutex>
#include <thread>
using namespace anisette_owned_attempt;
static constexpr uint64_t code_address = 0x12000000;
static void install(EmulatorVM &vm, uint32_t first) {
    assert(uc_mem_map(vm.uc, code_address, 0x1000, UC_PROT_ALL)==UC_ERR_OK);
    uint32_t code[] = {first,0xd65f03c0}; // instruction; ret
    assert(uc_mem_write(vm.uc,code_address,code,sizeof(code))==UC_ERR_OK);
}
struct Barrier { std::mutex lock; std::condition_variable condition; bool entered=false; };
static void entered(uc_engine*,uint64_t,uint32_t,void *value) {
    auto &b=*static_cast<Barrier*>(value); std::lock_guard<std::mutex> lock(b.lock); b.entered=true; b.condition.notify_all();
}
int main() {
    { auto c=std::make_shared<Control>(std::chrono::seconds(10)); EmulatorVM vm(false,c); install(vm,0x528000e0); // mov w0,#7
      bool completed=false; assert(run_vm_procedure(&vm,code_address,{},0,0,&completed)==7); assert(completed && c->check()); }
    { auto c=std::make_shared<Control>(std::chrono::seconds(10)); EmulatorVM vm(false,c); install(vm,0x14000000); // b .
      bool completed=true; assert(run_vm_procedure(&vm,code_address,{},20000,1000,&completed)!=0); assert(!completed && !c->check());
      assert(vm.initialization_failed); assert(run_vm_procedure(&vm,code_address,{})!=0); }
    { auto c=std::make_shared<Control>(std::chrono::seconds(10)); EmulatorVM vm(false,c); install(vm,0x14000000);
      Barrier barrier; uc_hook hook{}; assert(uc_hook_add(vm.uc,&hook,UC_HOOK_CODE,reinterpret_cast<void*>(entered),&barrier,code_address,code_address)==UC_ERR_OK);
      std::thread cancel([&]{std::unique_lock<std::mutex> lock(barrier.lock); barrier.condition.wait(lock,[&]{return barrier.entered;}); c->cancel();});
      bool completed=true; assert(run_vm_procedure(&vm,code_address,{},0,0,&completed)!=0); cancel.join();
      assert(!completed && c->reason()==Stop::cancelled && vm.initialization_failed); }
    { auto c=std::make_shared<Control>(std::chrono::seconds(10)); EmulatorVM vm(false,c); install(vm,0x14000000);
      EmulatorVM::LibraryInfo lib{}; lib.name="synthetic-owned-constructor"; lib.init_func=code_address; vm.loaded_libraries.push_back(std::move(lib));
      c->cancel(); assert(!run_library_constructors(&vm)); assert(vm.initialization_failed); }
}
