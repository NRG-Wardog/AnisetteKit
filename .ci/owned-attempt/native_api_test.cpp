#include "anisette_core.h"
#include <unicorn/unicorn.h>
#include <cassert>
#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <sys/stat.h>

static std::mutex mutex;
static std::condition_variable condition;
static bool block_open = false, open_entered = false, release_open = false;
static std::atomic<unsigned> open_calls{0};
extern "C" {
uc_err uc_open(uc_arch,uc_mode,uc_engine **out) {
    ++open_calls; std::unique_lock<std::mutex> lock(mutex);
    open_entered=true; condition.notify_all();
    if(block_open) condition.wait(lock,[]{return release_open;});
    *out=nullptr; return UC_ERR_RESOURCE;
}
uc_err uc_close(uc_engine*) { return UC_ERR_OK; }
uc_err uc_emu_start(uc_engine*,uint64_t,uint64_t,uint64_t,size_t) { return UC_ERR_RESOURCE; }
uc_err uc_emu_stop(uc_engine*) { return UC_ERR_OK; }
uc_err uc_free(void*) { return UC_ERR_OK; }
uc_err uc_hook_add(uc_engine*,uc_hook*,int,void*,void*,uint64_t,uint64_t,...) { return UC_ERR_RESOURCE; }
uc_err uc_mem_map(uc_engine*,uint64_t,uint64_t,uint32_t) { return UC_ERR_RESOURCE; }
uc_err uc_mem_unmap(uc_engine*,uint64_t,uint64_t) { return UC_ERR_RESOURCE; }
uc_err uc_mem_regions(uc_engine*,uc_mem_region**,uint32_t*) { return UC_ERR_RESOURCE; }
uc_err uc_mem_read(uc_engine*,uint64_t,void*,uint64_t) { return UC_ERR_RESOURCE; }
uc_err uc_mem_write(uc_engine*,uint64_t,const void*,uint64_t) { return UC_ERR_RESOURCE; }
uc_err uc_reg_read(uc_engine*,int,void*) { return UC_ERR_RESOURCE; }
uc_err uc_reg_write(uc_engine*,int,const void*) { return UC_ERR_RESOURCE; }
const char *uc_strerror(uc_err) { return "fixture failure"; }
}
int main() {
    char temp[]="/tmp/owned-native-XXXXXX"; assert(mkdtemp(temp)); std::string root(temp), lib=root+"/lib";
    assert(mkdir(lib.c_str(),0700)==0); uint8_t id[16]={}, blob[3]={1,2,3};
    assert(!anisette_owned_attempt_create(lib.c_str(),root.c_str(),id,0));
    assert(!anisette_owned_attempt_create(lib.c_str(),root.c_str(),id,120001));
    assert(chmod(root.c_str(),0755)==0);
    assert(!anisette_owned_attempt_create(lib.c_str(),root.c_str(),id,60000));
    assert(chmod(root.c_str(),0700)==0);
    auto *first=anisette_owned_attempt_create(lib.c_str(),root.c_str(),id,60000); assert(first);
    auto *second=anisette_owned_attempt_create(lib.c_str(),root.c_str(),id,60000); assert(second);
    assert(anisette_owned_attempt_stage_libraries(first,blob,3,blob,3)==0);
    assert(anisette_owned_attempt_stage_libraries(second,blob,3,blob,3)==0);
    assert(anisette_owned_attempt_stage_libraries(first,blob,3,blob,3)!=0);
    std::string first_dir=anisette_owned_attempt_directory(first), second_dir=anisette_owned_attempt_directory(second);
    assert(first_dir!=second_dir); assert(std::filesystem::exists(first_dir));
    anisette_owned_attempt_cancel(first); char *out=reinterpret_cast<char*>(uintptr_t(1));
    assert(anisette_owned_attempt_headers(first,blob,3,&out)!=0 && out==nullptr && open_calls==0);
    assert(anisette_owned_attempt_finish(first)==0 && anisette_owned_attempt_is_quiescent(first));
    assert(!std::filesystem::exists(first_dir) && std::filesystem::exists(second_dir));
    anisette_owned_attempt_release(first);
    { std::lock_guard<std::mutex> lock(mutex); block_open=true; }
    std::atomic<int32_t> result{0};
    std::thread worker([&] { char *value=nullptr; result=anisette_owned_attempt_headers(second,blob,3,&value); assert(!value); });
    { std::unique_lock<std::mutex> lock(mutex); condition.wait(lock,[]{return open_entered;}); }
    anisette_owned_attempt_cancel(second);
    assert(anisette_owned_attempt_finish(second)==-8);
    assert(!anisette_owned_attempt_is_quiescent(second));
    assert(std::filesystem::exists(second_dir));
    // A second operation cannot enter or destroy the first operation's state.
    out=nullptr; assert(anisette_owned_attempt_start(second,blob,3,&out)!=0 && !out && open_calls==1);
    { std::lock_guard<std::mutex> lock(mutex); release_open=true; } condition.notify_all(); worker.join();
    assert(result!=0); assert(anisette_owned_attempt_finish(second)==0);
    assert(anisette_owned_attempt_is_quiescent(second)); assert(!std::filesystem::exists(second_dir));
    assert(anisette_owned_attempt_finish(second)==0); anisette_owned_attempt_release(second);
    auto *swapped=anisette_owned_attempt_create(lib.c_str(),root.c_str(),id,60000); assert(swapped);
    std::string state=anisette_owned_attempt_directory(swapped);
    std::string owned=std::filesystem::path(state).parent_path(), moved=owned+"-moved";
    assert(rename(owned.c_str(),moved.c_str())==0);
    assert(symlink(lib.c_str(),owned.c_str())==0);
    // Staging uses retained descriptors, never the replacement symlink tree.
    assert(anisette_owned_attempt_stage_libraries(swapped,blob,3,blob,3)==0);
    assert(!std::filesystem::exists(lib+"/libraries"));
    assert(std::filesystem::exists(moved+"/libraries/libCoreADI.so"));
    assert(anisette_owned_attempt_finish(swapped)==-6);
    assert(std::filesystem::is_symlink(owned) && std::filesystem::exists(lib));
    anisette_owned_attempt_release(swapped);
    std::filesystem::remove_all(root);
}
