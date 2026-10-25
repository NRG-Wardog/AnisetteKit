#include <stdlib.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <fstream>
#include <iterator>
#include "Loader/elf_loader_emulator.h"

int constructed=0, destroyed=0, otp_calls=0, provision_calls=0;
std::string fault, expected_blob="SYNTHETIC-EXISTING-BLOB", expected_uuid, observed_id;
bool stage_observed=false, require_bounded=true;
static bool normal_mode=false;
static bool normal_otp_checks=false, synthetic_provision_success=false;
static std::vector<std::string> native_checkpoints;
static int library_loads=0, library_relocations=0, library_constructors=0, symbol_lookups=0;
static bool fired=false;
static int close_count=0;
static std::string root;
static std::atomic<int> in_vm{0}, peak_vm{0};
static std::atomic<int> mixed_phase{0};
static std::vector<uint64_t> normal_procedures;
static std::vector<std::string> checked_created_names;
static unsigned checked_open_attempts=0;
static unsigned checked_mkdir_attempts=0;
static unsigned unchecked_mkdir_attempts=0, root_open_attempts=0;
static int normal_uuid_formats=0;
static bool hit(const char *name) {
    if (!fired && fault==name) {
        fired=true;errno=fault=="open"?EACCES:(fault=="write"?ENOSPC:(fault=="close"?EBADF:EIO));return true;
    }
    return false;
}
static std::string injected_format_uuid_string(const uint8_t *identifier) {
    if(normal_mode && ++normal_uuid_formats==2 && fault=="uuidalloc") throw std::bad_alloc();
    return ::format_uuid_string(identifier);
}
static int injected_mkdir(const char *p,mode_t m) {
    if(normal_mode)++unchecked_mkdir_attempts;
    if(hit("mkdir"))return -1;return ::mkdir(p,m);
}
static int injected_open(const char *p,int f,mode_t m=0) {
    if(normal_mode)++root_open_attempts;
    if(hit(normal_mode?"rootopen":"open"))return -1;return ::open(p,f,m);
}
static int injected_mkdirat(int fd,const char *p,mode_t m) {
    if(normal_mode)++checked_mkdir_attempts;
    if(hit("mkdir"))return -1;return ::mkdirat(fd,p,m);
}
static int injected_openat(int fd,const char *p,int f,mode_t m=0) {
    if(normal_mode && (f&O_CREAT))++checked_open_attempts;
    const char *stage=(f&O_DIRECTORY)?"uuidopen":((f&O_CREAT)?"open":"readopen");
    if(hit(stage))return -1;int result=::openat(fd,p,f,m);
    if(normal_mode && result>=0 && (f&O_CREAT))checked_created_names.push_back(p);
    return result;
}
static int injected_renameat(int a,const char *p,int b,const char *q) { if(hit("rename"))return -1;return ::renameat(a,p,b,q); }
static FILE *injected_fdopen(int fd,const char *m) { if(hit(strcmp(m,"wb")==0?"fdopen":"readfdopen"))return nullptr;return ::fdopen(fd,m); }
static size_t injected_fwrite(const void *b,size_t s,size_t n,FILE *f) { if(hit("write"))return 0;return ::fwrite(b,s,n,f); }
static int injected_fflush(FILE *f) { if(hit("flush"))return -1;return ::fflush(f); }
static int injected_fclose(FILE *f) {
    ++close_count;const bool bad=hit("close") || (close_count==2 && hit("readclose"));
    const int failed_errno=errno;int r=::fclose(f);
    if(normal_mode && close_count==2 && hit("rootreplace")) {
        assert(::rename(root.c_str(),(root+"-detached").c_str())==0);
        assert(::mkdir(root.c_str(),0700)==0);
        assert(::mkdir((root+"/"+expected_uuid).c_str(),0755)==0);
        std::ofstream replacement(root+"/"+expected_uuid+"/adi.pb");replacement<<"FOREIGN-REPLACEMENT-BLOB";
    }
    if(bad) { errno=failed_errno;return -1; }
    if(normal_mode && fault=="write")errno=EBUSY; // Successful cleanup must not replace ENOSPC.
    return r;
}
static FILE *injected_fopen(const char *p,const char *m) { if(hit("readopen"))return nullptr;return ::fopen(p,m); }
static size_t injected_fread(void *b,size_t s,size_t n,FILE *f) {
    if(hit("read"))return 0;auto r=::fread(b,s,n,f);
    if(hit("mismatch")&&r) ((char*)b)[0]^=1;return r;
}
static int injected_rename(const char *a,const char *b) { if(hit("rename"))return -1;return ::rename(a,b); }
static int injected_unlink(const char *p) { if(hit("cleanup"))return -1;return ::unlink(p); }
static int injected_fgetc(FILE *f) { if(hit("extra"))return 'X';return ::fgetc(f); }
static int injected_ferror(FILE *f) { if(hit("readerror"))return 1;return ::ferror(f); }
static char *injected_strdup(const char *p) { if(hit("alloc"))return nullptr;return ::strdup(p); }

static bool fail_diagnostic_malloc = false;
static void *injected_malloc(size_t size) {
    if (fail_diagnostic_malloc) { fail_diagnostic_malloc = false; return nullptr; }
    return std::malloc(size);
}
#define malloc injected_malloc
#define mkdir injected_mkdir
#define mkdirat injected_mkdirat
#define open injected_open
#define openat injected_openat
#define renameat injected_renameat
#define fdopen injected_fdopen
#define fwrite injected_fwrite
#define fflush injected_fflush
#define fclose injected_fclose
#define fopen injected_fopen
#define fread injected_fread
#define rename injected_rename
#define unlink injected_unlink
#define fgetc injected_fgetc
#define ferror injected_ferror
#define strdup injected_strdup
#define format_uuid_string injected_format_uuid_string
#include "anisette_core_uc.cpp"
#undef malloc
#undef mkdir
#undef mkdirat
#undef open
#undef openat
#undef renameat
#undef fdopen
#undef fwrite
#undef fflush
#undef fclose
#undef fopen
#undef fread
#undef rename
#undef unlink
#undef fgetc
#undef ferror
#undef strdup
#undef format_uuid_string

static std::string contents(const std::string &path) {
    std::ifstream file(path,std::ios::binary);return std::string(std::istreambuf_iterator<char>(file),{});
}
void observe_native_checkpoint(const char *checkpoint) {
    if(!normal_mode || !normal_otp_checks)return;
    const std::string path=root+"/"+expected_uuid+"/adi.pb";
    struct stat st;
    assert(lstat(path.c_str(),&st)==0 && S_ISREG(st.st_mode));
    assert(contents(path)==expected_blob);
    stage_observed=true;
    native_checkpoints.push_back(checkpoint);
}

// Snapshot the real wrapper caches and the double's native state before an
// attempt. Every rejected staging operation must leave this whole snapshot
// unchanged, including a cold VM and previously configured other identities.
struct NormalState {
    EmulatorVM *vm=legacy_vm_state.vm;
    bool initialized=legacy_vm_state.libraries_initialized;
    std::string path=legacy_vm_state.provisioning_path, id=legacy_vm_state.android_id, observed=observed_id;
    std::string native_path=vm?vm->provisioning_path:"";
    uint64_t heap_next=vm?vm->heap.next:0;
    std::map<uint64_t,std::vector<uint8_t>> memory=vm?vm->uc->memory:decltype(memory){};
    int created=constructed, deleted=destroyed, otp=otp_calls, provision=provision_calls;
    int loads=library_loads, relocations=library_relocations, constructors=library_constructors;
    int symbols=symbol_lookups;
    size_t procedures=normal_procedures.size(), checkpoints=native_checkpoints.size();
    void assert_unchanged() const {
        assert(legacy_vm_state.vm==vm && legacy_vm_state.libraries_initialized==initialized);
        assert(legacy_vm_state.provisioning_path==path && legacy_vm_state.android_id==id && observed_id==observed);
        assert(constructed==created && destroyed==deleted && otp_calls==otp && provision_calls==provision);
        assert(library_loads==loads && library_relocations==relocations && library_constructors==constructors);
        assert(symbol_lookups==symbols && normal_procedures.size()==procedures);
        assert(native_checkpoints.size()==checkpoints);
        if(vm)assert(vm->provisioning_path==native_path && vm->heap.next==heap_next && vm->uc->memory==memory);
    }
};
static int open_descriptor_count() {
    int count=0;for(int fd=0;fd<1024;++fd)if(fcntl(fd,F_GETFD)!=-1)++count;return count;
}
bool load_library_to_vm(EmulatorVM *vm,const std::string &,const std::string &) {
    ++library_loads;observe_native_checkpoint("library.load");
    if(normal_mode) { assert(!vm->read_only_filesystem);return fault!="load"; }
    assert(vm->read_only_filesystem);
    stage_observed=contents(root+"/"+expected_uuid+"/adi.pb")==expected_blob;
    assert(stage_observed);return fault!="load";
}
void relocate_all_vm_libraries(EmulatorVM *) { ++library_relocations;observe_native_checkpoint("library.relocate"); }
bool run_library_constructors(EmulatorVM *vm, vm_initialization_diagnostics::ConstructorFailure *failure) {
    if (failure) *failure = {};
    ++library_constructors;observe_native_checkpoint("library.constructors");
    if (fault == "constructor_diag") {
        using namespace vm_initialization_diagnostics;
        if (failure) {
            *failure = {Kind::DTInitArray, Reason::EngineError, 13, 1, 2};
            failure->fault.available = true;
            failure->fault.access = bounded_fault_diagnostics::Access::ReadProtection;
            failure->fault.width = 8;
            failure->fault.region = bounded_fault_diagnostics::Region::LowGuard;
            failure->fault.pc_library = 1; failure->fault.pc_offset = 32;
            failure->fault.guard = bounded_fault_diagnostics::Guard::Intact;
        }
        vm->initialization_failed = true;
        return false;
    }
    return true;
}
uint64_t get_vm_symbol_address(EmulatorVM *,const std::string &name) {
    ++symbol_lookups;observe_native_checkpoint("symbol.lookup");
    const std::vector<std::string> symbols={"kq56gsgHG6","nf92ngaK92","Sph98paBcz","qi864985u0","rsegvyrt87","uv5t6nhkui"};
    for(size_t i=0;i<symbols.size();++i)if(name==symbols[i])return fault=="symbol"&&i==3?0:i+1;
    return 0;
}
int32_t run_vm_procedure(EmulatorVM *vm,uint64_t proc,const std::vector<uint64_t>&args,uint64_t timeout,size_t count) {
    observe_native_checkpoint("procedure.call");
    if(normal_mode)normal_procedures.push_back(proc);
    if(require_bounded) assert(timeout==5000000 && count==50000000);
    if(proc==2)vm->provisioning_path=std::string((char*)vm->uc->memory[args[0]].data());
    if(proc==3)observed_id=std::string((char*)vm->uc->memory[args[0]].data());
    if(proc>4){
        ++provision_calls;
        if(!synthetic_provision_success)return -45063;
        if(proc==5) {
            const uint8_t cpim[]={7,8,9};const uint64_t address=vm->write_bytes(cpim,sizeof(cpim));
            const uint32_t length=sizeof(cpim),session=42;
            uc_mem_write(vm->uc,args[3],&address,sizeof(address));
            uc_mem_write(vm->uc,args[4],&length,sizeof(length));
            uc_mem_write(vm->uc,args[5],&session,sizeof(session));
        } else if(proc==6) {
            assert(args[0]==42);
            std::ofstream generated(vm->provisioning_path+"/adi.pb",std::ios::binary);
            generated<<expected_blob;assert(generated.good());
        }
        return 0;
    }
    if(fault=="setup_init"&&proc==1)return -45075;
    if((fault=="setup" || fault=="setup_path")&&proc==2)return -45054;
    if(fault=="setup_id"&&proc==3)return -45046;
    if(proc!=4)return 0;
    ++otp_calls;
    if(normal_mode && contents(vm->provisioning_path+"/adi.pb")!=expected_blob) return -45061;
    assert(contents(vm->provisioning_path+"/adi.pb")==expected_blob);
    int concurrent=++in_vm;int old=peak_vm.load();while(old<concurrent&&!peak_vm.compare_exchange_weak(old,concurrent)){}
    std::this_thread::yield();--in_vm;
    if(fault=="mixed") {
        mixed_phase=1;
        while(mixed_phase.load()!=2)std::this_thread::yield();
    }
    if(fault=="otp")return -45061;
    if(fault=="throw")throw std::runtime_error("synthetic");
    const uint8_t mid[]={1,2,3},otp[]={4,5,6};
    uint64_t midaddr=vm->write_bytes(mid,3),otpaddr=vm->write_bytes(otp,3);
    uint32_t len=fault=="length"?5000:3;
    uc_mem_write(vm->uc,args[1],&midaddr,8);uc_mem_write(vm->uc,args[2],&len,4);
    uc_mem_write(vm->uc,args[3],&otpaddr,8);uc_mem_write(vm->uc,args[4],&len,4);
    if(fault=="outputread")vm->uc->memory.erase(args[1]);
    return 0;
}

static std::string native_trace(const char *json) {
    const char *prefix="\"v3_native_trace\":\"";
    const char *start=strstr(json,prefix);
#if V3_TEMPORARY_ANISETTE_TRACE_ENABLED
    assert(start);start+=strlen(prefix);const char *end=strchr(start,'"');assert(end);
    std::string value(start,end);
    assert(value.size()<=1024 && std::count(value.begin(),value.end(),',')<32);
    for(const auto &private_value:{expected_blob,expected_uuid,root,std::string("0001020304050607"),
            std::string("AQID"),std::string("BAUG"),std::string("X-Apple-I-MD"),
            std::string("PASSWORD-CANARY"),std::string("TOKEN-CANARY")})
        if(!private_value.empty())assert(value.find(private_value)==std::string::npos);
    const char *timing_prefix="\"v3_login_native_trace\":\"";
    if(const char *timing=strstr(json,timing_prefix)) {
        timing+=strlen(timing_prefix);const char *end=strchr(timing,'"');assert(end);
        const std::string numeric(timing,end);
        assert(numeric.size()<=2055 && numeric.rfind("v1;",0)==0);
        assert(numeric.find_first_not_of("v0123456789;,")==std::string::npos);
        assert(std::count(numeric.begin(),numeric.end(),';')<=65);
        for(const auto &secret:{expected_blob,expected_uuid,root,std::string("PASSWORD-CANARY"),std::string("TOKEN-CANARY")})
            if(!secret.empty())assert(numeric.find(secret)==std::string::npos);
    }
    return value;
#else
    assert(!start);return "disabled";
#endif
}

int main(int argc,char **argv) {
#if V3_TEMPORARY_ANISETTE_TRACE_ENABLED
    // Optional metadata allocation failure preserves the original error JSON.
    char *preserved = strdup("{\"error\":\"engine13\"}");
    char *original = preserved;
    {
        NativeOTPTrace trace(&preserved);
        trace.add(NativeOTPStage::LibraryInitFailed);
        vm_initialization_diagnostics::ConstructorFailure f{
            vm_initialization_diagnostics::Kind::DTInit,
            vm_initialization_diagnostics::Reason::EngineError,13,0,0};
        f.fault.available = true;
        trace.record_constructor_fault(f);
        fail_diagnostic_malloc = true;
    }
    assert(!fail_diagnostic_malloc && preserved == original && strcmp(preserved,"{\"error\":\"engine13\"}")==0);
    free_c_string(preserved);
#endif
    assert(argc==2);fault=argv[1];
    if(fault.rfind("normal_",0)==0) { normal_mode=true;require_bounded=false;fault=fault.substr(7); }
    anisetteCoreSetLogging(1);
    char temporary[]="/tmp/isolated-adi-test-XXXXXX";assert(mkdtemp(temporary));root=temporary;
    uint8_t uuid[16];for(int i=0;i<16;++i)uuid[i]=i;expected_uuid=format_uuid_string(uuid);
    // A warmed normal provider must survive every probe result byte-for-byte.
    auto normal=new EmulatorVM;legacy_vm_state.vm=normal;legacy_vm_state.libraries_initialized=true;
    legacy_vm_state.provisioning_path="unchanged-normal-path";legacy_vm_state.android_id="UNCHANGEDNORMAL";
    if (normal_mode && fault == "fresh_constructor_diag") {
        anisetteCoreSetLogging(0);
        delete normal;legacy_vm_state.vm=nullptr;legacy_vm_state.libraries_initialized=false;
        fault="constructor_diag";
        const uint8_t spim[]={10,11};char *json=nullptr;
        assert(start_provision_uc(root.c_str(),root.c_str(),uuid,spim,sizeof(spim),&json)==ANISETTE_ERR_LOADER_FAILED);
        assert(json && strstr(json,"initializer=2"));
        const auto trace=native_trace(json);
        assert(trace.find("library.init.failed")!=std::string::npos);
        assert(trace.find("setup.failed")!=std::string::npos);
        assert(strstr(json,"\"v3_login_native_trace\":\"v1;"));
        assert(strstr(json,"3,2,") && provision_calls==0 && otp_calls==0);
        free_c_string(json);
        assert(legacy_vm_state.vm && legacy_vm_state.vm->initialization_failed);
        delete legacy_vm_state.vm;legacy_vm_state.vm=nullptr;assert(rmdir(root.c_str())==0);
        puts("FRESH_CONSTRUCTOR_TRACE_PASS");return 0;
    }
    if (normal_mode && fault == "constructor_diag") {
        anisetteCoreSetLogging(0);
        delete normal;legacy_vm_state.vm=nullptr;legacy_vm_state.libraries_initialized=false;
        normal_otp_checks=true;
        char *json=nullptr;
        const std::string directory=root+"/"+expected_uuid;
        auto invoke=[&]() {
            return get_anisette_headers_uc(root.c_str(),root.c_str(),uuid,
                (const uint8_t*)expected_blob.data(),static_cast<uint32_t>(expected_blob.size()),&json);
        };
        assert(invoke()==ANISETTE_ERR_LOADER_FAILED && json);
        const std::string first=json;
        assert(first.find("\"error\":\"Library constructor execution failed [v1;kind=dt_init_array;reason=engine_error;engine=13;library=1;initializer=2]\"")!=std::string::npos);
        const std::string trace=native_trace(json);
#if V3_TEMPORARY_ANISETTE_TRACE_ENABLED
        assert(trace.find("vm.init.ok,library.load.ok,library.init.failed,setup.failed")!=std::string::npos);
        assert(trace.find("cleanup.not_requested")!=std::string::npos);
        assert(first.find("\"v3_constructor_fault\":\"v1;p0_fault_diag1;1;8;1;1;32;1;-;-\"")!=std::string::npos);
#else
        assert(first.find("v3_constructor_fault")==std::string::npos);
#endif
        assert(first.find("v2|0|0|0")!=std::string::npos);
        assert(first.find(expected_blob)==std::string::npos && first.find(expected_uuid)==std::string::npos);
        assert(first.find(root)==std::string::npos);
        assert(legacy_vm_state.vm && legacy_vm_state.vm->initialization_failed && !legacy_vm_state.libraries_initialized);
        assert(legacy_vm_state.provisioning_path=="unchanged-normal-path" && legacy_vm_state.android_id=="UNCHANGEDNORMAL");
        assert(normal_procedures.empty() && otp_calls==0 && provision_calls==0);
        assert(contents(directory+"/adi.pb")==expected_blob && library_constructors==1);
        free_c_string(json);json=nullptr;
        assert(invoke()==ANISETTE_ERR_LOADER_FAILED && json);
        assert(strstr(json,"VM initialization previously failed; restart required"));
        assert(!strstr(json,"Library constructor execution failed"));
        assert(!strstr(json,"v3_constructor_fault"));
        assert(library_constructors==1 && normal_procedures.empty() && otp_calls==0 && provision_calls==0);
        assert(first.find("reason=engine_error;engine=13;library=1;initializer=2")!=std::string::npos);
        assert(contents(directory+"/adi.pb")==expected_blob);
        free_c_string(json);delete legacy_vm_state.vm;legacy_vm_state.vm=nullptr;
        assert(unlink((directory+"/adi.pb").c_str())==0 && rmdir(directory.c_str())==0 && rmdir(root.c_str())==0);
        puts("CONSTRUCTOR_DIAGNOSTIC_BOUNDARY_PASS");return 0;
    }
    if(normal_mode) {
        anisetteCoreSetLogging(0);
        if(fault=="invalid") {
            normal_otp_checks=true;
            const NormalState before;
            char *untouched=reinterpret_cast<char *>(1);
            assert(get_anisette_headers_uc(root.c_str(),root.c_str(),nullptr,
                (const uint8_t*)expected_blob.data(),static_cast<uint32_t>(expected_blob.size()),&untouched)==-1);
            assert(untouched==reinterpret_cast<char *>(1));
            // Preserve original short-circuit admission: invalid calls must not
            // inspect otherwise unreadable root/identifier arguments for debug.
            const char *unreadable=reinterpret_cast<const char *>(1);
            const uint8_t *unreadable_bytes=reinterpret_cast<const uint8_t *>(1);
            assert(get_anisette_headers_uc(nullptr,unreadable,unreadable_bytes,unreadable_bytes,1,&untouched)==-1);
            assert(get_anisette_headers_uc(unreadable,nullptr,unreadable_bytes,unreadable_bytes,1,&untouched)==-1);
            assert(get_anisette_headers_uc(unreadable,unreadable,unreadable_bytes,nullptr,1,&untouched)==-1);
            assert(get_anisette_headers_uc(unreadable,unreadable,unreadable_bytes,unreadable_bytes,1,nullptr)==-1);
            assert(untouched==reinterpret_cast<char *>(1) && activeADIConsumptionDebug==nullptr);
            before.assert_unchanged();
            assert(checked_mkdir_attempts==0 && unchecked_mkdir_attempts==0);
            assert(root_open_attempts==0 && checked_open_attempts==0 && normal_uuid_formats==0);

            delete normal;legacy_vm_state.vm=nullptr;assert(rmdir(root.c_str())==0);
            puts("NORMAL_INVALID_ARGUMENT_PASS");return 0;
        }
        const bool cold_failure=fault.rfind("coldfail_",0)==0;
        if(cold_failure)fault=fault.substr(9);
        const bool new_setup_failure=fault.rfind("new_",0)==0;
        if(new_setup_failure)fault=fault.substr(4);
        const bool provisioned=fault=="provisioned";
        const bool same_identity=fault=="same_identity", different_identity=fault=="different_identity";
        const bool invalid_libdir=fault=="invalid_libdir_missing" || fault=="invalid_libdir_file";
        const bool cold=cold_failure || fault=="cold" || fault=="cold_new" || provisioned ||
            fault=="load" || fault=="setup_init";
        const bool fresh=fault=="fresh" || fault=="cold_new" || new_setup_failure;
        const bool concurrent=fault=="concurrent", retry=fault=="retrywrite";
        const std::string scenario=fault;
        if(cold) {
            delete normal;normal=nullptr;legacy_vm_state.vm=nullptr;legacy_vm_state.libraries_initialized=false;
        }
        if(fault=="cold" || fault=="fresh" || fault=="cold_new" || same_identity || different_identity || provisioned)fault="ok";
        if(fresh || provisioned)expected_blob="SYNTHETIC-FRESH-PROVISION-BLOB";
        if(fault=="zero") { fault="ok";expected_blob.clear(); }
        if(fault=="large") { fault="ok";expected_blob=std::string(1048577,'B'); }
        if(retry) fault="write";
        const std::string directory=root+"/"+expected_uuid;
        const std::string destination=directory+"/adi.pb";
        const std::string temporary_file=directory+"/.adi.pb.checked-"+std::to_string(getpid())+"-0";
        const std::string historical_temporary=directory+"/.adi.pb.checked-staging";
        const std::string previous="PRESERVE-PREVIOUS-BLOB", foreign="DO-NOT-CHANGE-TEMPORARY";
        const std::string outside=root+"-outside";
        assert(::mkdir(outside.c_str(),0700)==0);
        { std::ofstream f(outside+"/adi.pb");f<<previous; }
        if(!fresh && !provisioned) {
            assert(::mkdir(directory.c_str(),0755)==0);
            std::ofstream f(destination);f<<previous;
        }
        std::string provisioning_root=root;
        std::string library_root=root;
        if(invalid_libdir) {
            library_root=root+"/invalid-library-directory";
            if(scenario=="invalid_libdir_file") { std::ofstream f(library_root);f<<"NOT-A-DIRECTORY"; }
        }
        if(scenario=="rootlink") {
            assert(symlink(outside.c_str(),(root+"/root-link").c_str())==0);
            provisioning_root=root+"/root-link";
        }
        if(scenario=="uuidlink" || scenario=="uuidfile") {
            assert(unlink(destination.c_str())==0);assert(rmdir(directory.c_str())==0);
            if(scenario=="uuidlink")assert(symlink(outside.c_str(),directory.c_str())==0);
            else { std::ofstream f(directory);f<<previous; }
        }
        if(scenario=="filelink" || scenario=="hardlink" || scenario=="fifo") {
            assert(unlink(destination.c_str())==0);
            if(scenario=="filelink")assert(symlink((outside+"/adi.pb").c_str(),destination.c_str())==0);
            else if(scenario=="hardlink")assert(link((outside+"/adi.pb").c_str(),destination.c_str())==0);
            else assert(mkfifo(destination.c_str(),0600)==0);
        }
        if(scenario=="temp_exists" || scenario=="crash_leftover") { std::ofstream f(temporary_file);f<<foreign; }
        if(scenario=="temp_full") {
            for(int i=0;i<16;++i) { std::ofstream f(directory+"/.adi.pb.checked-"+std::to_string(getpid())+"-"+std::to_string(i));f<<foreign; }
        }
        if(scenario=="crash_leftover") { std::ofstream f(historical_temporary);f<<"PARTIAL-CRASH-LEFTOVER"; }
        if(scenario=="temp_link")assert(symlink((outside+"/adi.pb").c_str(),temporary_file.c_str())==0);
        if(scenario=="rootpermissions")assert(chmod(root.c_str(),0777)==0);
        if(scenario=="uuidpermissions")assert(chmod(directory.c_str(),0777)==0);
        std::string prior_identity_directory;
        if(same_identity || different_identity) {
            uint8_t prior_uuid[16];memcpy(prior_uuid,uuid,sizeof(uuid));
            if(different_identity)prior_uuid[0]=0x80;
            EmulatorVM *configured=nullptr;std::string configured_directory,error;
            assert(setup_vm_and_adi(configured,root.c_str(),root.c_str(),prior_uuid,
                configured_directory,error));
            assert(configured==normal && legacy_vm_state.libraries_initialized && constructed==1 && destroyed==0);
            if(different_identity) {
                prior_identity_directory=configured_directory;
                std::ofstream old_blob(prior_identity_directory+"/adi.pb");old_blob<<previous;
                assert(legacy_vm_state.provisioning_path!=directory && legacy_vm_state.android_id!="0001020304050607");
            } else assert(legacy_vm_state.provisioning_path==directory && legacy_vm_state.android_id=="0001020304050607");
        }
        if(provisioned) {
            synthetic_provision_success=true;
            const uint8_t spim[]={10,11},ptm[]={12,13},tk[]={14,15};char *json=nullptr;
            assert(start_provision_uc(root.c_str(),root.c_str(),uuid,spim,sizeof(spim),&json)==0);
            assert(json && strstr(json,"\"session\":42") && strstr(json,"\"cpim_base64\":\"BwgJ\""));
            free_c_string(json);json=nullptr;
            assert(end_provision_uc(root.c_str(),root.c_str(),uuid,42,ptm,sizeof(ptm),tk,sizeof(tk),&json)==0);
            const std::string provision_response="{\"adi_pb_base64\":\""+
                base64_encode(reinterpret_cast<const uint8_t *>(expected_blob.data()),expected_blob.size())+"\"}";
            assert(json);
            std::string payload(json);
            const auto metadata = payload.find(",\"v3_native_trace\":");
            if (metadata != std::string::npos) payload = payload.substr(0, metadata) + "}";
            assert(payload==provision_response);
            assert(native_trace(json).find("native.end.ok")!=std::string::npos);
            free_c_string(json);
            assert(contents(destination)==expected_blob && otp_calls==0 && provision_calls==2);
            assert((normal_procedures==std::vector<uint64_t>{1,2,3,5,6}));
            assert(legacy_vm_state.provisioning_path==directory && legacy_vm_state.android_id=="0001020304050607");
            assert(constructed==2 && destroyed==1 && legacy_vm_state.libraries_initialized);
            assert(library_loads==2 && library_constructors==1 && library_relocations==1);
            // Match the Swift boundary: provisioning returns bytes, its UUID
            // directory can be removed, and OTP must stage them into a new one
            // while retaining the already initialized VM and identity caches.
            assert(unlink(destination.c_str())==0 && rmdir(directory.c_str())==0);
            synthetic_provision_success=false;
        }
        const NormalState before;
        const std::string authoritative_blob=expected_blob;
        const unsigned mkdir_before=checked_mkdir_attempts;
        const unsigned unchecked_mkdir_before=unchecked_mkdir_attempts, root_open_before=root_open_attempts;
        normal_otp_checks=true;
        if(scenario=="uuidalloc") {
            const int descriptors=open_descriptor_count();char *json=nullptr;bool threw=false;
            try {
                get_anisette_headers_uc(root.c_str(),root.c_str(),uuid,(const uint8_t*)expected_blob.data(),
                    static_cast<uint32_t>(expected_blob.size()),&json);
            } catch(const std::bad_alloc &) { threw=true; }
            assert(threw && normal_uuid_formats==2 && open_descriptor_count()==descriptors);
            before.assert_unchanged();
            assert(expected_blob==authoritative_blob);
            assert(otp_calls==0 && contents(destination)==previous);
            assert(access(temporary_file.c_str(),F_OK)!=0 && !json);
            assert(unlink(destination.c_str())==0 && rmdir(directory.c_str())==0);
            assert(unlink((outside+"/adi.pb").c_str())==0 && rmdir(outside.c_str())==0);
            delete legacy_vm_state.vm;legacy_vm_state.vm=nullptr;assert(rmdir(root.c_str())==0);
            puts("NORMAL_ALLOCATION_FD_PASS");return 0;
        }
        auto invoke_normal=[&]() {
            char *json=nullptr;
            int result=get_anisette_headers_uc(library_root.c_str(),provisioning_root.c_str(),uuid,
                (const uint8_t*)expected_blob.data(),static_cast<uint32_t>(expected_blob.size()),&json);
            assert(expected_blob==authoritative_blob);
            assert(json);printf("NATIVE_TRACE=%s\n",native_trace(json).c_str());
            if(invalid_libdir) {
                assert(result==ANISETTE_ERR_LOADER_FAILED);
                const std::string error="\"error\":\"Provided library path is not a valid directory: "+library_root+"\"";
                assert(strstr(json,error.c_str()));
            }
            const std::map<std::string,std::string> setup_errors={
                {"load","Failed to load libraries into VM"},
                {"setup_init","ADILoadLibraryWithPath failed: -45075"},
                {"setup_path","ADISetProvisioningPath failed: -45054"},
                {"setup_id","ADISetAndroidID failed: -45046"}};
            if(setup_errors.count(fault)) {
                assert(result==ANISETTE_ERR_LOADER_FAILED);
                const std::string error="\"error\":\""+setup_errors.at(fault)+"\"";
                assert(strstr(json,error.c_str()));
            }
            if(fault=="otp") {
                assert(result==-45061);
                assert(strstr(json,"ADIOTPRequest failed (") && strstr(json,"): -45061\""));
            }
            if(fault=="symbol")assert(result==ANISETTE_ERR_SYMBOL_MISSING && strstr(json,"Symbol ADIOTPRequest missing"));
            if(result==-6) {
                assert(strstr(json,"Checked OTP staging failed"));
                int expected_errno=0;
                if(fault=="open")expected_errno=EACCES;
                if(fault=="write")expected_errno=ENOSPC;
                if(fault=="flush" || fault=="readclose")expected_errno=EIO;
                if(fault=="close")expected_errno=EBADF;
                if(fault=="temp_full")expected_errno=EEXIST;
                if(expected_errno) {
                    const std::string exact="\"error\":\"Checked OTP staging failed (errno "+std::to_string(expected_errno)+")\"";
                    assert(strstr(json,exact.c_str()));
                }
                if(fault=="mismatch" || fault=="extra" || fault=="rootpermissions" || fault=="uuidpermissions" ||
                    fault=="filelink" || fault=="hardlink" || fault=="fifo" || fault=="rootreplace")
                    assert(strstr(json,"\"error\":\"Checked OTP staging failed\""));
            }
            free_c_string(json);return result;
        };
        int result;
        if(concurrent) {
            int second=-99;
            std::thread a([&]{result=invoke_normal();}),b([&]{second=invoke_normal();});
            a.join();b.join();assert(result==0 && second==0 && otp_calls==2);
        } else result=invoke_normal();
        const bool foreign_temporary=scenario=="temp_exists" || scenario=="temp_link" || scenario=="crash_leftover";
        const bool setup_failure=fault=="load" || fault=="setup_init" || fault=="setup_path" || fault=="setup_id";
        const bool promoted=fault=="ok" || fault=="otp" || fault=="symbol" || concurrent || foreign_temporary || setup_failure;
        if(invalid_libdir) {
            before.assert_unchanged();
            assert(checked_mkdir_attempts==mkdir_before && checked_open_attempts==0);
            assert(root_open_attempts==root_open_before && normal_uuid_formats==0);
            assert(contents(destination)==previous);
        } else if(promoted) {
            if(fault=="ok" || concurrent || foreign_temporary) assert(result==0);
            else assert(result!=0);
            assert(contents(destination)==expected_blob);
            if(!concurrent)assert(otp_calls-before.otp==((fault=="symbol" || setup_failure)?0:1));
            assert(stage_observed && native_checkpoints.size()>before.checkpoints);
        } else {
            assert(result==-6 && otp_calls==0);
            before.assert_unchanged();
            assert(!stage_observed);
            if(scenario!="uuidfile" && scenario!="fifo" && scenario!="rootreplace")assert(contents(destination)==previous);
            if(scenario=="rootreplace") {
                assert(contents(destination)=="FOREIGN-REPLACEMENT-BLOB");
                assert(contents(root+"-detached/"+expected_uuid+"/adi.pb")==previous);
                for(const auto &name:checked_created_names)
                    assert(access((root+"-detached/"+expected_uuid+"/"+name).c_str(),F_OK)!=0);
            }
            if(scenario=="uuidfile")assert(contents(directory)==previous);
            assert(std::find(normal_procedures.begin(),normal_procedures.end(),4)==normal_procedures.end());
        }
        const bool root_rejected=scenario=="rootopen" || scenario=="rootlink" || scenario=="rootpermissions";
        if(!invalid_libdir)assert(checked_mkdir_attempts-mkdir_before==(root_rejected?0u:(concurrent?2u:1u)));
        assert(unchecked_mkdir_attempts==unchecked_mkdir_before);
        if(scenario=="temp_exists" || scenario=="crash_leftover" || scenario=="temp_full")assert(contents(temporary_file)==foreign);
        else if(scenario=="temp_link") { struct stat st;assert(lstat(temporary_file.c_str(),&st)==0 && S_ISLNK(st.st_mode)); }
        else assert(access(temporary_file.c_str(),F_OK)!=0);
        for(const auto &name:checked_created_names)assert(access((directory+"/"+name).c_str(),F_OK)!=0);
        if(scenario=="crash_leftover")assert(contents(historical_temporary)=="PARTIAL-CRASH-LEFTOVER");
        if(scenario=="open")assert(checked_open_attempts==1);
        if(scenario=="temp_full") {
            assert(checked_open_attempts==16 && checked_created_names.empty());
            for(int i=0;i<16;++i) {
                const auto name=directory+"/.adi.pb.checked-"+std::to_string(getpid())+"-"+std::to_string(i);
                assert(contents(name)==foreign);assert(unlink(name.c_str())==0);
            }
        }
        assert(contents(outside+"/adi.pb")==previous);
        assert(access((outside+"/"+expected_uuid).c_str(),F_OK)!=0);
        assert(provision_calls==before.provision);
        if(promoted) {
            assert(legacy_vm_state.vm && !legacy_vm_state.vm->read_only_filesystem);
            assert(destroyed==before.deleted);
            if(before.vm) {
                assert(legacy_vm_state.vm==before.vm && constructed==before.created);
                assert(library_loads==before.loads && library_relocations==before.relocations);
                assert(library_constructors==before.constructors);
            } else {
                assert(constructed==before.created+1);
                assert(std::count(native_checkpoints.begin(),native_checkpoints.end(),"vm.construct")==1);
                assert(library_loads==before.loads+(fault=="load"?1:2));
                assert(library_relocations==before.relocations+(fault=="load"?0:1));
                assert(library_constructors==before.constructors+(fault=="load"?0:1));
            }
            assert(legacy_vm_state.libraries_initialized==(fault!="load" && fault!="setup_init"));
            std::vector<uint64_t> expected_procedures;
            if(fault!="load") {
                if(!before.initialized)expected_procedures.push_back(1);
                if(fault!="setup_init") {
                    if(before.path!=directory)expected_procedures.push_back(2);
                    if(fault!="setup_path") {
                        if(before.id!="0001020304050607")expected_procedures.push_back(3);
                        if(fault!="setup_id" && fault!="symbol") {
                            expected_procedures.push_back(4);
                            if(concurrent)expected_procedures.push_back(4);
                        }
                    }
                }
            }
            const std::vector<uint64_t> actual_procedures(normal_procedures.begin()+before.procedures,normal_procedures.end());
            assert(actual_procedures==expected_procedures);
            const bool path_succeeded=fault!="load" && fault!="setup_init" && fault!="setup_path";
            const bool id_succeeded=path_succeeded && fault!="setup_id";
            assert(legacy_vm_state.provisioning_path==(path_succeeded?directory:before.path));
            assert(legacy_vm_state.android_id==(id_succeeded?"0001020304050607":before.id));
        }
        if(retry) {
            fault="ok";fired=false;close_count=0;
            assert(invoke_normal()==0 && otp_calls==1 && contents(destination)==expected_blob);
            assert(legacy_vm_state.vm==normal && constructed==1 && destroyed==0);
            assert(access(temporary_file.c_str(),F_OK)!=0);
        }
        if(different_identity) {
            assert(contents(prior_identity_directory+"/adi.pb")==previous);
            assert(unlink((prior_identity_directory+"/adi.pb").c_str())==0);
            assert(rmdir(prior_identity_directory.c_str())==0);
        }
        if(scenario=="invalid_libdir_file")assert(unlink(library_root.c_str())==0);
        if(scenario=="uuidlink" || scenario=="uuidfile")assert(unlink(directory.c_str())==0);
        else {
            unlink(temporary_file.c_str());unlink(historical_temporary.c_str());
            unlink(destination.c_str());assert(rmdir(directory.c_str())==0);
        }
        if(scenario=="rootlink")assert(unlink(provisioning_root.c_str())==0);
        if(scenario=="rootreplace") {
            assert(unlink((root+"-detached/"+expected_uuid+"/adi.pb").c_str())==0);
            assert(rmdir((root+"-detached/"+expected_uuid).c_str())==0);
            assert(rmdir((root+"-detached").c_str())==0);
        }
        assert(unlink((outside+"/adi.pb").c_str())==0);assert(rmdir(outside.c_str())==0);
        delete legacy_vm_state.vm;legacy_vm_state.vm=nullptr;assert(rmdir(root.c_str())==0);
        assert(constructed==destroyed);
        puts("NORMAL_NATIVE_TRACE_PASS");return 0;
    }
    if(fault=="tracecap") {
        char *json=strdup("{\"error\":\"synthetic\"}");
        {
            NativeOTPTrace trace(&json);
            for(int i=0;i<10000;++i) {
                trace.add(NativeOTPStage::ArgumentsOK);
                trace.timed(3, 2, NativeOTPTrace::Clock::now());
            }
            assert(trace.timing_count<=64 && trace.timing_length<=2048 && trace.timing_truncated);
#if !V3_TEMPORARY_ANISETTE_TRACE_ENABLED
            assert(trace.count==0 && trace.length==0);
#endif
        }
        printf("NATIVE_TRACE=%s\n",native_trace(json).c_str());free_c_string(json);
        delete normal;legacy_vm_state.vm=nullptr;assert(rmdir(root.c_str())==0);
        puts("NATIVE_TRACE_CAP_PASS");return 0;
    }
    if(fault=="existing") {
        assert(mkdir((root+"/"+expected_uuid).c_str(),0700)==0);
        std::ofstream file(root+"/"+expected_uuid+"/adi.pb");file<<"DO-NOT-CHANGE";
    }
    if(fault=="rootpermissions")assert(chmod(root.c_str(),0755)==0);
    auto invoke=[&] {
        char *json=nullptr;
        const uint32_t len=fault=="empty"?0:static_cast<uint32_t>(expected_blob.size());
        int result=get_anisette_headers_isolated_uc(root.c_str(),root.c_str(),uuid,
            (const uint8_t*)expected_blob.data(),len,&json);
        if(fault=="ok"||fault=="concurrent"||fault=="mixed")assert(result==0 && json && strstr(json,"AQID"));
        else if(fault=="otp") {
            assert(result==-45061);
#if V3_TEMPORARY_ANISETTE_TRACE_ENABLED
            assert(json && strstr(json,";7,2,"));
#endif
        }
        else assert(result!=0);
        assert(json && !strstr(json,"SYNTHETIC-EXISTING-BLOB"));
        printf("NATIVE_TRACE=%s\n",native_trace(json).c_str());free_c_string(json);
    };
    if(fault=="concurrent") {
        std::thread a(invoke),b(invoke);a.join();b.join();assert(peak_vm==1);
    } else if(fault=="mixed") {
        auto invalid=[&] {
            while(mixed_phase.load()!=1)std::this_thread::yield();
            char *json=nullptr;
            int result=get_anisette_headers_isolated_uc(root.c_str(),root.c_str(),uuid,
                (const uint8_t*)expected_blob.data(),0,&json);
            assert(result==-1 && json);
            printf("NATIVE_TRACE=%s\n",native_trace(json).c_str());free_c_string(json);
            mixed_phase=2;
        };
        std::thread a(invoke),b(invalid);a.join();b.join();
    } else invoke();
    assert(legacy_vm_state.vm==normal && legacy_vm_state.libraries_initialized);
    assert(legacy_vm_state.provisioning_path=="unchanged-normal-path" && legacy_vm_state.android_id=="UNCHANGEDNORMAL");
    assert(provision_calls==0 && constructed-destroyed==1);
    assert(!g_isolated_otp_logging_suppressed && anisetteCoreIsLoggingEnabled()==1);
    if(otp_calls)assert(observed_id=="0001020304050607");
    if(fault=="existing") {
        assert(contents(root+"/"+expected_uuid+"/adi.pb")=="DO-NOT-CHANGE");
        assert(unlink((root+"/"+expected_uuid+"/adi.pb").c_str())==0);
        assert(rmdir((root+"/"+expected_uuid).c_str())==0);
    }
    else assert(access((root+"/"+expected_uuid).c_str(),F_OK)!=0);
    delete normal;legacy_vm_state.vm=nullptr;assert(constructed==destroyed);
    assert(rmdir(root.c_str())==0);
    LOG_UC("NORMAL_LOG_RETAINED\n");
    puts("ISOLATED_NATIVE_OTP_PASS");
}
