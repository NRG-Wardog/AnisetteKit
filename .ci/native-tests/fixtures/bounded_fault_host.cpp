// Full production source with host API outcome injection only. No linked
// Unicorn engine, guest decoding/execution, proprietary data or network.
#ifdef BOUNDED_FAULT_HOST_APPLE_DIGEST
#define __APPLE__ 1
#include "../../../Native/Loader/bounded_asset_digest.h"
#undef __APPLE__
#endif
#include <cstdio>
#include <cstring>
#include <string>
static const char *mutate_path = nullptr;
static size_t tracked_fread(void *p,size_t width,size_t count,FILE *f) {
    const size_t n = std::fread(p,width,count,f);
    if (mutate_path && n == count) {
        FILE *changed = std::fopen(mutate_path,"r+b");
        if (!changed || std::fseek(changed,0x1f0,SEEK_SET) || std::fputc(0xa5,changed)==EOF || std::fclose(changed)) std::abort();
    }
    return n;
}
#define fread tracked_fread
#include "../../../Native/Loader/elf_loader_emulator.cpp"
#undef fread
#include <array>
#include <algorithm>
#include <map>
#include <openssl/sha.h>
thread_local bool g_isolated_otp_logging_suppressed = true;
extern "C" void anisetteCoreLog(const char *, ...) {}
using namespace bounded_fault_diagnostics;
using vm_initialization_diagnostics::ProcedureFailure;
static unsigned checks=0, opens=0, closes=0, maps=0, writes=0, reads=0, starts=0, stops=0, regions_reads=0;
#define CHECK(x) do { ++checks; if (!(x)) {fprintf(stderr,"line %d check %u failed\n",__LINE__,checks);exit(1);} } while (0)
using FaultHook = bool (*)(uc_engine*,uc_mem_type,uint64_t,int,int64_t,void*);
struct uc_struct {
    std::map<int,std::array<uint8_t,16>> regs;
    std::map<uint64_t,uint8_t> memory;
    std::vector<uc_mem_region> regions;
    FaultHook fault=nullptr; void *owner=nullptr;
};
static bool fail_protection_hook=false, fail_pc=false, fail_regions=false, oversized_regions=false, raise_fault=false;
static uc_err status=UC_ERR_READ_PROT;
static uint64_t final_pc=kLibraryAddress+32;
static size_t width(int r){return r==UC_ARM64_REG_W0?4:(r>=UC_ARM64_REG_V0&&r<=UC_ARM64_REG_V31?16:8);}
extern "C" {
uc_err uc_open(uc_arch,uc_mode,uc_engine **out){*out=new uc_struct;++opens;return UC_ERR_OK;}
uc_err uc_close(uc_engine *e){delete e;++closes;return UC_ERR_OK;}
uc_err uc_mem_map(uc_engine *e,uint64_t a,uint64_t n,uint32_t p){++maps;e->regions.push_back({a,a+n-1,p});return UC_ERR_OK;}
uc_err uc_mem_unmap(uc_engine*,uint64_t,uint64_t){return UC_ERR_OK;}
uc_err uc_mem_write(uc_engine *e,uint64_t a,const void *p,uint64_t n){++writes;for(uint64_t i=0;i<n;++i)e->memory[a+i]=((const uint8_t*)p)[i];return UC_ERR_OK;}
uc_err uc_mem_read(uc_engine *e,uint64_t a,void *p,uint64_t n){++reads;for(uint64_t i=0;i<n;++i)((uint8_t*)p)[i]=e->memory[a+i];return UC_ERR_OK;}
uc_err uc_reg_read(uc_engine *e,int r,void *p){if(r==UC_ARM64_REG_PC && fail_pc)return UC_ERR_ARG;memcpy(p,e->regs[r].data(),width(r));return UC_ERR_OK;}
uc_err uc_reg_write(uc_engine *e,int r,const void *p){memcpy(e->regs[r].data(),p,width(r));return UC_ERR_OK;}
uc_err uc_hook_add(uc_engine *e,uc_hook *h,int type,void *callback,void *owner,uint64_t begin,uint64_t end,...){
    if(type==(UC_HOOK_MEM_READ_PROT|UC_HOOK_MEM_WRITE_PROT|UC_HOOK_MEM_FETCH_PROT)){
        CHECK(begin==1 && end==0);if(fail_protection_hook)return UC_ERR_ARG;e->fault=(FaultHook)callback;e->owner=owner;
    }
    *h=1;return UC_ERR_OK;
}
uc_err uc_mem_regions(uc_engine *e,uc_mem_region **out,uint32_t *count){
    ++regions_reads;*out=nullptr;*count=0;if(fail_regions)return UC_ERR_NOMEM;
    *count=oversized_regions?257:e->regions.size();
    *out=(uc_mem_region*)std::malloc(sizeof(uc_mem_region)*(*count));
    if(!*out)return UC_ERR_NOMEM;
    if(!oversized_regions)memcpy(*out,e->regions.data(),e->regions.size()*sizeof(uc_mem_region));return UC_ERR_OK;
}
uc_err uc_free(void *p){std::free(p);return UC_ERR_OK;}
uc_err uc_emu_stop(uc_engine*){++stops;return UC_ERR_OK;}
uc_err uc_emu_start(uc_engine *e,uint64_t,uint64_t,uint64_t,size_t){
    ++starts; // Injection only: never reads/interprets any guest instruction.
    if(raise_fault){CHECK(e->fault);CHECK(!e->fault(e,UC_MEM_READ_PROT,24,8,0,e->owner));CHECK(!e->fault(e,UC_MEM_WRITE_PROT,kHeapAddress,4,0,e->owner));}
    uc_reg_write(e,UC_ARM64_REG_PC,&final_pc);return status;
}
const char *uc_strerror(uc_err){return "host fault injection";}
}
static EmulatorVM::LibraryInfo library(uint64_t base=kLibraryAddress,uint64_t size=0x10000){
    EmulatorVM::LibraryInfo l{};l.base_address=base;l.min_vaddr=0x20000;l.max_vaddr=l.min_vaddr+size;l.name="SECRET-PATH-IDENTITY";return l;
}
struct Hash {
    SHA256_CTX c; int fail=0, calls=0; size_t largest=0;
    bool begin() noexcept {++calls;return fail!=1 && SHA256_Init(&c)==1;}
    bool update(const uint8_t*p,size_t n) noexcept {++calls;largest=std::max(largest,n);return fail!=2 && SHA256_Update(&c,p,n)==1;}
    bool finish(uint8_t*out) noexcept {++calls;return fail!=3 && SHA256_Final(out,&c)==1;}
};
static Digest digest(const std::vector<uint8_t>&v){Hash h;return digest_buffer(v.data(),v.size(),h);}
static bool same(Digest a,Digest b){return a.known==b.known && memcmp(a.bytes,b.bytes,32)==0;}
template<class T>static void put(std::vector<uint8_t>&d,size_t offset,const T&v){CHECK(offset+sizeof(T)<=d.size());memcpy(d.data()+offset,&v,sizeof(T));}
static std::vector<uint8_t> data_elf(){
    std::vector<uint8_t>d(512);Elf64_Ehdr h{};memcpy(h.e_ident,"\x7f" "ELF\x02\x01\x01",7);
    h.e_type=3;h.e_machine=183;h.e_version=1;h.e_ehsize=sizeof(h);h.e_phoff=sizeof(h);h.e_phentsize=sizeof(Elf64_Phdr);h.e_phnum=2;put(d,0,h);
    Elf64_Phdr load{};load.p_type=PT_LOAD;load.p_flags=PF_R|PF_W;load.p_filesz=load.p_memsz=d.size();load.p_align=8;put(d,sizeof(h),load);
    Elf64_Dyn tags[]={{DT_HASH,{0x180}},{DT_SYMTAB,{0x1a0}},{DT_SYMENT,{sizeof(Elf64_Sym)}},{DT_STRTAB,{0x1e0}},{DT_STRSZ,{1}},{DT_NULL,{0}}};
    Elf64_Phdr dyn{};dyn.p_type=PT_DYNAMIC;dyn.p_offset=dyn.p_vaddr=0x100;dyn.p_filesz=dyn.p_memsz=sizeof(tags);dyn.p_align=8;put(d,sizeof(h)+sizeof(load),dyn);
    memcpy(d.data()+0x100,tags,sizeof(tags));const uint32_t hash[]={1,1,0,0};memcpy(d.data()+0x180,hash,sizeof(hash));d[0x1f0]=0x5a;return d;
}
int main(){
    {unsigned before=opens,closed=closes;fail_protection_hook=true;bool threw=false;try{EmulatorVM v;}catch(const std::exception&){threw=true;}fail_protection_hook=false;CHECK(threw && opens==before+1 && closes==closed+1);}
    {
        EmulatorVM v,other;CHECK(v.protection_hook!=0);CHECK(v.uc->fault!=nullptr);
        const auto m=maps,w=writes,r=reads,s=starts,t=stops;
        CHECK(!hook_mem_protection(v.uc,UC_MEM_READ_PROT,24,8,0,&v));
        CHECK(!hook_mem_protection(v.uc,UC_MEM_FETCH_PROT,99,4,0,&v));
        CHECK(v.protection_fault.seen && v.protection_fault.address==24 && v.protection_fault.width==8 && v.protection_fault.access==Access::ReadProtection);
        CHECK(!other.protection_fault.seen);CHECK(maps==m && writes==w && reads==r && starts==s && stops==t);
        CHECK(!hook_mem_protection(v.uc,UC_MEM_READ_PROT,0,8,0,nullptr));
        v.protection_fault.reset();CHECK(!hook_mem_protection(v.uc,UC_MEM_READ_UNMAPPED,1,8,0,&v));CHECK(!v.protection_fault.seen);
        for(auto kind:{UC_MEM_READ_PROT,UC_MEM_WRITE_PROT,UC_MEM_FETCH_PROT}){v.protection_fault.reset();CHECK(!hook_mem_protection(v.uc,kind,0,8,0,&v));CHECK(v.protection_fault.seen);}
        for(int width:{-1,0,257,INT32_MAX}){v.protection_fault.reset();CHECK(!hook_mem_protection(v.uc,UC_MEM_READ_PROT,24,width,0,&v));CHECK(v.protection_fault.width==-1);CHECK(bounded_fault_runtime::snapshot(&v,false,0).region==Region::Unknown);}
        v.loaded_libraries.push_back(library());
        for(auto test:std::vector<std::pair<uint64_t,Region>>{{24,Region::LowGuard},{kHeapAddress,Region::Heap},{kStackAddress,Region::Stack},{android_tls_runtime::page,Region::TLS},{v.errno_addr,Region::Errno},{kLibraryAddress+4,Region::Library},{0x90000000,Region::Other}})
            CHECK(bounded_fault_runtime::target_region(&v,test.first,8)==test.second);
        for(uint64_t crossing:{uint64_t(0xffff),kHeapAddress-1,kStackAddress-1,kLibraryAddress-1,kLibraryAddress+0xffff,UINT64_MAX-3}) CHECK(bounded_fault_runtime::target_region(&v,crossing,8)==Region::Unknown);
        v.loaded_libraries.push_back(library());CHECK(bounded_fault_runtime::target_region(&v,kLibraryAddress,8)==Region::Unknown);
        CHECK(bounded_fault_runtime::snapshot(&v,true,kLibraryAddress+16).pc_library==-1);v.loaded_libraries.pop_back();
        auto p=bounded_fault_runtime::snapshot(&v,true,kLibraryAddress+16);CHECK(p.pc_library==0 && p.pc_offset==16);CHECK(p.guard==Guard::Intact);
        for(uint64_t pc:{kLibraryAddress-1,kLibraryAddress+0x10000,UINT64_MAX})CHECK(bounded_fault_runtime::snapshot(&v,true,pc).pc_library==-1);
        CHECK(bounded_fault_runtime::snapshot(&v,false,kLibraryAddress+16).pc_library==-1);
        v.loaded_libraries[0].max_vaddr=UINT64_MAX;CHECK(bounded_fault_runtime::snapshot(&v,true,kLibraryAddress).pc_library==-1);v.loaded_libraries[0]=library();
        fail_regions=true;CHECK(bounded_fault_runtime::snapshot(&v,true,kLibraryAddress).guard==Guard::Unknown);fail_regions=false;
        oversized_regions=true;CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);oversized_regions=false;
        for(auto &region:v.uc->regions)if(region.begin==0)region.perms=UC_PROT_READ;
        CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Changed);
        for(auto &region:v.uc->regions)if(region.begin==0){region.perms=UC_PROT_NONE;region.end=0x7fff;}
        CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);
        // Malformed/ambiguous metadata always wins over accessible low memory,
        // regardless of ordering; even a malformed unrelated tail is rejected.
        const uc_mem_region accessible{0,0xffff,UC_PROT_READ};
        const uc_mem_region overlap{0x8000,0x17fff,UC_PROT_NONE};
        const uc_mem_region malformed{0x20000,0x10000,UC_PROT_NONE};
        const uc_mem_region bad_permissions{0x20000,0x2ffff,0x80};
        for(const auto &bad:{overlap,malformed,bad_permissions}) {
            v.uc->regions={accessible,bad};CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);
            v.uc->regions={bad,accessible};CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);
        }
        v.uc->regions={{0,0xffff,0x80}};CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);
        v.uc->regions={accessible,{0x20000,0x2ffff,UC_PROT_NONE},{0x28000,0x3ffff,UC_PROT_READ}};
        CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);
        std::reverse(v.uc->regions.begin(),v.uc->regions.end());CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Unknown);
        v.uc->regions={accessible,{0x10000,0x1ffff,UC_PROT_READ}};CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Changed);
        std::reverse(v.uc->regions.begin(),v.uc->regions.end());CHECK(bounded_fault_runtime::low_guard(v.uc)==Guard::Changed);
    }
    {
        EmulatorVM v;v.loaded_libraries.push_back(library());raise_fault=true;status=UC_ERR_READ_PROT;final_pc=kLibraryAddress+32;
        const auto m=maps;const auto mapped=v.uc->regions;ProcedureFailure f;bool completed=true;
        CHECK(run_vm_procedure(&v,kLibraryAddress,{},0,0,&completed,&f)==-1013);
        CHECK(!completed && f.engine==13 && f.reason==vm_initialization_diagnostics::Reason::EngineError);
        CHECK(f.fault.access==Access::ReadProtection && f.fault.width==8 && f.fault.region==Region::LowGuard && f.fault.pc_offset==32);
        CHECK(maps==m && v.uc->regions.size()==mapped.size() && memcmp(mapped.data(),v.uc->regions.data(),mapped.size()*sizeof(uc_mem_region))==0);
        fail_pc=true;fail_regions=true;CHECK(run_vm_procedure(&v,kLibraryAddress,{},0,0,&completed,&f)==-1013);CHECK(f.engine==13 && f.fault.pc_library==-1 && f.fault.guard==Guard::Unknown);
        status=UC_ERR_OK;CHECK(run_vm_procedure(&v,kLibraryAddress,{},0,0,&completed,&f)==-1000-UC_ERR_ARG);CHECK(f.engine==UC_ERR_ARG);
        fail_pc=false;fail_regions=false;raise_fault=false;final_pc=kReturnAddress;
        CHECK(run_vm_procedure(&v,kLibraryAddress,{},0,0,&completed,&f)==0);CHECK(completed && !f.fault.available && !v.protection_fault.seen);
        CHECK(run_vm_procedure(&v,0,{},0,0,&completed,&f)==-1 && !v.protection_fault.seen);
        status=UC_ERR_READ_PROT;raise_fault=true;final_pc=kLibraryAddress+32;v.loaded_libraries[0].init_func=kLibraryAddress;
        vm_initialization_diagnostics::ConstructorFailure c;CHECK(!run_library_constructors(&v,&c));CHECK(c.engine==13 && c.fault.pc_offset==32 && v.initialization_failed);
        CHECK(vm_initialization_diagnostics::description(c)=="Library constructor execution failed [v1;kind=dt_init;reason=engine_error;engine=13;library=0;initializer=0]");
        CHECK(!run_library_constructors(&v,&c));CHECK(c.reason==vm_initialization_diagnostics::Reason::PreviouslyFailed && !c.fault.available);
    }
    {
        std::vector<uint8_t> bytes={'a','b','c'};auto known=digest(bytes);char hex[65]={};digest_text(known,hex);CHECK(std::string(hex)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        for(size_t i=0;i<bytes.size();++i)for(unsigned bit=0;bit<8;++bit){auto mutation=bytes;mutation[i]^=1<<bit;CHECK(!same(known,digest(mutation)));}
        std::vector<uint8_t>big(2*65536+7,0x5a);Hash h;CHECK(digest_buffer(big.data(),big.size(),h).known && h.largest==65536 && h.calls==5);
        for(int failure:{1,2,3}){Hash bad;bad.fail=failure;CHECK(!digest_buffer(bytes.data(),bytes.size(),bad).known);}
        Hash null;CHECK(!digest_buffer(nullptr,3,null).known && null.calls==0);
        Snapshot s;s.available=true;s.access=Access::ReadProtection;s.width=8;s.region=Region::LowGuard;s.pc_library=0;s.pc_offset=32;s.guard=Guard::Intact;s.assets[0]=known;
        char out[wire_capacity];CHECK(encode(s,out));CHECK(std::string(out)==std::string("v1;p0_fault_diag1;1;8;1;0;32;1;")+hex+";-");CHECK(strlen(out)<wire_capacity);
        s.access=static_cast<Access>(999);s.region=static_cast<Region>(999);s.guard=static_cast<Guard>(999);s.pc_offset=UINT32_MAX;CHECK(encode(s,out));CHECK(std::string(out).find(";0;-1;0;-1;-1;0;")!=std::string::npos);
        CHECK(!encode({},out) && out[0]==0);
    }
    {
        const auto bytes=data_elf();const auto original_digest=digest(bytes);
        for(size_t i=0;i<bytes.size();++i){auto mutation=bytes;mutation[i]^=1;CHECK(!same(original_digest,digest(mutation)));}
        char path[]="/tmp/bounded-fault-metadata-XXXXXX";int fd=mkstemp(path);CHECK(fd>=0);CHECK(::write(fd,bytes.data(),bytes.size())==ssize_t(bytes.size()));CHECK(::close(fd)==0);
        EmulatorVM v;mutate_path=path;const auto before=starts;CHECK(load_library_to_vm(&v,path,"SECRET-PATH"));mutate_path=nullptr;CHECK(starts==before && v.uc->memory[kLibraryAddress+0x1f0]==0x5a);
#ifdef BOUNDED_FAULT_HOST_APPLE_DIGEST
        CHECK(same(v.loaded_libraries[0].asset_digest,digest(bytes)));
#else
        CHECK(!v.loaded_libraries[0].asset_digest.known);
#endif
        FILE*f=fopen(path,"rb");CHECK(f!=nullptr);std::vector<uint8_t>changed(bytes.size());CHECK(std::fread(changed.data(),1,changed.size(),f)==changed.size());CHECK(fclose(f)==0);CHECK(changed[0x1f0]==0xa5 && !same(digest(bytes),digest(changed)));CHECK(unlink(path)==0);
    }
    CHECK(opens==closes);
    printf("{\"checks\":%u,\"failures\":0,\"guest_execution\":false,\"real_engine_starts\":0,\"proprietary_input\":false,\"synthetic_api_starts\":%u}\n",checks,starts);
}
