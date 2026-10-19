// Exact production source plus sparse host-only API doubles. No engine linked.
// uc_emu_start aborts if called: these tests cannot execute guest instructions.
#include "../../../Native/Loader/elf_loader_emulator.cpp"
#include <array>
#include <map>
#include <new>
thread_local bool g_isolated_otp_logging_suppressed = true;
extern "C" void anisetteCoreLog(const char *, ...) {}
static bool fail_next_new = false;
void *operator new(std::size_t size) {
    if (fail_next_new) { fail_next_new = false; throw std::bad_alloc(); }
    if (void *p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
struct uc_struct { std::map<int,std::array<uint8_t,16>> regs; std::map<uint64_t,uint8_t> memory; };
static bool fail_reads=false, fail_writes=false, fail_reg_reads=false, fail_reg_writes=false;
static int checks=0, starts=0, stops=0, reads=0, writes=0;
static uint64_t largest_transfer=0, last_read_address=0, last_read_size=0;
static void check(bool okay) { ++checks; if (!okay) {fprintf(stderr,"check %d failed\n",checks);exit(1);} }
static size_t width(int r) {return r==UC_ARM64_REG_W0?4:(r>=UC_ARM64_REG_V0&&r<=UC_ARM64_REG_V31?16:8);}
extern "C" {
uc_err uc_open(uc_arch,uc_mode,uc_engine **out){*out=new uc_struct;return UC_ERR_OK;}
uc_err uc_close(uc_engine *e){delete e;return UC_ERR_OK;}
uc_err uc_mem_map(uc_engine *,uint64_t,uint64_t,uint32_t){return UC_ERR_OK;}
uc_err uc_mem_unmap(uc_engine *,uint64_t,uint64_t){return UC_ERR_OK;}
uc_err uc_mem_write(uc_engine *e,uint64_t a,const void *p,uint64_t n){++writes;largest_transfer=(std::max)(largest_transfer,n);if(fail_writes)return UC_ERR_WRITE_UNMAPPED;for(uint64_t i=0;i<n;++i)e->memory[a+i]=((const uint8_t*)p)[i];return UC_ERR_OK;}
uc_err uc_mem_read(uc_engine *e,uint64_t a,void *p,uint64_t n){++reads;last_read_address=a;last_read_size=n;largest_transfer=(std::max)(largest_transfer,n);if(fail_reads)return UC_ERR_READ_UNMAPPED;for(uint64_t i=0;i<n;++i)((uint8_t*)p)[i]=e->memory[a+i];return UC_ERR_OK;}
uc_err uc_reg_read(uc_engine *e,int r,void *p){if(fail_reg_reads)return UC_ERR_ARG;memcpy(p,e->regs[r].data(),width(r));return UC_ERR_OK;}
uc_err uc_reg_write(uc_engine *e,int r,const void *p){if(fail_reg_writes)return UC_ERR_ARG;memcpy(e->regs[r].data(),p,width(r));return UC_ERR_OK;}
uc_err uc_hook_add(uc_engine *,uc_hook *,int,void *,void *,uint64_t,uint64_t,...){return UC_ERR_OK;}
uc_err uc_emu_stop(uc_engine *){++stops;return UC_ERR_OK;}
uc_err uc_emu_start(uc_engine *,uint64_t,uint64_t,uint64_t,size_t){++starts;std::abort();}
const char *uc_strerror(uc_err){return "host-only memory boundary double";}
}
static void reg(EmulatorVM &v,int which,uint64_t n){check(uc_reg_write(v.uc,which,&n)==UC_ERR_OK);}
static uint64_t result(EmulatorVM &v){uint64_t n=0;check(uc_reg_read(v.uc,UC_ARM64_REG_X0,&n)==UC_ERR_OK);return n;}
static void args(EmulatorVM &v,uint64_t x0,uint64_t x1=0,uint64_t x2=0){reg(v,UC_ARM64_REG_X0,x0);reg(v,UC_ARM64_REG_X1,x1);reg(v,UC_ARM64_REG_X2,x2);}
static void route(EmulatorVM &v,const char *name){v.import_stubs[kImportAddress]=name;import_callback_router(v.uc,kImportAddress,4,&v);}
static uint64_t allocate(EmulatorVM &v,uint64_t size){args(v,size);route(v,"malloc");check(!v.initialization_failed);return result(v);}
static void poisoned(EmulatorVM &v,int before){check(v.initialization_failed);check(stops==before+1);}
int main(){
 {PageAllocator a(0x1000,128,64);check(a.alloc(UINT64_MAX)==0);check(a.alloc(64)==0x1000);check(a.alloc(64)==0x1040);check(a.alloc(1)==0);}
 for(uint64_t align:{uint64_t(0),uint64_t(3)}){PageAllocator a(0x1000,128,align);check(a.alloc(1)==0);}
 {PageAllocator a(UINT64_MAX-32,128,64);check(a.alloc(1)==0);}
 for(uint64_t size:{UINT64_MAX,UINT64_MAX-16,uint64_t(kHeapSize)+1}){
  EmulatorVM v(true);args(v,size);int before=stops;route(v,"malloc");poisoned(v,before);check(v.heap_allocation_sizes.empty());
 }
 {EmulatorVM v(true);check(v.heap.alloc(kHeapSize)==kHeapAddress);args(v,1);int before=stops;route(v,"malloc");poisoned(v,before);}
 {EmulatorVM v(true);args(v,uint64_t(1)<<63,2);int before=stops;route(v,"calloc");poisoned(v,before);check(v.heap_allocation_sizes.empty());}
 {EmulatorVM v(true);args(v,3,5);route(v,"calloc");auto p=result(v);check(v.heap_allocation_sizes.at(p)==15);for(unsigned i=0;i<15;++i)check(v.uc->memory[p+i]==0);}
 {EmulatorVM v(true);auto a=allocate(v,0),b=allocate(v,0);check(b==a+64);check(v.heap_allocation_sizes.at(a)==0);}
 {EmulatorVM v(true);auto old=allocate(v,16),neighbor=allocate(v,16);uint8_t data[16];memset(data,0x42,16);uc_mem_write(v.uc,old,data,16);uint64_t marker=0x8877665544332211ULL;uc_mem_write(v.uc,neighbor,&marker,8);
  args(v,old,80);route(v,"realloc");auto grown=result(v);check(!v.initialization_failed);check(last_read_address==old&&last_read_size==16);check(v.heap_allocation_sizes.count(old)==0);check(v.heap_allocation_sizes.at(grown)==80);
  for(unsigned i=0;i<16;++i)check(v.uc->memory[grown+i]==0x42);check(v.uc->memory.count(grown+64)==0);check(v.heap_allocation_sizes.at(neighbor)==16);
  args(v,grown,8);route(v,"realloc");auto shrunk=result(v);check(last_read_size==8);check(v.heap_allocation_sizes.at(shrunk)==8);check(v.heap_allocation_sizes.count(grown)==0);
 }
 {EmulatorVM v(true);args(v,0,19);route(v,"realloc");check(result(v)==kHeapAddress);check(v.heap_allocation_sizes.at(kHeapAddress)==19);}
 {EmulatorVM v(true);auto old=allocate(v,10);args(v,old,0);route(v,"realloc");check(result(v)==old+64);check(v.heap_allocation_sizes.count(old)==0);check(v.heap_allocation_sizes.at(old+64)==0);}
 {EmulatorVM v(true);auto old=allocate(v,16);args(v,old+1,32);int before=stops;route(v,"realloc");poisoned(v,before);check(v.heap_allocation_sizes.at(old)==16);}
 for(bool fail_read:{false,true}){
  EmulatorVM v(true);auto old=allocate(v,16);args(v,old,32);int before=stops;fail_reads=fail_read;fail_writes=!fail_read;route(v,"realloc");fail_reads=fail_writes=false;poisoned(v,before);check(result(v)==old);check(v.heap_allocation_sizes.size()==1);check(v.heap_allocation_sizes.at(old)==16);
 }
 {EmulatorVM v(true);auto old=allocate(v,16);args(v,old,UINT64_MAX);int before=stops;route(v,"realloc");poisoned(v,before);check(v.heap_allocation_sizes.at(old)==16);}
 {EmulatorVM v(true);auto old=allocate(v,16);args(v,old);route(v,"free");check(!v.initialization_failed);check(v.heap_allocation_sizes.empty());check(allocate(v,16)==old+64);}
 for(const char *name:{"_Znwm","_Znam","__cxa_allocate_exception"}){EmulatorVM v(true);args(v,7);route(v,name);check(v.heap_allocation_sizes.at(result(v))==7);}
 {EmulatorVM v(true);args(v,UINT64_MAX);int before=stops;route(v,"__cxa_allocate_exception");poisoned(v,before);}
 {EmulatorVM v(true);args(v,16);v.import_stubs[kImportAddress]="malloc";int before=stops;fail_next_new=true;import_callback_router(v.uc,kImportAddress,4,&v);check(!fail_next_new);poisoned(v,before);}
 for(bool read_failure:{false,true}){EmulatorVM v(true);args(v,16);int before=stops;fail_reg_reads=read_failure;fail_reg_writes=!read_failure;route(v,"malloc");fail_reg_reads=fail_reg_writes=false;poisoned(v,before);}
 {EmulatorVM v(true);uint8_t data[3]={1,2,3};int before=stops;fail_writes=true;check(v.write_bytes(data,3)==0);fail_writes=false;poisoned(v,before);}
 {EmulatorVM v(true);uint8_t data[3]={1,2,3};auto p=v.write_bytes(data,3);check(p==kHeapAddress);check(v.heap_allocation_sizes.at(p)==3);check(v.uc->memory[p+2]==3);}
 {EmulatorVM v(true);auto src=allocate(v,9000),dst=allocate(v,9000);args(v,src,0x5a,9000);largest_transfer=0;route(v,"memset");check(!v.initialization_failed);check(largest_transfer<=4096);args(v,dst,src,9000);route(v,"memcpy");check(!v.initialization_failed);check(largest_transfer<=4096);check(v.uc->memory[dst+8999]==0x5a);args(v,dst,src,9000);route(v,"memcmp");check(result(v)==0);v.uc->memory[dst+8999]=0x5b;args(v,dst,src,9000);route(v,"memcmp");check(result(v)>0);}
 for(const char *name:{"memcpy","memcmp","strcpy","strncpy"}){EmulatorVM v(true);args(v,kHeapAddress+64,kHeapAddress,4);int before=stops;int writes_before=writes;fail_reads=true;route(v,name);fail_reads=false;poisoned(v,before);check(writes==writes_before);}
 for(const char *name:{"memcpy","memset","strcpy","strncpy"}){EmulatorVM v(true);args(v,kHeapAddress+64,kHeapAddress,4);int before=stops;fail_writes=true;route(v,name);fail_writes=false;poisoned(v,before);}
 for(const char *name:{"memcpy","memset","memcmp","strncpy"}){EmulatorVM v(true);args(v,UINT64_MAX-1,kHeapAddress,4);int before=stops;int transfers=reads+writes;route(v,name);poisoned(v,before);check(reads+writes==transfers);}
 for(uint64_t low:{uint64_t(0),uint64_t(0x18),uint64_t(0xffff)}){EmulatorVM v(true);args(v,kHeapAddress,low,1);int before=stops;int transfers=reads+writes;route(v,"memcpy");poisoned(v,before);check(reads+writes==transfers);}
 {EmulatorVM v(true);auto src=v.write_string("abc"),dst=allocate(v,8);args(v,dst,src);route(v,"strcpy");check(v.uc->memory[dst+3]==0);args(v,dst,src,8);route(v,"strncpy");check(v.uc->memory[dst+7]==0);check(!v.initialization_failed);}
 {EmulatorVM v(true);args(v,0,0,0);route(v,"memcpy");check(!v.initialization_failed);check(result(v)==0);}
 {EmulatorVM v(true);FILE *f=tmpfile();check(f!=nullptr);check(fwrite("abc",1,3,f)==3);fflush(f);rewind(f);v.fd_map[10]=dup(fileno(f));args(v,10,kHeapAddress,3);int before=stops;fail_writes=true;route(v,"read");fail_writes=false;poisoned(v,before);check(result(v)==10);fclose(f);}
 {EmulatorVM v(true);FILE *f=tmpfile();check(f!=nullptr);v.fd_map[10]=dup(fileno(f));args(v,10,kHeapAddress,3);int before=stops;fail_reads=true;route(v,"write");fail_reads=false;poisoned(v,before);check(lseek(v.fd_map[10],0,SEEK_END)==0);check(result(v)==10);fclose(f);}
 {EmulatorVM v(true);FILE *f=tmpfile();check(f!=nullptr);v.fd_map[10]=dup(fileno(f));args(v,10,kHeapAddress,16);v.import_stubs[kImportAddress]="read";int before=stops;fail_next_new=true;import_callback_router(v.uc,kImportAddress,4,&v);check(!fail_next_new);poisoned(v,before);check(result(v)==10);fclose(f);}
 check(starts==0);
 printf("{\"checks\":%d,\"failures\":0,\"guest_execution\":false,\"engine_starts\":%d,\"proprietary_input\":false}\n",checks,starts);
}
