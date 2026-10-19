// Host API doubles only. No instruction decoding or guest execution.
#include "../../../Native/Loader/elf_loader_emulator.cpp"
#include <array>
#include <map>
thread_local bool g_isolated_otp_logging_suppressed = true;
extern "C" void anisetteCoreLog(const char *, ...) {}
struct uc_struct { std::map<int,std::array<uint8_t,16>> regs; std::map<uint64_t,uint8_t> memory; };
static bool bad_read=false,bad_write=false; static int stops=0,checks=0;
static EmulatorVM *poison_on_start=nullptr;
static void check(bool b){++checks;if(!b){fprintf(stderr,"failed %d\n",checks);exit(1);}}
static size_t width(int r){return r==UC_ARM64_REG_W0?4:(r>=UC_ARM64_REG_V0&&r<=UC_ARM64_REG_V31?16:8);}
extern "C" {
uc_err uc_open(uc_arch,uc_mode,uc_engine **out){*out=new uc_struct;return UC_ERR_OK;}
uc_err uc_close(uc_engine *e){delete e;return UC_ERR_OK;}
uc_err uc_mem_map(uc_engine*,uint64_t,uint64_t,uint32_t){return UC_ERR_OK;}
uc_err uc_mem_unmap(uc_engine*,uint64_t,uint64_t){return UC_ERR_OK;}
uc_err uc_mem_write(uc_engine *e,uint64_t a,const void *p,uint64_t n){for(uint64_t i=0;i<n;++i)e->memory[a+i]=((const uint8_t*)p)[i];return UC_ERR_OK;}
uc_err uc_mem_read(uc_engine *e,uint64_t a,void *p,uint64_t n){for(uint64_t i=0;i<n;++i)((uint8_t*)p)[i]=e->memory[a+i];return UC_ERR_OK;}
uc_err uc_reg_read(uc_engine *e,int r,void *p){if(bad_read)return UC_ERR_ARG;memcpy(p,e->regs[r].data(),width(r));return UC_ERR_OK;}
uc_err uc_reg_write(uc_engine *e,int r,const void *p){if(bad_write)return UC_ERR_ARG;memcpy(e->regs[r].data(),p,width(r));return UC_ERR_OK;}
uc_err uc_hook_add(uc_engine*,uc_hook*,int,void*,void*,uint64_t,uint64_t,...){return UC_ERR_OK;}
uc_err uc_mem_regions(uc_engine *,uc_mem_region **out,uint32_t *count){*out=nullptr;*count=0;return UC_ERR_NOMEM;}
uc_err uc_free(void *p){std::free(p);return UC_ERR_OK;}
uc_err uc_emu_stop(uc_engine*){++stops;return UC_ERR_OK;}
uc_err uc_emu_start(uc_engine *e,uint64_t,uint64_t end,uint64_t,size_t){
 // API outcome injection only: no guest bytes read/interpreted/executed.
 if(poison_on_start)poison_on_start->initialization_failed=true;
 uc_reg_write(e,UC_ARM64_REG_PC,&end);return UC_ERR_OK;
}
const char *uc_strerror(uc_err){return "host-double";}
}
static void input(EmulatorVM &v,uint64_t n){check(uc_reg_write(v.uc,UC_ARM64_REG_X0,&n)==UC_ERR_OK);}
static uint64_t result(EmulatorVM &v){uint64_t n=0;check(uc_reg_read(v.uc,UC_ARM64_REG_X0,&n)==UC_ERR_OK);return n;}
int main(){
 for(const char *name:{"_Znwm","_Znam"}){
  EmulatorVM v(true);v.import_stubs[kImportAddress]=name;input(v,32);int before=stops;
  import_callback_router(v.uc,kImportAddress,4,&v);
  check(result(v)==kHeapAddress);check(!v.initialization_failed);check(stops==before);
 }
 for(const char *name:{"_ZdlPv","_ZdaPv","_ZdlPvm","_ZdaPvm"}){
  EmulatorVM v(true);v.import_stubs[kImportAddress]=name;input(v,0);int before=stops;
  import_callback_router(v.uc,kImportAddress,4,&v);check(result(v)==0);check(!v.initialization_failed);check(stops==before);
 }
 for(int mode=0;mode<4;++mode){
  EmulatorVM v(true);input(v,mode==2?UINT64_MAX:mode==3?kHeapSize+1ULL:32);int before=stops;
  bad_read=mode==0;bad_write=mode==1;hook_cxx_new(&v);bad_read=bad_write=false;
  check(v.initialization_failed);check(stops==before+1);
 }
 {EmulatorVM v(true);input(v,0);hook_cxx_new(&v);uint64_t first=result(v);input(v,0);hook_cxx_new(&v);check(result(v)==first+64);check(!v.initialization_failed);}
 {EmulatorVM v(true);poison_on_start=&v;bool completed=true;vm_initialization_diagnostics::ProcedureFailure failure;
  run_vm_procedure(&v,kLibraryAddress,{},0,0,&completed,&failure);
  check(!completed);check(v.initialization_failed);check(failure.reason==vm_initialization_diagnostics::Reason::UnexpectedReturn);poison_on_start=nullptr;}
 printf("{\"checks\":%d,\"failures\":0,\"guest_execution\":false}\n",checks);
}
