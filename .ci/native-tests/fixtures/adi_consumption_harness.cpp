
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#define LOG_UC(...) ((void)0)
#define UC_ERR_OK 0
enum {UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2};
struct Fake {uint64_t r[3]={}; unsigned char mem[4096]={}; bool fail_copy=false;};
struct EmulatorVM {Fake *uc; uint64_t errno_addr=16; int next_guest_fd=10;std::unordered_map<int,int> fd_map;};
int uc_reg_read(Fake*u,int r,void*p){memcpy(p,&u->r[r],8);return 0;}
int uc_reg_write(Fake*u,int r,const void*p){memcpy(&u->r[r],p,8);return 0;}
int uc_mem_read(Fake*u,uint64_t a,void*p,size_t n){if(a+n>4096)return 1;memcpy(p,u->mem+a,n);return 0;}
int uc_mem_write(Fake*u,uint64_t a,const void*p,size_t n){if(a+n>4096 || (u->fail_copy && a==512))return 1;memcpy(u->mem+a,p,n);return 0;}
bool deny_read_only_mutation(EmulatorVM*){return false;}
#include "adi_consumption_debug.h"
static int injected_open_errno=0;
static int observed_open(const char *path,int flags,mode_t mode) {
    if(injected_open_errno) { errno=injected_open_errno;return -1; }
    return ::open(path,flags,mode);
}
#define open observed_open
#include "consumer_functions.inc"
#undef open

int main(){
 char path[]="/tmp/SECRET-CANARY-XXXXXX";int fd=mkstemp(path);assert(fd>=0);assert(write(fd,"DATA",4)==4);close(fd);
 uint8_t id[16]={};ADIConsumptionDebug debug("/synthetic",id);strcpy(debug.expected,path);debug.expectedValid=true;
 assert(debug.target(path,true)==ADIConsumptionDebug::ExpectedBlob);
 assert(debug.target("relative",true)==ADIConsumptionDebug::Relative);
 assert(debug.target("/other",true)==ADIConsumptionDebug::Other);
 assert(debug.target(path,false)==ADIConsumptionDebug::Unreadable);
 Fake f;EmulatorVM v{&f};
 {
 ADIConsumptionScope scope(&debug);adiConsumptionPhase(ADIConsumptionDebug::OTP);
 strcpy((char*)f.mem+128,path);f.r[0]=128;f.r[1]=0;f.r[2]=0;hook_open(&v);int g=f.r[0];assert(g>=10);
 f.r[0]=g;f.r[1]=512;f.r[2]=4;hook_read(&v);assert((int64_t)f.r[0]==4 && memcmp(f.mem+512,"DATA",4)==0);
 assert(lseek(v.fd_map[g],0,SEEK_SET)==0);memset(f.mem+512,0,4);f.fail_copy=true;f.r[0]=g;f.r[1]=512;f.r[2]=4;hook_read(&v);assert((int64_t)f.r[0]==4 && memcmp(f.mem+512,"DATA",4)!=0);
 f.fail_copy=false;f.r[0]=g;f.r[1]=512;f.r[2]=4;hook_read(&v);assert((int64_t)f.r[0]==0);
 uint32_t sentinel=77;memcpy(f.mem+16,&sentinel,4);close(v.fd_map[g]);f.r[0]=g;f.r[1]=512;f.r[2]=4;hook_read(&v);uint32_t guest_errno=0;memcpy(&guest_errno,f.mem+16,4);assert((int64_t)f.r[0]==-1 && guest_errno==77);
 f.r[0]=g;hook_close(&v);assert((int64_t)f.r[0]==0); // Original ignored close failure is preserved.
 unlink(path);f.r[0]=128;f.r[1]=0;f.r[2]=0;hook_open(&v);memcpy(&guest_errno,f.mem+16,4);assert((int64_t)f.r[0]==-1 && guest_errno==ENOENT);
 }
 assert(activeADIConsumptionDebug==nullptr);
 {
 ADIConsumptionScope scope(&debug);adiConsumptionPhase(ADIConsumptionDebug::LibraryInit);
 injected_open_errno=EACCES;f.r[0]=128;f.r[1]=0;f.r[2]=0;hook_open(&v);assert((int64_t)f.r[0]==-1);injected_open_errno=0;
 f.r[0]=999;f.r[1]=512;f.r[2]=4;hook_read(&v);assert((int64_t)f.r[0]==-1);
 }
#if ADI_CONSUMER_DEBUG_ENABLED
 assert(debug.count==8);assert(debug.events[0].target==ADIConsumptionDebug::ExpectedBlob && debug.events[0].phase==ADIConsumptionDebug::OTP);
 assert(debug.events[1].copy==0 && debug.events[1].returned==4);
 assert(debug.events[2].copy==1 && debug.events[2].result==1);
 assert(debug.events[3].result==0 && debug.events[3].copy==-1);
 assert(debug.events[4].error==EBADF && debug.events[4].result==-1);
 assert(debug.events[5].error==ENOENT);
 assert(debug.events[6].error==EACCES && debug.events[6].phase==ADIConsumptionDebug::LibraryInit);
 assert(debug.events[7].target==ADIConsumptionDebug::Untracked && debug.events[7].error==0 && debug.events[7].copy==-1);
 char *out=strdup("{\"error\":\"synthetic\"}");errno=91;debug.append(&out);assert(errno==91);assert(strstr(out,"SECRET-CANARY")==nullptr);assert(strstr(out,"DATA")==nullptr);assert(strstr(out,"v3_native_consumption")!=nullptr);free(out);
 for(unsigned i=0;i<64;++i)debug.record(ADIConsumptionDebug::Read,0,-1,99999,UINT64_MAX,UINT64_MAX,999);
 assert(debug.count<=32 && debug.truncated);
 ADIConsumptionDebug crowded(nullptr,nullptr);crowded.phase=ADIConsumptionDebug::LibraryInit;
 for(unsigned i=0;i<40;++i)crowded.record(ADIConsumptionDebug::Open,ADIConsumptionDebug::Other,1,0);
 crowded.phase=ADIConsumptionDebug::OTP;
 for(unsigned i=0;i<40;++i)crowded.record(ADIConsumptionDebug::Read,ADIConsumptionDebug::ExpectedBlob,1,0,4,4,0);
 crowded.record(ADIConsumptionDebug::Read,ADIConsumptionDebug::ExpectedBlob,-1,EIO,UINT64_MAX,0,-1);
 assert(crowded.count==32 && crowded.setupCount==16 && crowded.otpCount==16 && crowded.truncated);
 assert(crowded.events[0].phase==ADIConsumptionDebug::LibraryInit);
 assert(crowded.events[31].phase==ADIConsumptionDebug::OTP && crowded.events[31].error==EIO && crowded.events[31].result==-1);
 assert(crowded.events[31].requested==1048577 && crowded.events[31].copy==-1);
 try { ADIConsumptionScope exceptional(&debug);throw 1; } catch(int) {} assert(activeADIConsumptionDebug==nullptr);
 ADIConsumptionDebug overflow(nullptr,nullptr);for(int i=0;i<65;++i)overflow.track(i,ADIConsumptionDebug::ExpectedBlob);assert(overflow.truncated && overflow.lookup(64)==ADIConsumptionDebug::Untracked && overflow.lookup(-1)==ADIConsumptionDebug::Untracked);
 ADIConsumptionDebug other(nullptr,nullptr);{ADIConsumptionScope outer(&debug);{ADIConsumptionScope inner(&other);assert(activeADIConsumptionDebug==&other);}assert(activeADIConsumptionDebug==&debug);}assert(activeADIConsumptionDebug==nullptr);
#else
 assert(debug.count==0);char *out=strdup("{\"error\":\"synthetic\"}");debug.append(&out);assert(strcmp(out,"{\"error\":\"synthetic\"}")==0);free(out);
#endif
 puts("CONSUMER_OBSERVER_PASS");
}
