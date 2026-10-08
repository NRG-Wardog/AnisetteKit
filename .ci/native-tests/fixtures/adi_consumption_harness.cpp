
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

static unsigned host_opens=0,host_reads=0,host_closes=0,host_writes=0;
static ssize_t observed_read(int fd,void *bytes,size_t length) { ++host_reads; return ::read(fd,bytes,length); }
static int observed_close(int fd) { ++host_closes; return ::close(fd); }
static ssize_t observed_write(int fd,const void *bytes,size_t length) { ++host_writes;return ::write(fd,bytes,length); }

static int injected_open_errno=0;
static int observed_open(const char *path,int flags,mode_t mode) {
    ++host_opens;
    if(injected_open_errno) { errno=injected_open_errno;return -1; }
    return ::open(path,flags,mode);
}
#define open observed_open
#define read observed_read
#define close observed_close
#define write observed_write
#include "consumer_functions.inc"
#undef open
#undef read
#undef close
#undef write

void comparison_fixtures();

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
 comparison_fixtures();
 printf("HOST_IO_COUNTS=%u,%u,%u,%u\n",host_opens,host_reads,host_closes,host_writes);
 puts("CONSUMER_OBSERVER_PASS");
}


struct SyntheticStream {
    char path[64] = "/tmp/SECRET-COMPARISON-XXXXXX";
    Fake fake;
    EmulatorVM vm{&fake};
    ADIConsumptionDebug debug;
    ADIConsumptionScope scope;
    int guest = -1;
    SyntheticStream(const std::string &host, const std::string &input, int flags=0, bool expected=true)
        : debug(nullptr,nullptr,reinterpret_cast<const uint8_t *>(input.data()),static_cast<uint32_t>(input.size())), scope(&debug) {
        const int fd=mkstemp(path);assert(fd>=0);
        assert(::write(fd,host.data(),host.size())==static_cast<ssize_t>(host.size()));assert(::close(fd)==0);
        strcpy(debug.expected,expected ? path : "/some-other-expected-path");debug.expectedValid=true;
        debug.phase=ADIConsumptionDebug::OTP;
        open(flags);
    }
    void open(int flags=0) {
        strcpy(reinterpret_cast<char *>(fake.mem)+128,path);
        fake.r[0]=128;fake.r[1]=flags;fake.r[2]=0;hook_open(&vm);
        guest=static_cast<int>(fake.r[0]);assert(guest>=10);
    }
    int64_t read(unsigned count, bool failCopy=false) {
        fake.fail_copy=failCopy;fake.r[0]=guest;fake.r[1]=512;fake.r[2]=count;
        errno=93;hook_read(&vm);assert(errno==93);
        return static_cast<int64_t>(fake.r[0]);
    }
    void close() { if(guest<0)return;fake.r[0]=guest;hook_close(&vm);assert(static_cast<int64_t>(fake.r[0])==0);guest=-1; }
    void state(unsigned comparison,unsigned coverage) {
#if ADI_CONSUMER_DEBUG_ENABLED
        assert(debug.comparison==comparison && debug.coverage()==coverage);
        char *out=strdup("{\"error\":\"synthetic\"}");errno=94;debug.append(&out);assert(errno==94);
        assert(strstr(out,"SECRET")==nullptr && strstr(out,"DATA")==nullptr);
        const std::string header="v2|"+std::to_string(debug.truncated?1:0)+"|"+std::to_string(comparison)+"|"+std::to_string(coverage);
        assert(strstr(out,header.c_str()));assert(strlen(out)<2100);free(out);
#else
        assert(debug.comparison==0 && debug.coverage()==0);
#endif
    }
    ~SyntheticStream() { close();assert(unlink(path)==0); }
};

void comparison_fixtures() {
    // Immutable input objects outlive the observer; no host or guest re-read.
    const std::string input="DATA-INPUT",shortInput="DATA",different="DAXA-INPUT";
    { SyntheticStream s(input,input);s.state(0,0);assert(s.read(4)==4);s.state(1,0);assert(s.read(6)==6);s.state(1,1);assert(s.read(4)==0);s.state(1,1);s.close();s.state(1,1); }
    { SyntheticStream s(input,input,2);assert(s.read(10)==10);s.state(1,1); } // O_RDWR starts at offset zero too.
    { SyntheticStream s(shortInput,input);assert(s.read(10)==4);assert(s.read(10)==0);s.state(1,0); }
    { SyntheticStream s("",input);assert(s.read(10)==0);s.state(0,0); }
    { SyntheticStream s(different,input);assert(s.read(4)==4);s.state(2,0);assert(s.read(6)==6);s.state(2,0); }
    { SyntheticStream s(input,shortInput);assert(s.read(4)==4);s.state(1,1);assert(s.read(6)==6);s.state(2,0); }
    { SyntheticStream s(input,input);assert(s.read(4,true)==4);s.state(1,0);assert(s.read(6)==6);s.state(1,0); }
    { SyntheticStream s(input,input,0,false);assert(s.read(10)==10);s.state(0,0); }
    { SyntheticStream s(input,input);assert(s.read(4)==4);const int reused=s.guest;s.close();s.vm.next_guest_fd=reused;s.open();assert(s.guest==reused);assert(s.read(6)==6);s.state(1,0);assert(s.read(4)==4);s.state(1,1); }
    { SyntheticStream s(input,input);assert(s.read(4)==4);s.debug.forget(s.guest);assert(s.read(6)==6);s.state(1,0); }
    { SyntheticStream s(input,input,2);assert(s.read(4)==4);s.fake.mem[512]='-';s.fake.r[0]=s.guest;s.fake.r[1]=512;s.fake.r[2]=1;errno=96;hook_write(&s.vm);assert(s.fake.r[0]==1 && errno==96);assert(s.read(5)==5);s.state(1,0); }
    { SyntheticStream s(input,"");assert(s.read(10)==10);s.state(0,0); }
#if ADI_CONSUMER_DEBUG_ENABLED
    const uint8_t *bytes=reinterpret_cast<const uint8_t *>(input.data());
    ADIConsumptionDebug nullInput(nullptr,nullptr,nullptr,10);nullInput.track(1,ADIConsumptionDebug::ExpectedBlob);nullInput.observeRead(1,bytes,10,0);assert(nullInput.comparison==0 && nullInput.coverage()==0);
    ADIConsumptionDebug oversized(nullptr,nullptr,bytes,1048577);oversized.track(1,ADIConsumptionDebug::ExpectedBlob);oversized.observeRead(1,bytes,10,0);assert(oversized.comparison==0 && oversized.coverage()==0);
    ADIConsumptionDebug untracked(nullptr,nullptr,bytes,10);untracked.observeRead(9,bytes,10,0);assert(untracked.comparison==0 && untracked.coverage()==0);
    ADIConsumptionDebug unknown(nullptr,nullptr,bytes,10);unknown.track(1,ADIConsumptionDebug::ExpectedBlob,false);unknown.observeRead(1,bytes,10,0);assert(unknown.comparison==0 && unknown.coverage()==0);
    ADIConsumptionDebug multi(nullptr,nullptr,bytes,10);multi.track(1,ADIConsumptionDebug::ExpectedBlob);multi.track(2,ADIConsumptionDebug::ExpectedBlob);multi.observeRead(1,bytes,6,0);multi.observeRead(2,bytes,4,0);assert(multi.comparison==1 && multi.coverage()==0);multi.observeRead(1,bytes+6,4,0);assert(multi.coverage()==1);
    ADIConsumptionDebug sticky(nullptr,nullptr,bytes,10);sticky.track(1,ADIConsumptionDebug::ExpectedBlob);sticky.observeRead(1,reinterpret_cast<const uint8_t *>(different.data()),10,0);sticky.forget(1);sticky.track(1,ADIConsumptionDebug::ExpectedBlob);sticky.observeRead(1,bytes,10,0);assert(sticky.comparison==2 && sticky.coverage()==0);
    ADIConsumptionDebug lostCopy(nullptr,nullptr,bytes,10);lostCopy.track(1,ADIConsumptionDebug::ExpectedBlob);lostCopy.observeRead(1,bytes,10,0);assert(lostCopy.coverage()==1);lostCopy.track(2,ADIConsumptionDebug::ExpectedBlob);lostCopy.observeRead(2,bytes,10,7);assert(lostCopy.comparison==1 && lostCopy.coverage()==0);
    ADIConsumptionDebug tracking(nullptr,nullptr,bytes,10);tracking.track(0,ADIConsumptionDebug::ExpectedBlob);tracking.observeRead(0,bytes,10,0);for(int i=1;i<65;++i)tracking.track(i,ADIConsumptionDebug::Other);assert(tracking.truncated && tracking.coverage()==0);
    ADIConsumptionDebug overflow(nullptr,nullptr,bytes,10);overflow.track(1,ADIConsumptionDebug::ExpectedBlob);overflow.descriptors[0].offset=UINT64_MAX-1;overflow.observeRead(1,bytes,10,0);assert(overflow.comparison==0 && overflow.coverage()==0);
    std::vector<uint8_t> large(1048576,'Q');
    ADIConsumptionDebug budget(nullptr,nullptr,large.data(),static_cast<uint32_t>(large.size()));budget.track(1,ADIConsumptionDebug::ExpectedBlob);budget.observeRead(1,large.data(),524288,0);budget.observeRead(1,large.data()+524288,524288,0);assert(budget.compared==1048576 && budget.coverage()==1);budget.track(2,ADIConsumptionDebug::ExpectedBlob);budget.observeRead(2,large.data(),1,0);assert(budget.compared==1048576 && budget.comparison==1 && budget.coverage()==0);
    ADIConsumptionDebug partialBudget(nullptr,nullptr,large.data(),static_cast<uint32_t>(large.size()));partialBudget.track(1,ADIConsumptionDebug::ExpectedBlob);partialBudget.observeRead(1,large.data(),524289,0);partialBudget.forget(1);partialBudget.track(1,ADIConsumptionDebug::ExpectedBlob);partialBudget.observeRead(1,large.data(),1048576,0);assert(partialBudget.compared==1048576 && partialBudget.comparison==1 && partialBudget.coverage()==0);
    ADIConsumptionDebug capped(nullptr,nullptr,bytes,10);capped.phase=ADIConsumptionDebug::OTP;capped.track(1,ADIConsumptionDebug::ExpectedBlob);capped.observeRead(1,bytes,10,0);assert(capped.coverage()==1);for(unsigned i=0;i<40;++i)capped.record(ADIConsumptionDebug::Read,ADIConsumptionDebug::ExpectedBlob,1,4095,UINT64_MAX,UINT64_MAX,32);assert(capped.truncated && capped.coverage()==0);char *out=strdup("{\"error\":\"synthetic\"}");capped.append(&out);assert(strstr(out,"v2|1|1|0"));assert(strlen(out)<2100);free(out);
#endif
}
