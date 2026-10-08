#ifndef ADI_EXECUTION_DEBUG_H
#define ADI_EXECUTION_DEBUG_H
// Measurement only. No identity, input bytes, paths, raw PCs or register values
// are serialized. Hashes describe the two ELF file buffers actually loaded.
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cerrno>
#include <algorithm>

struct ADIPreserveErrno { int value = errno; ~ADIPreserveErrno() { errno = value; } };
namespace adi_execution {
inline uint32_t rotate(uint32_t n, unsigned b) { return (n >> b) | (n << (32-b)); }
inline void sha256(const uint8_t *data, size_t length, char out[65]) noexcept {
    static constexpr uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const size_t blocks=length/64+1+((length%64)>=56);
    for(size_t block=0;block<blocks;++block) {
        uint8_t bytes[64]={};
        for(size_t j=0;j<64;++j){size_t at=block*64+j;
            if(at<length) bytes[j]=data[at];
            else if(at==length) bytes[j]=0x80;
            if(block==blocks-1&&j>=56) bytes[j]=uint8_t((uint64_t(length)*8)>>(8*(63-j)));
        }
        uint32_t w[64]={};
        for(unsigned j=0;j<16;++j) w[j]=(uint32_t(bytes[4*j])<<24)|(uint32_t(bytes[4*j+1])<<16)|(uint32_t(bytes[4*j+2])<<8)|bytes[4*j+3];
        for(unsigned j=16;j<64;++j){uint32_t a=w[j-15],b=w[j-2];w[j]=w[j-16]+(rotate(a,7)^rotate(a,18)^(a>>3))+w[j-7]+(rotate(b,17)^rotate(b,19)^(b>>10));}
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];
        for(unsigned j=0;j<64;++j){uint32_t t1=z+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[j]+w[j];
            uint32_t t2=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
    }
    for(unsigned i=0;i<8;++i) std::snprintf(out+8*i,9,"%08x",h[i]);
}
struct Location { unsigned module=0; uint32_t offset=0; };
struct Range { uint64_t base=0,begin=0,end=0; unsigned module=0; };
struct Modules {
    char hash[2][65] = {};
    std::array<Range,16> ranges{};
    unsigned count=0;
    bool incomplete=false;
    void add(unsigned module,uint64_t base,uint64_t begin,uint64_t end) noexcept {
        if(module<1||module>2||begin<base||end<=begin||end-base>UINT32_MAX||count==ranges.size()){incomplete=true;return;}
        ranges[count++]={base,begin,end,module};
    }
    Location locate(uint64_t pc) const noexcept {
        for(unsigned i=0;i<count;++i){const auto&r=ranges[i];if(pc>=r.begin&&pc<r.end)return {r.module,uint32_t(pc-r.base)};}
        return {};
    }
};
template<class T, unsigned N> struct Ring {
    std::array<T,N> data{}; unsigned count=0; uint32_t omitted=0;
    void push(const T&v) noexcept {
        if(count==N){std::move(data.begin()+1,data.end(),data.begin());if(omitted!=UINT32_MAX)++omitted;--count;}
        data[count++]=v;
    }
};
struct Transition { Location before{},after{}; };
struct Import { unsigned phase=0,code=0,index=0; Location caller{}; unsigned result=0,error=0; };
struct Capture {
    bool active=false;
    Modules modules{};
    unsigned flags=0,guest=0,bugMask=0;
    uint32_t instructions=0,transitions=0,constructorFailures=0;
    Location previous{};
    bool previousError=false;
    Transition first{},last{};
    Ring<Location,6> preceding{}, beforeLast{};
    Ring<Location,4> returns{};
    Ring<Import,8> imports{};
    static void increment(uint32_t&v) noexcept {if(v!=UINT32_MAX)++v;}
    void boundary() noexcept { previous={};previousError=false; }
    bool observe(Location here,bool error,bool readable) noexcept {
        active=true;increment(instructions);
        if(!readable){flags|=1;boundary();return false;}
        if(!here.module){boundary();return false;}
        if(error&&!previousError){Transition t{previous,here};if(transitions==0)first=t;last=t;beforeLast=preceding;increment(transitions);}
        preceding.push(here);previous=here;previousError=error;
        return error;
    }
    void guestResult(unsigned result) noexcept {
        if(result==2||guest==2)guest=2;
        else if(result==3||guest==3)guest=3;
        else guest=1;
    }
    bool encode(char *out,size_t capacity) const noexcept {
        ADIPreserveErrno save;
        size_t used=0;bool okay=true;
        auto add=[&](const char*format,auto... values){if(!okay)return;int n=std::snprintf(out+used,capacity-used,format,values...);
            if(n<0||size_t(n)>=capacity-used){okay=false;return;}used+=size_t(n);};
        add("x1;H,%s,%s;S,%u,%u,%u,%u,%u,%u,%u",modules.hash[0][0]?modules.hash[0]:"0",modules.hash[1][0]?modules.hash[1]:"0",
            flags|(modules.incomplete?2u:0u)|(returns.omitted?4u:0u)|(beforeLast.omitted?8u:0u),instructions,transitions,imports.omitted,constructorFailures,guest,bugMask);
        add(";F,%u,%u,%u,%u",first.before.module,first.before.offset,first.after.module,first.after.offset);
        add(";L,%u,%u,%u,%u",last.before.module,last.before.offset,last.after.module,last.after.offset);
        for(unsigned i=0;i<beforeLast.count;++i)add(";P,%u,%u",beforeLast.data[i].module,beforeLast.data[i].offset);
        for(unsigned i=0;i<returns.count;++i)add(";R,%u,%u",returns.data[i].module,returns.data[i].offset);
        for(unsigned i=0;i<imports.count;++i){auto&e=imports.data[i];add(";I,%u,%u,%u,%u,%u,%u,%u",e.phase,e.code,e.index,e.caller.module,e.caller.offset,e.result,e.error);}
        return okay;
    }
};
} // namespace adi_execution
#endif
