// Diagnostic fixture includes the actual core implementation to observe its
// internal setup flags without exposing account/error data in the public ABI.
#include "anisette_core_uc.cpp"
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include <CommonCrypto/CommonDigest.h>
#include <iomanip>
#include <sstream>
#ifdef NDEBUG
#error "Trusted-library fixture must retain all validation assertions"
#endif
static std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream stream(path,std::ios::binary);
    assert(stream.good());
    return {std::istreambuf_iterator<char>(stream),std::istreambuf_iterator<char>()};
}
static std::string digest(const std::vector<uint8_t> &bytes) {
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(bytes.data(),static_cast<CC_LONG>(bytes.size()),result);
    std::ostringstream out; out << std::hex << std::setfill('0');
    for(unsigned char byte:result)out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}
int main(int argc,char **argv) {
    assert(argc==2);
    // The runner verifies exact reviewed library hashes before invoking this.
    const std::string lib=argv[1];
    auto ssc=read_file(lib+"/libstoreservicescore.so"),adi=read_file(lib+"/libCoreADI.so");
    assert(ssc.size()==2388480 && adi.size()==1792592);
    assert(digest(ssc)=="bd335e6963ba5ae2f5babca613435ad56d2660a9aee37df35f876c458d105ce4");
    assert(digest(adi)=="9d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22");
    char temporary[]="/tmp/owned-adi-startup-XXXXXX"; assert(mkdtemp(temporary));
    uint8_t identity[16]; std::random_device random;
    for(auto &byte:identity)byte=static_cast<uint8_t>(random());
    identity[6]=(identity[6]&0x0f)|0x40; identity[8]=(identity[8]&0x3f)|0x80;
    const uint8_t invalid_blob[]={0x00,0x01,0x02};
    auto *attempt=anisette_owned_attempt_create(lib.c_str(),temporary,identity,60000);
    if(!attempt) {
        bool removed=rmdir(temporary)==0;
        std::cout << "{\"attempt_creation_failed\":true,\"parent_removed\":" << removed << "}\n";
        return 1;
    }
    std::string state=anisette_owned_attempt_directory(attempt);
    if(anisette_owned_attempt_stage_libraries(attempt,ssc.data(),static_cast<uint32_t>(ssc.size()),adi.data(),static_cast<uint32_t>(adi.size()))!=0) {
        bool drained=anisette_owned_attempt_finish(attempt)==0 && anisette_owned_attempt_is_quiescent(attempt);
        anisette_owned_attempt_release(attempt);
        bool removed=rmdir(temporary)==0;
        std::cout << "{\"library_staging_failed\":true,\"drained\":" << drained << ",\"owned_root_removed\":" << removed << "}\n";
        return 1;
    }
    char *output=nullptr;
    int32_t result=anisette_owned_attempt_headers(attempt,invalid_blob,sizeof(invalid_blob),&output);
    // No OTP/blob/header is printed, including if invalid input unexpectedly succeeds.
    bool engine=attempt->state.vm && !attempt->state.vm->initialization_failed;
    bool libraries=attempt->state.libraries_initialized;
    bool path=!attempt->state.provisioning_path.empty();
    bool android=!attempt->state.android_id.empty();
    bool rejected=result!=0 && output==nullptr;
    if(output)free_c_string(output);
    bool drained=anisette_owned_attempt_finish(attempt)==0 && anisette_owned_attempt_is_quiescent(attempt);
    anisette_owned_attempt_release(attempt);
    bool removed=access(state.c_str(),F_OK)!=0 && errno==ENOENT;
    bool parent_removed=rmdir(temporary)==0;
    std::cout << "{\"engine_returned\":" << engine << ",\"libraries_initialized\":" << libraries
              << ",\"provisioning_path_initialized\":" << path << ",\"android_id_initialized\":" << android
              << ",\"invalid_blob_rejected\":" << rejected << ",\"drained\":" << drained
              << ",\"owned_root_removed\":" << (removed&&parent_removed) << "}\n";
    return engine && libraries && path && android && rejected && drained && removed && parent_removed ? 0 : 1;
}
