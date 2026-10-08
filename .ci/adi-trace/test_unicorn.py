#!/usr/bin/env python3
"""Run the modified production loader against synthetic ARM64 code in Unicorn.
The CPU engine is real Unicorn 2.1.4, not memory doubles. The ELF and all data
are synthetic, not Apple ADI binaries, device data, or an authentication test.
"""
import argparse, hashlib, json, os, shutil, struct, subprocess, tempfile
from pathlib import Path
HARNESS=r'''
#include "Loader/elf_loader_emulator.cpp"
#include <cassert>
#include <iostream>
thread_local bool g_isolated_otp_logging_suppressed=true;
extern "C" void anisetteCoreLog(const char*,...) {}
int main(int argc,char**argv) {
 assert(argc==2); EmulatorVM vm(true);
 assert(load_library_to_vm(&vm,argv[1],"libCoreADI.so"));
 uint64_t start=vm.loaded_libraries[0].base_address+0x100;
 assert(run_vm_procedure(&vm,start,{},100000,1000)==-45061);
 ADIConsumptionDebug observed(nullptr,nullptr);ADIConsumptionScope scope(&observed);
 observed.phase=ADIConsumptionDebug::OTP;
 assert(run_vm_procedure(&vm,start,{},100000,1000)==-45061);
 assert(observed.execution.transitions==1);
 assert(observed.execution.first.before.module==2&&observed.execution.first.before.offset==0x104);
 assert(observed.execution.first.after.offset==0x108);
 assert(observed.execution.returns.count==1&&observed.execution.returns.data[0].offset==0x108);
 assert(observed.execution.modules.hash[1][0]!=0);
 uint64_t pointer=vm.write_string("8000000000000000");
 uint64_t stub=vm.register_import("strtoull");
 run_vm_procedure(&vm,stub,{pointer,0,16},100000,1000);
 assert(observed.execution.bugMask&1);
 assert(observed.execution.imports.count==1&&observed.execution.imports.data[0].code==39);
 uint64_t unknown=vm.register_import("__synthetic_unknown__");
 run_vm_procedure(&vm,unknown,{},100000,1000);
 assert(observed.execution.bugMask&16);
 std::vector<uint8_t> bytes(639,0xA5);
 uint64_t dest=vm.write_bytes(bytes.data(),bytes.size());
 observed.track(50,ADIConsumptionDebug::ExpectedBlob);
 errno=123;adi_observe_guest_read(&vm,50,dest,bytes.data(),bytes.size(),0);assert(errno==123);
 assert(observed.execution.guest==1);
 uint8_t tamper=0xB5;assert(uc_mem_write(vm.uc,dest+3,&tamper,1)==UC_ERR_OK);
 adi_observe_guest_read(&vm,50,dest,bytes.data(),bytes.size(),0);assert(observed.execution.guest==2);
 observed.phase=ADIConsumptionDebug::Constructors;
 run_vm_procedure(&vm,start+0x100,{},1000,100);
 assert(observed.execution.constructorFailures==1);
 char detail[1321];assert(observed.execution.encode(detail,sizeof(detail)));
 std::cout<<"DETAIL="<<detail<<"\nREAL_UNICORN_SYNTHETIC_PASS\n";
}
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('--anisette',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 import unicorn
 assert unicorn.__version__=='2.1.4'
 package=Path(unicorn.__file__).parent
 libraries=list((package/'lib').glob('libunicorn*.dylib'))+list((package/'lib').glob('libunicorn.so*'))
 assert libraries,'Unicorn shared library missing'
 with tempfile.TemporaryDirectory() as temporary:
  tmp=Path(temporary)
  # Vn in the maintained iOS fork corresponds to Qn in the upstream C API.
  # Alias names only in this external test translation unit, never production.
  aliases=''.join(f'#define UC_ARM64_REG_V{i} UC_ARM64_REG_Q{i}\n' for i in range(32))
  (tmp/'main.cpp').write_text(aliases+HARNESS)
  elf=bytearray(4096)
  struct.pack_into('<16sHHIQQQIHHHHHH',elf,0,b'\x7fELF\x02\x01\x01'+b'\0'*9,3,183,1,0,64,0,0,64,56,1,64,0,0)
  struct.pack_into('<IIQQQQQQ',elf,64,1,5,0,0,0,len(elf),len(elf),4096)
  struct.pack_into('<III',elf,0x100,0x52800000,0x12800000|(0xb004<<5),0xd65f03c0)
  (tmp/'fixture.so').write_bytes(elf)
  binary=tmp/'test'
  command=[shutil.which('clang++') or 'c++','-std=c++17','-I',str(a.anisette/'Native'),'-I',str(a.anisette/'Native/include'),'-I',str(package/'include'),str(tmp/'main.cpp'),str(libraries[0]),'-Wl,-rpath,'+str(package/'lib'),'-o',str(binary)]
  subprocess.run(command,check=True,timeout=90)
  run=subprocess.run([str(binary),str(tmp/'fixture.so')],capture_output=True,text=True,timeout=20)
  print(run.stdout)
  if run.returncode:raise RuntimeError(run.stdout+run.stderr)
  digest=hashlib.sha256(elf).hexdigest()
  assert 'H,0,'+digest in run.stdout
  a.output.parent.mkdir(parents=True,exist_ok=True)
  a.output.write_text(json.dumps({'status':'PASS','engine':unicorn.__version__,'scope':'production loader + synthetic ELF, not Apple ADI','fixture_sha256':digest,'stdout':run.stdout},indent=2)+'\n')
if __name__=='__main__':main()
