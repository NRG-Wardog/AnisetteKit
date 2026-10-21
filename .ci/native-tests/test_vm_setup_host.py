#!/usr/bin/env python3
"""Host-only setup failure injection. Uses trusted headers, never links/runs an engine.
The core setup prefix, isolated scope and output-buffer preparation blocks are
extracted unchanged; library loading is excluded. No proprietary input is used.
"""
from pathlib import Path
import subprocess,os,json,hashlib,argparse
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--unicorn-include',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();root=a.output.resolve();root.mkdir(parents=True,exist_ok=True)
repo=Path(__file__).resolve().parents[2]
evidence=[repo / name for name in ['Native/Loader/elf_loader_emulator.cpp','Native/Loader/elf_loader_emulator.h','Native/Loader/elf_metadata_bounds.h','Native/Loader/android_tls_runtime.h','Native/Loader/cxx_allocation_runtime.h','Native/anisette_core_uc.cpp','.ci/native-tests/fixtures/vm_setup_host.cpp','.ci/native-tests/test_vm_setup_host.py']]
def hashes(): return {str(f.relative_to(repo)):hashlib.sha256(f.read_bytes()).hexdigest() for f in evidence}
evidence += [repo / 'Native/Loader' / name for name in ('bounded_fault_diagnostics.h','bounded_fault_runtime.h','bounded_asset_digest.h','vm_initialization_diagnostics.h','native_logging_policy.h')]
before=hashes()
source=repo/'Native/Loader/elf_loader_emulator.cpp';core=repo/'Native/anisette_core_uc.cpp';text=core.read_text()
prefix=text[text.index('static EmulatorVM *g_shared_vm'):text.index('    if (!g_libraries_initialized)',text.index('static bool setup_vm_and_adi'))]
isolated=text[text.index('struct IsolatedOTPVM {'):text.index('\n#endif',text.index('struct IsolatedOTPVM {'))]
stubs='''#include <mutex>
struct NativeOTPTrace {};
enum class NativeOTPStage {SetupBegin,SetupFailed,VMInitFailed,VMInitOK,VMReused,NativeOTPFailed,NativeStartFailed};
struct NativeOTPStageScope {NativeOTPStageScope(NativeOTPTrace*,NativeOTPStage){} void finish(NativeOTPStage){}};
'''.replace('struct NativeOTPTrace {};','struct NativeOTPTrace {template<class T>void add(T){}};')
otp_start=text.index('    uint64_t mid_ptr = vm->allocate_guest(8);')
provision_start=text.index('    uint64_t spim_vm = vm->write_bytes(spim, spim_len);')
otp_block=text[otp_start:text.index('    uint64_t dsid',otp_start)]
provision_block=text[provision_start:text.index('    uint64_t dsid',provision_start)]
output_blocks=''
output_blocks+='static int prepare_otp_outputs(EmulatorVM *vm, NativeOTPTrace &trace, char **out_json) {\n'+otp_block+'return 0;\n}\n'
output_blocks+='static int prepare_provision_outputs(EmulatorVM *vm, NativeOTPTrace &trace, char **out_json, const uint8_t *spim, uint32_t spim_len) {\n'+provision_block+'return 0;\n}\n'
(root/'core_setup_slice.inc').write_text(stubs+prefix+'    return true;\n}\n'+isolated+'\n'+output_blocks)
rows=[]
for variant,flags in [('normal',[]),('optimized',['-O2','-DNDEBUG']),('sanitized',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])]:
 binary=root/('setup-'+variant)
 cmd=['c++','-std=c++17',*flags,'-I',str(a.unicorn_include.resolve()),'-I',str(repo/'Native'),'-I',str(repo/'Native/include'),'-DLOADER_SOURCE="'+str(source)+'"','-DCORE_SETUP_SLICE="'+str(root/'core_setup_slice.inc')+'"',str(repo/'.ci/native-tests/fixtures/vm_setup_host.cpp'),'-o',str(binary)]
 for stage,command in [('compile',cmd),('run',[str(binary)])]:
  r=subprocess.run(command,capture_output=True,text=True,timeout=120,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
  rows.append(dict(variant=variant,stage=stage,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
  (root/'setup-check-results.json').write_text(json.dumps(dict(source_sha256=before,guest_execution=False,leak_sanitizer_enabled=False,results=rows),indent=2)+'\n')
  print(variant,stage,r.returncode,r.stdout,r.stderr,flush=True)
  if r.returncode:raise SystemExit(1)

if before != hashes(): raise RuntimeError("Sources changed during validation")
