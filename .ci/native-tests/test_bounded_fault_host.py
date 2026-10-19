#!/usr/bin/env python3
"""Synthetic only: complete loader plus API doubles; never link a Unicorn engine.
Apple hash code is additionally exercised via an explicit test-only OpenSSL
adapter. That is not Apple SDK, CommonCrypto linkage or device evidence.
"""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--unicorn-include',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();repo=Path(__file__).resolve().parents[2];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
files=sorted(f for folder in ('Native','Sources','.ci/native-tests') for f in (repo/folder).rglob('*') if f.is_file() and f.suffix in ('.cpp','.h','.swift','.py'))
def hashes():return {str(f.relative_to(repo)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
before=hashes();rows=[]
def save():
 (out/'bounded-fault-results.json').write_text(json.dumps(dict(source_sha256=before,guest_execution=False,real_engine_linked=False,proprietary_input=False,leak_sanitizer_enabled=False,apple_linkage_validated=False,results=rows),indent=2)+'\n')
def run(command,label,env=None):
 r=subprocess.run(command,capture_output=True,text=True,timeout=120,env=env)
 rows.append(dict(label=label,command=command,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr));save()
 if r.returncode or r.stderr:raise RuntimeError(f'{label}: {r.returncode}: {r.stderr}')
 return r
for mode in ('native-unknown','apple-hash-host-adapter'):
 for variant,flags in [('normal',[]),('optimized',['-O2','-DNDEBUG']),('sanitized',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])]:
  label=mode+'-'+variant;binary=out/label
  command=['c++','-std=c++17','-Wno-deprecated-declarations',*flags,'-I',str(a.unicorn_include.resolve()),'-I',str(repo/'Native'),'-I',str(repo/'Native/include')]
  if mode=='apple-hash-host-adapter':command+=['-DBOUNDED_FAULT_HOST_APPLE_DIGEST=1','-I',str(repo/'.ci/native-tests/fixtures/commoncrypto-host-double')]
  command+=[str(repo/'.ci/native-tests/fixtures/bounded_fault_host.cpp'),'-lcrypto','-o',str(binary)]
  run(command,label+'-compile')
  result=json.loads(run([str(binary)],label+'-run',dict(os.environ,ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')).stdout)
  expected=dict(checks=662,failures=0,guest_execution=False,real_engine_starts=0,proprietary_input=False,synthetic_api_starts=5)
  if result!=expected or any(type(result[k]) is not type(v) for k,v in expected.items()):raise RuntimeError('Unexpected host result')
  print(label,result,flush=True)
# Test the exact production Swift parser when a Swift compiler exists. Never
# substitute a Python reimplementation and label it Swift validation.
text=(repo/'Sources/AnisetteDataProvider.swift').read_text()
start=text.index('private enum TemporaryConstructorFaultTrace {');parser=text[start:]
harness=r'''
let valid = "v1;p0_fault_diag1;1;8;1;0;32;1;-;-"
precondition(TemporaryConstructorFaultTrace.suffix(valid) == " [DEBUG_TEMPORARY_CONSTRUCTOR_FAULT:\(valid)]")
let hash = String(repeating: "a", count: 64)
precondition(!TemporaryConstructorFaultTrace.suffix("v1;p0_fault_diag1;3;256;7;65535;805306367;2;\(hash);\(hash)").isEmpty)
for bad in ["SECRET",valid+";extra",valid+"\n",String(repeating:"a",count:256),
    valid.replacingOccurrences(of:"v1;",with:"v2;"), valid.replacingOccurrences(of:"p0_fault_diag1",with:"rehash"),
    "v1;p0_fault_diag1;4;8;1;0;32;1;-;-", "v1;p0_fault_diag1;1;257;1;0;32;1;-;-",
    "v1;p0_fault_diag1;1;8;8;0;32;1;-;-", "v1;p0_fault_diag1;1;8;1;65536;32;1;-;-",
    "v1;p0_fault_diag1;1;8;1;0;805306368;1;-;-", "v1;p0_fault_diag1;1;8;1;0;32;3;-;-",
    "v1;p0_fault_diag1;0;8;1;0;32;1;-;-", "v1;p0_fault_diag1;1;-1;1;0;32;1;-;-",
    "v1;p0_fault_diag1;1;8;1;-1;32;1;-;-", "v1;p0_fault_diag1;1;8;1;0;-1;1;-;-",
    "v1;p0_fault_diag1;01;8;1;0;32;1;-;-", "v1;p0_fault_diag1;1;+8;1;0;32;1;-;-",
    "v1;p0_fault_diag1;1;8;1;0;32;1;SECRET;-", "v1;p0_fault_diag1;1;8;1;0;32;1;\(hash.uppercased());-",
    "v1;p0_fault_diag1;1;8;1;0;32;1;\(hash)a;-", "v1;p0_fault_diag1;1;999999999999999999999;1;0;32;1;-;-"] {
    precondition(TemporaryConstructorFaultTrace.suffix(bad).isEmpty)
}
precondition(TemporaryConstructorFaultTrace.suffix(nil).isEmpty)
print("BOUNDED_FAULT_SWIFT_DECODER_PASS")
'''
# A negative source-flow guard covers all three response boundaries even when
# Swift is unavailable; it is not a substitute for compiling that code.
for method,next_method in [('func parseHeadersResponse','func parseStartProvisionResponse'),('func parseStartProvisionResponse','func parseEndProvisionResponse'),('func parseEndProvisionResponse','private func parseJSONString')]:
 block=text[text.index(method):text.index(next_method)]
 if block.count('removeValue(forKey: "v3_constructor_fault")')!=1 or not (block.index('removeValue(forKey: "v3_constructor_fault")')<block.index('if let err')<block.index('return ')) or 'TemporaryConstructorFaultTrace.suffix(constructorFault)' not in block:
  raise RuntimeError('Private constructor metadata is not stripped before response use')
if shutil.which('swiftc'):
 source=out/'bounded-fault-decoder.swift';source.write_text('import Foundation\n'+parser+harness)
 binary=out/'bounded-fault-decoder';run(['swiftc',str(source),'-o',str(binary)],'swift-compile');run([str(binary)],'swift-run')
else:rows.append(dict(label='swift-decoder',status='not_run',reason='Swift compiler unavailable'));save()
if before!=hashes():raise RuntimeError('Sources changed during validation')
save()
