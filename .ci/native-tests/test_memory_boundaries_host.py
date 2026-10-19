#!/usr/bin/env python3
"""Synthetic host-only memory boundaries; no engine or proprietary inputs."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--unicorn-include',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
repo=Path(__file__).resolve().parents[2]
files=[repo/name for name in ['Native/Loader/elf_loader_emulator.cpp','Native/Loader/elf_loader_emulator.h','Native/Loader/elf_metadata_bounds.h','Native/Loader/android_tls_runtime.h','Native/Loader/cxx_allocation_runtime.h','Native/Loader/adi_consumption_debug.h','Native/anisette_base.h','Native/include/anisette_core.h','.ci/native-tests/fixtures/memory_boundaries_host.cpp','.ci/native-tests/test_memory_boundaries_host.py']]
def hashes():return {str(f.relative_to(repo)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
files += [repo / 'Native/Loader' / name for name in ('bounded_fault_diagnostics.h','bounded_fault_runtime.h','bounded_asset_digest.h','vm_initialization_diagnostics.h')]
before=hashes();rows=[]
for variant,flags in [('normal',[]),('optimized',['-O2','-DNDEBUG']),('sanitized',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])]:
 binary=out/('memory-'+variant)
 cmd=['c++','-std=c++17',*flags,'-I',str(a.unicorn_include.resolve()),'-I',str(repo/'Native'),'-I',str(repo/'Native/include'),str(repo/'.ci/native-tests/fixtures/memory_boundaries_host.cpp'),'-o',str(binary)]
 for stage,command in [('compile',cmd),('run',[str(binary)])]:
  r=subprocess.run(command,capture_output=True,text=True,timeout=120,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
  rows.append(dict(variant=variant,stage=stage,command=command,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
  (out/'memory-check-results.json').write_text(json.dumps(dict(source_sha256=before,guest_execution=False,leak_sanitizer_enabled=False,results=rows),indent=2)+'\n')
  print(variant,stage,r.returncode,r.stdout,r.stderr,flush=True)
  if r.returncode or r.stderr:raise SystemExit(1)
  if stage=='run':
   result=json.loads(r.stdout)
   if result.get('checks',0)<1 or result.get('failures')!=0 or result.get('engine_starts')!=0 or result.get('guest_execution') is not False or result.get('proprietary_input') is not False:raise RuntimeError('Invalid host result')
if before!=hashes():raise RuntimeError('Sources changed during validation')
