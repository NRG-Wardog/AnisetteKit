#!/usr/bin/env python3
"""Focused real-engine synthetic test; no Apple ADI execution or downloads.

Example (explicit trusted installed Unicorn package root):
  python3 .ci/native-tests/test_android_tls_runtime.py \
    --unicorn-root /trusted/venv/lib/python3.12/site-packages/unicorn \
    --sanitizers --output /tmp/tls-result.json
The matching iOS fork must still be validated in its platform build.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, subprocess, tempfile

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--unicorn-root',type=pathlib.Path,required=True,help='Already installed trusted engine containing include/ and lib/')
 p.add_argument('--source-root',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[2])
 p.add_argument('--output',type=pathlib.Path)
 p.add_argument('--sanitizers',action='store_true')
 p.add_argument('--disable-leak-sanitizer',action='store_true',help='Explicitly disclose unavailable LSan, for ptrace executors only')
 a=p.parse_args();root=a.source_root.resolve();uc=a.unicorn_root.resolve()
 library=next((uc/'lib'/n for n in ('libunicorn.so.2','libunicorn.dylib') if (uc/'lib'/n).is_file()),None)
 if library is None or not (uc/'include/unicorn/unicorn.h').is_file():p.error('Trusted Unicorn headers/shared library unavailable')
 if a.disable_leak_sanitizer and not a.sanitizers:p.error('Leak detector override requires --sanitizers')
 sources=[root/'Native/Loader/elf_loader_emulator.cpp',root/'.ci/native-tests/fixtures/android_tls_constructor.cpp']
 evidence=sources+[root/'Native/Loader/elf_loader_emulator.h',root/'Native/Loader/android_tls_runtime.h']
 if not all(x.is_file() for x in evidence):p.error('Candidate sources/fixture missing')
 compiler=os.environ.get('CXX','c++');environment=os.environ.copy()
 if a.disable_leak_sanitizer:environment['ASAN_OPTIONS']='detect_leaks=0'
 with tempfile.TemporaryDirectory(prefix='android-tls-focused-') as t:
  exe=pathlib.Path(t)/'synthetic-tls'
  cmd=[compiler,'-std=c++17','-O1','-g','-fno-omit-frame-pointer']
  if a.sanitizers:cmd+=['-fsanitize=address,undefined']
  for include in [uc/'include',root/'Native',root/'Native/include',root/'Native/Loader']:cmd+=['-I'+str(include)]
  cmd += [str(x) for x in sources]+[str(library),'-Wl,-rpath,'+str(library.parent),'-o',str(exe)]
  subprocess.run(cmd,check=True,env=environment,timeout=120)
  result=subprocess.run([str(exe)],check=True,env=environment,text=True,capture_output=True,timeout=60)
  report={'schema':1,'purpose':'own_synthetic_full_production_loader_regression','ADI_executed':False,'iOS_or_device_validated':False,'engine_library_sha256':digest(library),'source_sha256':{str(x.relative_to(root)):digest(x) for x in evidence},'sanitizers':a.sanitizers,'leak_sanitizer_disabled':a.disable_leak_sanitizer,'stdout':result.stdout,'stderr':result.stderr}
  if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+'\n')
  print(result.stdout,end='')
if __name__=='__main__':main()
