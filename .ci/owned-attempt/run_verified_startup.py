#!/usr/bin/env python3
"""macOS-only local trusted-library startup. No networking or accounts in fixture."""
import argparse, hashlib, json, pathlib, platform, subprocess, sys, tempfile, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[2]
PIN='52e4ac9e2d704c4941adc2c381df8706aabf673dc843611a90b33ad349d562db'
p=argparse.ArgumentParser();p.add_argument('--archive',type=pathlib.Path,required=True);p.add_argument('--unicorn-archive',type=pathlib.Path,required=True);p.add_argument('--receipt',type=pathlib.Path,required=True);a=p.parse_args()
a.receipt=a.receipt.resolve();a.receipt.parent.mkdir(parents=True,exist_ok=True)
if platform.system()!='Darwin':raise RuntimeError('Real pinned macOS Unicorn required')
if hashlib.sha256(a.unicorn_archive.read_bytes()).hexdigest()!=PIN:raise RuntimeError('Unicorn pin mismatch')
receipt={'scope':'Local startup and invalid synthetic blob only, no Apple authentication proof','unicorn_sha256':PIN,'commands':[]}
def run(command,timeout):
 r=subprocess.run(list(map(str,command)),cwd=ROOT,capture_output=True,text=True,timeout=timeout)
 receipt['commands'].append({'command':list(map(str,command)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
 print(r.stdout,end='');print(r.stderr,end='',file=sys.stderr)
 a.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
 if r.returncode:raise RuntimeError('Trusted startup qualification failed')
 return r
try:
 with tempfile.TemporaryDirectory(prefix='verified-oda-startup-') as directory:
  work=pathlib.Path(directory);headers=work/'headers';headers.mkdir()
  prefix='Unicorn.xcframework/macos-arm64_x86_64/'
  with zipfile.ZipFile(a.unicorn_archive) as z:
   for name in z.namelist():
    if name.startswith(prefix+'Headers/') and name.endswith('.h'):
     relative=pathlib.PurePosixPath(name[len(prefix+'Headers/'):])
     if '..' in relative.parts:raise RuntimeError('Invalid pinned header path')
     out=headers/relative;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(z.read(name))
   (work/'libunicorn.a').write_bytes(z.read(prefix+'libunicorn.a'))
  verified=run([sys.executable,ROOT/'.ci/owned-attempt/prepare_verified_libraries.py','--archive',a.archive.resolve(),'--output',work/'libraries'],30)
  receipt['verified_inputs']=json.loads(verified.stdout)
  run(['c++','-std=c++17','-pthread','-I',ROOT/'Native','-I',ROOT/'Native/include','-I',headers,
       ROOT/'.ci/owned-attempt/verified_adi_startup.cpp',ROOT/'Native/Loader/elf_loader_emulator.cpp',ROOT/'Native/anisette_base.cpp',
       work/'libunicorn.a','-o',work/'startup'],120)
  run([work/'startup',work/'libraries'],90)
  receipt['passed']=True
except BaseException as error:
 receipt['passed']=False;receipt['failure_type']=type(error).__name__;raise
finally:
 a.receipt.parent.mkdir(parents=True,exist_ok=True)
 a.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
