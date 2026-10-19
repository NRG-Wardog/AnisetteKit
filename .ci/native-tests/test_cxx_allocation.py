#!/usr/bin/env python3
"""Host-only production allocator checks; no guest/library execution or account data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--unicorn-include', type=Path, required=True, help='Headers only, no linked engine')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
if sys.platform != "linux":
    p.error("This host-only driver currently requires Linux ELF dead stripping; no tests were run")
a.output.mkdir(parents=True, exist_ok=True)
loader = ROOT / 'Native/Loader/elf_loader_emulator.cpp'
source = ROOT / '.ci/native-tests/fixtures/cxx_allocation_unit.cpp'
hook_source = ROOT / '.ci/native-tests/fixtures/cxx_allocation_hook_unit.cpp'
includes = [ROOT/'Native/Loader', ROOT/'Native', ROOT/'Native/include', a.unicorn_include]
evidence = [loader, source, hook_source, ROOT/"Native/Loader/cxx_allocation_runtime.h", ROOT/"Native/Loader/elf_loader_emulator.h", ROOT/"Native/Loader/elf_metadata_bounds.h", ROOT/"Native/Loader/android_tls_runtime.h", ROOT/"Native/Loader/vm_initialization_diagnostics.h", ROOT/"Native/Loader/adi_consumption_debug.h", ROOT/"Native/anisette_base.h", ROOT/"Native/include/anisette_core.h", Path(__file__).resolve()]
evidence += [ROOT / 'Native/Loader' / name for name in ('bounded_fault_diagnostics.h','bounded_fault_runtime.h','bounded_asset_digest.h')]
before = {str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in evidence}
results = {}
for variant, flags in [('normal', []), ('optimized', ['-O2','-DNDEBUG']), ('sanitized', ['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])]:
    common = ['c++', '-std=c++17', '-ffunction-sections','-fdata-sections', *flags]
    for d in includes: common.extend(['-I',str(d)])
    obj = a.output / (variant+'.o')
    binary = a.output / variant
    commands = [common + ['-c',str(loader),'-o',str(obj)], common + ['-Wl,--gc-sections',str(source),str(obj),'-o',str(binary)], [str(binary.resolve())]]
    outputs = []
    for command in commands:
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        r = subprocess.run(command,capture_output=True,text=True,timeout=120,env=env)
        outputs.append({'command':command,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        (a.output/(variant+'.json')).write_text(json.dumps(outputs,indent=2))
        if r.returncode: raise SystemExit(f'{variant} failed: {r.stderr}')
    result = json.loads(outputs[-1]['stdout'])
    expected = {'checks':32,'failures':0,'guest_execution':False}
    if result != expected or any(type(result[k]) is not type(v) for k,v in expected.items()):
        raise RuntimeError(f'Unexpected result: {result}')
    hook_binary = a.output/(variant+'-hooks')
    hook_outputs=[]
    for command in [common+[str(hook_source),'-o',str(hook_binary)], [str(hook_binary.resolve())]]:
        r=subprocess.run(command,capture_output=True,text=True,timeout=120,env=env)
        hook_outputs.append({'command':command,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        (a.output/(variant+'-hooks.json')).write_text(json.dumps(hook_outputs,indent=2))
        if r.returncode: raise RuntimeError(f'Hook test failed: {r.stderr}')
    hook_result=json.loads(hook_outputs[-1]['stdout'])
    expected_hooks={'checks':51,'failures':0,'guest_execution':False}
    if hook_result != expected_hooks or any(type(hook_result[k]) is not type(v) for k,v in expected_hooks.items()):
        raise RuntimeError(f'Unexpected hook result: {hook_result}')
    results[variant]={'allocator':result,'hooks':hook_result}
after = {str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in evidence}
if before != after:
    raise RuntimeError('Sources changed during validation')
(a.output/'result.json').write_text(json.dumps({'results':results,'guest_execution':False,'leak_sanitizer_enabled':False,'source_sha256':before},indent=2))
print(json.dumps(results))
