#!/usr/bin/env python3
"""Offline fixtures against exact already-pinned Unicorn archive; never downloads."""
import argparse, hashlib, pathlib, platform, subprocess, tempfile, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
SHA = '52e4ac9e2d704c4941adc2c381df8706aabf673dc843611a90b33ad349d562db'
p=argparse.ArgumentParser(); p.add_argument('--unicorn-archive',type=pathlib.Path,required=True); args=p.parse_args()
assert hashlib.sha256(args.unicorn_archive.read_bytes()).hexdigest()==SHA, 'Unicorn pin mismatch'
def run(*cmd):
    print('+', ' '.join(map(str,cmd)),flush=True); subprocess.run(list(map(str,cmd)),check=True,cwd=ROOT,timeout=120 if str(cmd[0]) == "c++" else 30)
with tempfile.TemporaryDirectory(prefix='owned-oda-tests-') as temp:
    work=pathlib.Path(temp); headers=work/'headers'; headers.mkdir()
    prefix='Unicorn.xcframework/macos-arm64_x86_64/'
    with zipfile.ZipFile(args.unicorn_archive) as archive:
        for name in archive.namelist():
            if name.startswith(prefix+'Headers/') and name.endswith('.h'):
                rel=pathlib.PurePosixPath(name[len(prefix+'Headers/'):]); assert '..' not in rel.parts
                out=headers/rel; out.parent.mkdir(parents=True,exist_ok=True); out.write_bytes(archive.read(name))
        if platform.system()=='Darwin': (work/'libunicorn.a').write_bytes(archive.read(prefix+'libunicorn.a'))
    common=['c++','-std=c++17','-pthread','-I',ROOT/'Native','-I',ROOT/'Native/include','-I',ROOT/'Native/Loader','-I',headers]
    for name in ['control','filesystem']:
        run(*common,'-Wall','-Wextra','-Werror',ROOT/f'.ci/owned-attempt/{name}_test.cpp','-o',work/name); run(work/name)
    sources=[ROOT/'Native/anisette_core_uc.cpp', ROOT/'Native/Loader/elf_loader_emulator.cpp',ROOT/'Native/anisette_base.cpp']
    run(*common,'-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-fsyntax-only',*sources)
    run(*common,ROOT/'.ci/owned-attempt/native_api_test.cpp',*sources,'-o',work/'native'); run(work/'native')
    print('PASS: control, filesystem, pinned-header syntax, actual C ABI with mock engine',flush=True)
    if platform.system()=='Darwin':
        run(*common,ROOT/'.ci/owned-attempt/unicorn_procedure_test.cpp',sources[1],sources[2],work/'libunicorn.a','-o',work/'unicorn'); run(work/'unicorn')
        print('PASS: pinned real Unicorn synthetic ARM64 procedures',flush=True)
    else: print('NOT RUN: real Unicorn macOS binary and Swift tests (requires macOS)',flush=True)
