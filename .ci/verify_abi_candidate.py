#!/usr/bin/env python3
"""Verify a development-only source overlay without changing release acceptance.

Only the explicitly committed loader file may differ from the frozen baseline.
This receipt is not a replacement for the integration repository's release gates.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

BASE = 'f494494ede88890555df345054f7fbb87b53aea5'
CHANGED = 'Native/Loader/elf_loader_emulator.cpp'
EXPECTED = '6f8f156afe9ca4a49272f0f9b5d242a7cbdc56ad'


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', '-C', str(root), *args])


def blob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def tracked(root: Path, revision: str) -> dict[str, tuple[str, str]]:
    result = {}
    for entry in git(root, 'ls-tree', '-rz', revision).split(b'\0'):
        if not entry:
            continue
        metadata, path = entry.split(b'\t', 1)
        mode, kind, sha = metadata.decode().split()
        require(kind == 'blob', 'Unexpected submodule in AnisetteKit source inventory')
        result[path.decode()] = (mode, sha)
    return result


def bytes_at(root: Path, name: str, mode: str) -> bytes:
    path = root / name
    if mode == '120000':
        require(path.is_symlink(), 'Missing tracked symlink: ' + name)
        return os.fsencode(os.readlink(path))
    require(path.is_file() and not path.is_symlink(), 'Missing or linked source: ' + name)
    return path.read_bytes()


def install_source(path: Path, content: bytes) -> None:
    # SwiftPM makes noneditable source checkouts read-only. This isolated
    # development lane changes only the hash-verified file, never the whole
    # checkout. Restore its original permissions even when writing fails.
    original_mode = stat.S_IMODE(path.stat().st_mode)
    try:
        if not original_mode & stat.S_IWUSR:
            path.chmod(original_mode | stat.S_IWUSR)
        path.write_bytes(content)
    finally:
        path.chmod(original_mode)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--resolved', type=Path, required=True)
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    candidate, resolved = args.candidate.resolve(), args.resolved.resolve()
    head = git(candidate, 'rev-parse', 'HEAD').decode().strip()
    require(git(resolved, 'rev-parse', 'HEAD').decode().strip() == BASE,
            'SPM did not resolve the frozen AnisetteKit baseline')
    changed = git(candidate, 'diff', '--name-only', BASE, head, '--',
                  'Native', 'Sources', 'Package.swift', 'Package.resolved').decode().splitlines()
    require(changed == [CHANGED], 'Unexpected runtime change in candidate')
    fixed = bytes_at(candidate, CHANGED, '100644')
    require(blob(fixed) == EXPECTED, 'Candidate loader differs from the reviewed commit')
    inventory = tracked(resolved, BASE)
    for name, (mode, sha) in inventory.items():
        data = bytes_at(resolved, name, mode)
        allowed = {sha, EXPECTED} if args.install and name == CHANGED else {EXPECTED if name == CHANGED else sha}
        require(blob(data) in allowed, 'Unexpected resolved source content: ' + name)
    untracked = git(resolved, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')
    require(not any(p.startswith((b'Native/', b'Sources/')) for p in untracked),
            'Untracked compiler inputs in SPM checkout')
    if args.install:
        install_source(resolved / CHANGED, fixed)
    hashes = {}
    for name, (mode, sha) in inventory.items():
        data = bytes_at(resolved, name, mode)
        require(blob(data) == (EXPECTED if name == CHANGED else sha),
                'Compiler input verification failed: ' + name)
        hashes[name] = hashlib.sha256(data).hexdigest()
    record = {
        'schema_version': 1,
        'kind': 'development_abi_candidate_not_release_acceptance',
        'baseline_integration': '767234eb704745ce915c0750eee2c31061ac4f78',
        'baseline_anisette': BASE,
        'candidate_repository': 'NRG-Wardog/AnisetteKit',
        'candidate_commit': head,
        'changed_runtime_files': {CHANGED: EXPECTED},
        'compiler_input_sha256': hashes,
        'full_unit_ui_regression_run': False,
        'device_login_verified': False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print('Exact compiler input verification: PASS; development candidate only')


if __name__ == '__main__':
    main()
