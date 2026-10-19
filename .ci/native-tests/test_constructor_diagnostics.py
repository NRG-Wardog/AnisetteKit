#!/usr/bin/env python3
"""Compile the full production loader with own synthetic constructor diagnostics.

Uses an explicitly selected trusted installed Unicorn package (include/ and
lib/). Native iOS-fork CI may compile fixtures/constructor_diagnostics.cpp
directly against its pinned framework; the fixture emits one JSON result line.
No ADI download, Apple execution, provisioning, or device validation occurs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

EXPECTED_CHECKS = 2105
EXPECTED_CASE_IDS = (
    'normal_nonzero_w0', 'normal_error_shaped_w0', 'protected_access',
    'unsupported_interrupt', 'abnormal_stop', 'dt_init_failure',
    'dt_init_array_first_failure', 'dt_init_array_second_failure',
    'array_entry_read_first', 'array_entry_read_second', 'invalid_vm',
    'poisoned_vm', 'caller_snapshot_independence', 'serialization_bounds',
    'serialization_privacy',
)


def parse_fixture_result(stdout, stderr, returncode):
    """Fail closed on execution, sanitizer output, or drift in the sealed fixture."""
    if returncode != 0:
        raise RuntimeError(f'Synthetic diagnostics exited with status {returncode}')
    if stderr:
        raise RuntimeError('Synthetic diagnostics emitted unexpected stderr (including sanitizer findings)')
    if (not isinstance(stdout, str) or len(stdout) > 2048 or not stdout.startswith('{') or
            not stdout.endswith('}\n') or stdout.count('\n') != 1 or not stdout.isascii()):
        raise RuntimeError('Expected one bounded ASCII fixture JSON line')

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError('Non-finite JSON value')

    try:
        report = json.loads(stdout, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, TypeError) as error:
        raise RuntimeError('Invalid fixture JSON') from error
    expected = {'schema': 1, 'checks': EXPECTED_CHECKS, 'failures': 0, 'skipped': 0,
                'case_ids': list(EXPECTED_CASE_IDS), 'ADI_executed': False, 'device_validation': False}
    if type(report) is not dict or report.keys() != expected.keys():
        raise RuntimeError('Unexpected fixture schema keys')
    for key, value in expected.items():
        if type(report[key]) is not type(value) or report[key] != value:
            raise RuntimeError(f'Unexpected fixture field: {key}')
    return report


def sanitizer_environment(environment, disable_leak_sanitizer):
    """Override inherited recovery/suppression options for the checked run."""
    result = environment.copy()
    result['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:detect_leaks=' + ('0' if disable_leak_sanitizer else '1')
    result['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    result['LSAN_OPTIONS'] = 'exitcode=23'
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unicorn-root', type=pathlib.Path, required=True)
    parser.add_argument('--source-root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=pathlib.Path)
    parser.add_argument('--sanitizers', action='store_true')
    parser.add_argument('--disable-leak-sanitizer', action='store_true', help='Disclose unavailable LSan on ptrace executors')
    args = parser.parse_args()
    root, unicorn = args.source_root.resolve(), args.unicorn_root.resolve()
    library = next((unicorn / 'lib' / name for name in ('libunicorn.so.2', 'libunicorn.dylib')
                    if (unicorn / 'lib' / name).is_file()), None)
    if library is None or not (unicorn / 'include/unicorn/unicorn.h').is_file():
        parser.error('Trusted Unicorn headers/shared library unavailable')
    if args.disable_leak_sanitizer and not args.sanitizers:
        parser.error('Leak detector override requires --sanitizers')
    sources = [root / 'Native/Loader/elf_loader_emulator.cpp',
               root / '.ci/native-tests/fixtures/constructor_diagnostics.cpp']
    evidence = sources + [root / '.ci/native-tests/test_constructor_diagnostics.py'] + [root / 'Native/Loader' / name for name in
                          ('bounded_fault_diagnostics.h', 'bounded_fault_runtime.h', 'bounded_asset_digest.h', 'cxx_allocation_runtime.h', 'elf_loader_emulator.h', 'elf_metadata_bounds.h', 'android_tls_runtime.h', 'vm_initialization_diagnostics.h')]
    if not all(path.is_file() for path in evidence):
        parser.error('Production sources or fixture missing')
    environment = os.environ.copy()
    if args.sanitizers:
        environment = sanitizer_environment(environment, args.disable_leak_sanitizer)
    with tempfile.TemporaryDirectory(prefix='constructor-diagnostics-') as directory:
        executable = pathlib.Path(directory) / 'synthetic-constructors'
        command = [os.environ.get('CXX', 'c++'), '-std=c++17', '-O1', '-g', '-fno-omit-frame-pointer']
        if args.sanitizers:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
        command += ['-I' + str(path) for path in (unicorn / 'include', root / 'Native',
                                                 root / 'Native/include', root / 'Native/Loader')]
        command += [str(path) for path in sources] + [str(library), '-Wl,-rpath,' + str(library.parent), '-o', str(executable)]
        subprocess.run(command, check=True, env=environment, timeout=120)
        result = subprocess.run([str(executable)], env=environment, text=True, capture_output=True, timeout=60)
        report = parse_fixture_result(result.stdout, result.stderr, result.returncode)
        report.update(purpose='own_synthetic_constructor_diagnostics', iOS_or_device_validated=False,
                      engine_library_sha256=digest(library),
                      source_sha256={str(path.relative_to(root)): digest(path) for path in evidence},
                      sanitizers=args.sanitizers, leak_sanitizer_disabled=args.disable_leak_sanitizer,
                      stderr=result.stderr)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
