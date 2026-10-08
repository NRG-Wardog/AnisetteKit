#!/usr/bin/env python3
"""Compile maintained production boundaries with synthetic VM and I/O doubles.

No source patcher, builder checkout, Apple libraries, provisioning state or
network access is used. These tests establish staging/error/containment parity;
they do not establish real Apple ADI compatibility or fix the cleanup race.
Ported from sidestore-auto-refresh@141776ba; see NOTICE-NRG-Wardog.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def source(path):
    return (ROOT / path).read_text()


def native_trace_tokens():
    text = source('Native/anisette_core_uc.cpp')
    block = text.split('static const char *const tokens[] = {', 1)[1].split('};', 1)[0]
    return re.findall(r'"([a-z_]+(?:\.[a-z_]+)+)"', block)


def declaration(text, signature):
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 0
    for end in range(opening, len(text)):
        if text[end] == '{': depth += 1
        elif text[end] == '}':
            depth -= 1
            if depth == 0: return text[start:end + 1]
    raise AssertionError(signature)


class MaintainedAnisetteNativeTests(unittest.TestCase):
    success_trace = ('arguments.ok,root.ok,uuid_dir.created,file.open.ok,file.stream.ok,'
        'file.write.ok,file.flush.ok,file.close.ok,file.read_open.ok,file.readback.ok,'
        'file.read_close.ok,file.rename.ok,vm.init.ok,setup.begin,library.load.ok,'
        'library.init.ok,uuid_dir.exists,provisioning_path.ok,android_id.ok,setup.ok,'
        'native.symbol.ok,native.otp.ok,native.output.ok,cleanup.ok').split(',')

    @classmethod
    def expected_fault_trace(cls, fault):
        before = lambda stage: cls.success_trace[:cls.success_trace.index(stage)]
        tail = ['cleanup.ok']
        if fault in ('ok', 'concurrent', 'mixed'): return cls.success_trace
        if fault == 'empty': return ['arguments.failed']
        if fault == 'rootpermissions': return ['arguments.ok', 'root.failed', 'cleanup.not_needed']
        if fault in ('mkdir', 'existing'):
            return ['arguments.ok', 'root.ok', 'uuid_dir.failed' if fault == 'mkdir' else 'uuid_dir.exists', 'cleanup.not_needed']
        failed_stages = {'open': 'file.open', 'fdopen': 'file.stream', 'write': 'file.write',
            'flush': 'file.flush', 'close': 'file.close', 'readopen': 'file.read_open',
            'read': 'file.readback', 'mismatch': 'file.readback', 'extra': 'file.readback',
            'readerror': 'file.readback', 'readclose': 'file.read_close', 'rename': 'file.rename',
            'construct': 'vm.init', 'load': 'library.load', 'setup': 'provisioning_path',
            'symbol': 'native.symbol', 'otp': 'native.otp', 'throw': 'native.otp',
            'length': 'native.output', 'outputread': 'native.output'}
        if fault == 'cleanup': return cls.success_trace[:-1] + ['cleanup.failed', 'cleanup.ok']
        if fault == 'alloc': return cls.success_trace + ['response.allocation.failed']
        stage = failed_stages[fault]
        after = []
        if fault in ('write',): after += ['file.flush.ok']
        if fault in ('write', 'flush', 'fdopen'): after += ['file.close.ok']
        if stage == 'file.readback': after += ['file.read_close.ok']
        if fault in ('load', 'setup'): after += ['setup.failed']
        return before(stage + '.ok') + [stage + '.failed'] + after + tail

    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('c++') or shutil.which('g++')
        if not compiler:
            raise unittest.SkipTest('C++ compiler required for synthetic native tests')
        cls.temporary = tempfile.TemporaryDirectory(prefix='isolated-adi-build-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        (cls.build / 'Loader').mkdir()
        shutil.copyfile(ROOT / 'Native/Loader/adi_consumption_debug.h', cls.build / 'Loader/adi_consumption_debug.h')
        (cls.build / 'Loader/elf_loader_emulator.h').write_text(
            (HERE / 'fixtures/isolated_anisette_vm_double.h').read_text())
        for name in ('Native/anisette_base.h', 'Native/anisette_base.cpp',
                     'Native/include/anisette_core.h', 'Native/anisette_core_uc.cpp'):
            text = source(name)
            (cls.build / Path(name).name).write_text(text)
        (cls.build / 'main.cpp').write_text((HERE / 'fixtures/isolated_anisette_core_harness.cpp').read_text())
        cls.executable = cls.build / 'native-test'
        result = subprocess.run([compiler, '-std=c++17', '-pthread', '-I', str(cls.build),
            str(cls.build / 'main.cpp'), str(cls.build / 'anisette_base.cpp'), '-o', str(cls.executable)],
            capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)
        if b'V3_CHECKED_ANISETTE_STAGING_V1' not in cls.executable.read_bytes():
            raise AssertionError('Compiled checked normal staging marker absent')

    def test_actual_native_boundary_success_faults_and_concurrent_calls(self):
        for fault in ('ok', 'concurrent', 'mixed', 'mkdir', 'open', 'fdopen', 'write', 'flush', 'close',
                      'readopen', 'read', 'mismatch', 'rename', 'construct', 'load', 'setup',
                      'symbol', 'otp', 'throw', 'length', 'outputread', 'cleanup', 'existing',
                      'rootpermissions', 'empty', 'readclose', 'extra', 'readerror', 'alloc'):
            with self.subTest(fault=fault):
                result = subprocess.run([str(self.executable), fault], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('ISOLATED_NATIVE_OTP_PASS', result.stdout)
                self.assertIn('NORMAL_LOG_RETAINED', result.stdout)
                traces = [line.removeprefix('NATIVE_TRACE=').split(',') for line in result.stdout.splitlines()
                          if line.startswith('NATIVE_TRACE=')]
                expected = [self.expected_fault_trace(fault)]
                if fault == 'concurrent': expected *= 2
                if fault == 'mixed': expected += [['arguments.failed']]
                self.assertCountEqual(traces, expected)
                for trace in traces:
                    self.assertLessEqual(len(trace), 32)
                    self.assertLessEqual(len(','.join(trace).encode('ascii')), 1024)
                    self.assertTrue(set(trace) <= set(native_trace_tokens()))
                for private in ('SYNTHETIC-EXISTING-BLOB', 'isolated-adi-test-',
                                '00010203-0405-0607-0809-0a0b0c0d0e0f', '0001020304050607'):
                    self.assertNotIn(private, result.stdout + result.stderr)

    def test_normal_checked_staging_blocks_otp_and_preserves_previous_blob_on_every_io_failure(self):
        success = ('arguments.ok,uuid_dir.exists,root.ok,uuid_dir.exists,file.open.ok,file.stream.ok,file.write.ok,'
            'file.flush.ok,file.close.ok,file.read_open.ok,file.readback.ok,file.read_close.ok,file.rename.ok,'
            'setup.begin,vm.reused,library.cached,provisioning_path.ok,android_id.ok,setup.ok,native.symbol.ok,'
            'native.otp.ok,native.output.not_checked,cleanup.not_requested').split(',')
        cases = {'ok': success,
            'otp': success[:success.index('native.otp.ok')] + ['native.otp.failed', 'cleanup.not_requested'],
            'symbol': success[:success.index('native.symbol.ok')] + ['native.symbol.failed', 'cleanup.not_requested']}
        for fault in ('mkdir', 'rootopen', 'rootlink', 'rootpermissions'):
            cases[fault] = ['arguments.ok', 'uuid_dir.failed', 'cleanup.not_requested']
        for fault in ('uuidopen', 'uuidlink', 'uuidfile', 'uuidpermissions'):
            cases[fault] = success[:3] + ['uuid_dir.failed', 'cleanup.not_requested']
        stages = {'open':'file.open', 'filelink':'file.open', 'hardlink':'file.open',
            'fifo':'file.open', 'temp_full':'file.open',
            'fdopen':'file.stream', 'write':'file.write', 'flush':'file.flush', 'close':'file.close',
            'readopen':'file.read_open', 'readfdopen':'file.readback', 'read':'file.readback',
            'mismatch':'file.readback', 'extra':'file.readback', 'readerror':'file.readback',
            'readclose':'file.read_close', 'rename':'file.rename', 'rootreplace':'file.rename'}
        for fault, stage in stages.items():
            after = []
            if fault == 'write': after += ['file.flush.ok']
            if fault in ('fdopen', 'write', 'flush'): after += ['file.close.ok']
            if stage == 'file.readback': after += ['file.read_close.ok']
            cases[fault] = success[:success.index(stage + '.ok')] + [stage + '.failed'] + after + ['cleanup.not_requested']
        cases['cold'] = success[:14] + ['vm.init.ok', 'library.load.ok', 'library.init.ok'] + success[16:]
        cases['fresh'] = [event if index != 1 else 'uuid_dir.created' for index, event in enumerate(success)]
        cases['zero'] = success
        cases['large'] = success
        for fault in ('temp_exists', 'temp_link', 'crash_leftover'):
            cases[fault] = success
        for fault, expected in cases.items():
            with self.subTest(fault=fault):
                result = subprocess.run([str(self.executable), 'normal_' + fault], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('NATIVE_TRACE=' + ','.join(expected), result.stdout)
                self.assertIn('NORMAL_NATIVE_TRACE_PASS', result.stdout)
                self.assertNotIn('file.flush.not_checked', result.stdout)
                self.assertNotIn('file.readback.not_checked', result.stdout)
        # Every staging fault also runs from a cold VM: no native initialization
        # may happen until the checked rename has completed.
        for fault in ('mkdir', 'rootopen', 'rootlink', 'rootpermissions', 'uuidopen', 'uuidlink',
                      'uuidfile', 'uuidpermissions', *stages):
            with self.subTest(cold_fault=fault):
                result = subprocess.run([str(self.executable), 'normal_coldfail_' + fault],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('NATIVE_TRACE=' + ','.join(cases[fault]), result.stdout)
        for fault in ('concurrent', 'retrywrite', 'cold_new', 'same_identity', 'different_identity',
                      'provisioned', 'invalid_libdir_missing', 'invalid_libdir_file', 'load',
                      'setup_init', 'setup_path', 'setup_id', 'new_load', 'new_setup_init',
                      'new_setup_path', 'new_setup_id'):
            result = subprocess.run([str(self.executable), 'normal_' + fault], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('NORMAL_NATIVE_TRACE_PASS', result.stdout)
        result = subprocess.run([str(self.executable), 'normal_invalid'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('NORMAL_INVALID_ARGUMENT_PASS', result.stdout)
        result = subprocess.run([str(self.executable), 'normal_uuidalloc'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('NORMAL_ALLOCATION_FD_PASS', result.stdout)

    def test_native_trace_is_bounded_and_can_be_disabled_without_changing_results(self):
        result = subprocess.run([str(self.executable), 'tracecap'], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('NATIVE_TRACE=' + ','.join(['arguments.ok'] * 31 + ['trace.truncated']), result.stdout)
        core = self.build / 'anisette_core_uc.cpp'
        enabled = core.read_text()
        self.assertEqual(enabled.count('#define V3_TEMPORARY_ANISETTE_TRACE_ENABLED 1'), 1)
        disabled = enabled.replace('#define V3_TEMPORARY_ANISETTE_TRACE_ENABLED 1',
                                   '#define V3_TEMPORARY_ANISETTE_TRACE_ENABLED 0', 1)
        binary = self.build / 'trace-disabled-test'
        try:
            core.write_text(disabled)
            compiled = subprocess.run([shutil.which('c++') or shutil.which('g++'), '-std=c++17', '-pthread',
                '-I', str(self.build), str(self.build / 'main.cpp'), str(self.build / 'anisette_base.cpp'),
                '-o', str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            for fault in ('ok', 'otp', 'write', 'mixed', 'cleanup', 'normal_write', 'tracecap'):
                result = subprocess.run([str(binary), fault], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('NATIVE_TRACE=disabled', result.stdout)
                self.assertNotIn('NATIVE_TRACE=arguments', result.stdout)
        finally:
            core.write_text(enabled)

    def test_actual_loader_lifetime_and_read_only_callbacks(self):
        compiler = shutil.which('c++') or shutil.which('g++')
        loader = source('Native/Loader/elf_loader_emulator.cpp')
        signatures = ['uint64_t PageAllocator::alloc(', 'EmulatorVM::EmulatorVM(',
                      'EmulatorVM::~EmulatorVM()', 'uint64_t EmulatorVM::write_bytes(',
                      'uint64_t EmulatorVM::write_string(', 'static bool deny_read_only_mutation(',
                      'static int linux_to_darwin_open_flags(', 'int32_t run_vm_procedure(',
                      'bool load_library_to_vm(']
        signatures += ['static void hook_' + name + '(' for name in ('open', 'close', 'write', 'ftruncate', 'mkdir', 'chmod', 'umask')]
        functions = '\n\n'.join(declaration(loader, name) for name in signatures)
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            (build / 'Loader').mkdir()
            (build / 'unicorn').mkdir()
            (build / 'Loader/elf_loader_emulator.h').write_text(source('Native/Loader/elf_loader_emulator.h'))
            for path in ('Native/anisette_base.h', 'Native/include/anisette_core.h', 'Native/anisette_base.cpp'):
                (build / Path(path).name).write_text(source(path))
            constants = sorted(set(re.findall(r'\bUC_[A-Z0-9_]+\b', functions)))
            # SIMD register constants must form the real contiguous range.
            constants = [x for x in constants if not x.startswith('UC_ARM64_REG_V')]
            constants += ['UC_ARM64_REG_V' + str(n) for n in range(32)]
            constants.remove('UC_ERR_OK')
            header = '#pragma once\n#include <cstdint>\n#include <cstddef>\nstruct uc_engine;\nusing uc_err=int;using uc_hook=uint64_t;\n'
            header += 'enum { UC_ERR_OK=0, ' + ', '.join(constants) + ' };\n'
            header += '''uc_err uc_open(int,int,uc_engine**);uc_err uc_close(uc_engine*);
uc_err uc_mem_map(uc_engine*,uint64_t,size_t,int);
uc_err uc_mem_write(uc_engine*,uint64_t,const void*,size_t);
uc_err uc_mem_read(uc_engine*,uint64_t,void*,size_t);
uc_err uc_reg_write(uc_engine*,int,const void*);uc_err uc_reg_read(uc_engine*,int,void*);
uc_err uc_hook_add(uc_engine*,uc_hook*,int,void*,void*,uint64_t,uint64_t);
uc_err uc_emu_start(uc_engine*,uint64_t,uint64_t,uint64_t,size_t);
const char* uc_strerror(uc_err);
'''
            (build / 'unicorn/unicorn.h').write_text(header)
            shutil.copyfile(ROOT / 'Native/Loader/adi_consumption_debug.h', build / 'adi_consumption_debug.h')
            (build / 'loader_functions.inc').write_text('#include \"adi_consumption_debug.h\"\n' + functions)
            (build / 'main.cpp').write_text((HERE / 'fixtures/isolated_anisette_loader_harness.cpp').read_text())
            binary = build / 'loader-test'
            compiled = subprocess.run([compiler, '-std=c++17', '-I', str(build), str(build / 'main.cpp'),
                str(build / 'anisette_base.cpp'), '-o', str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('ISOLATED_LOADER_CONTAINMENT_PASS', result.stdout)

    def test_actual_consumer_hooks_observe_without_changing_results(self):
        compiler = shutil.which('c++') or shutil.which('g++')
        loader = source('Native/Loader/elf_loader_emulator.cpp')
        signatures = ['static int linux_to_darwin_open_flags(', 'static void hook_open(',
                      'static void hook_read(', 'static void hook_close(', 'static void hook_write(']
        functions = '\n\n'.join(declaration(loader, name) for name in signatures)
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory)
            shutil.copyfile(ROOT / 'Native/Loader/adi_consumption_debug.h', build / 'adi_consumption_debug.h')
            (build / 'consumer_functions.inc').write_text(functions)
            (build / 'main.cpp').write_text((HERE / 'fixtures/adi_consumption_harness.cpp').read_text())
            syscall_receipts = []
            for enabled in (0, 1):
                binary = build / ('consumer-' + str(enabled))
                compiled = subprocess.run([compiler, '-std=c++17', '-DADI_CONSUMER_DEBUG_ENABLED=' + str(enabled),
                    '-I', str(build), str(build / 'main.cpp'), '-o', str(binary)], capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('CONSUMER_OBSERVER_PASS', result.stdout)
                syscall_receipts += [line for line in result.stdout.splitlines() if line.startswith('HOST_IO_COUNTS=')]
            self.assertEqual(len(syscall_receipts), 2)
            self.assertEqual(syscall_receipts[0], syscall_receipts[1], 'Passive observation must not add host I/O')

    def test_actual_swift_consumer_decoder_rejects_private_or_malformed_values(self):
        compiler = shutil.which('swiftc')
        if not compiler:
            self.skipTest('Swift compiler required for actual finite consumer decoder')
        swift = declaration(source('Sources/AnisetteDataProvider.swift'), 'private enum TemporaryADIConsumptionTrace {')
        harness = r'''
let valid = "v1|0|5,0,1,1,0,0,0,-1|5,1,1,1,0,4,4,0"
precondition(TemporaryADIConsumptionTrace.suffix(valid) == " [DEBUG_TEMPORARY_ADI_CONSUMPTION:\(valid)]")
for value in ["SECRET-TOKEN", "v1|0|5,0,1,1,0,0,0,SECRET", "v1|0|05,0,1,1,0,0,0,-1",
    "v1|0|6,0,1,1,0,0,0,-1", "v1|0|5,2,1,1,0,0,0,-1", "v1|0|5,0,1,1,4096,0,0,-1",
    "v1|0|5,0,1,1,0,1048578,0,-1", "v1|0|5,0,1,1,0,0,0,33", "v1|2", "v1|0|",
    valid + "\n", "v1|0" + String(repeating: "|5,0,1,1,0,0,0,-1", count: 33), String(repeating: "1", count: 2049)] {
    precondition(TemporaryADIConsumptionTrace.suffix(value).isEmpty)
}
precondition(TemporaryADIConsumptionTrace.suffix(nil).isEmpty)
precondition(!TemporaryADIConsumptionTrace.suffix("v1|1").isEmpty)
for value in ["v2|0|0|0", "v2|0|1|0", "v2|0|1|1", "v2|1|2|0",
              "v2|0|1|1|5,1,1,1,0,4,4,0", "v2|1|1|0" + String(repeating: "|5,0,1,1,0,0,0,-1", count: 32)] {
    precondition(TemporaryADIConsumptionTrace.suffix(value) == " [DEBUG_TEMPORARY_ADI_CONSUMPTION:\(value)]")
}
for value in ["v2|0", "v2|0|1", "v2|0|01|0", "v2|0|1|01", "v2|0|3|0", "v2|0|0|1",
              "v2|0|2|1", "v2|0|-1|0", "v2|0|1|2", "v2|0|1|0|", "v2|0|SECRET|0",
              "v2|0|1|0\n", "v2|0|1|0|5,1,1,1,0,+4,4,0", "v2|0|1|0|5,1,1,1,0,4,4,-0",
              "v2|0|1|0" + String(repeating: "|5,0,1,1,0,0,0,-1", count: 33),
              "v2|0|1|0|5,1,1,1,0,99999999999999999999999999999,4,0"] {
    precondition(TemporaryADIConsumptionTrace.suffix(value).isEmpty)
}
print("CONSUMER_DECODER_PASS")
'''
        with tempfile.TemporaryDirectory() as directory:
            main = Path(directory) / 'main.swift'; binary = Path(directory) / 'decoder'
            main.write_text(swift + harness)
            compiled = subprocess.run([compiler, str(main), '-o', str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('CONSUMER_DECODER_PASS', result.stdout)

    def test_swift_and_native_metadata_allowlists_are_identical(self):
        swift = source('Sources/AnisetteDataProvider.swift')
        trace = declaration(swift, 'private enum TemporaryAnisetteNativeTrace {')
        allowed = trace.split('static let allowed: Set<String> = [', 1)[1].split(']', 1)[0]
        swift_tokens = re.findall(r'"([a-z_.]+)"', allowed)
        self.assertEqual(set(swift_tokens), set(native_trace_tokens()))
        self.assertEqual(len(swift_tokens), len(set(swift_tokens)))
        parser = declaration(swift, '    func parseHeadersResponse(')
        self.assertLess(parser.index('dict.removeValue(forKey: "v3_native_trace")'),
                        parser.index('AnisetteDataResponse(from: dict)'))
        for method in ('    func startProvision(', '    func endProvision('):
            isolated = declaration(swift, 'private struct IsolatedExistingBlobProvider:')
            self.assertIn('throw AnisetteError.invalidArgument', declaration(isolated, method))
        self.assertIn('static let enabled = true', trace)
        self.assertIn('value.utf8.count <= 1024', trace)
        self.assertIn('tokens.count <= 32', trace)


if __name__ == '__main__':
    unittest.main(verbosity=2)
