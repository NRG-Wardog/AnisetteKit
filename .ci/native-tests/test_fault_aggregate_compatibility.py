#!/usr/bin/env python3
"""Compile genuine diagnostic headers with legacy and explicit aggregates only."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class FaultAggregateCompatibilityTests(unittest.TestCase):
    def test_warning_clean_legacy_and_explicit_aggregates(self):
        compiler = shutil.which('c++')
        self.assertIsNotNone(compiler, 'trusted installed C++ compiler required')
        for name, flags in (('normal', []), ('optimized', ['-O2', '-DNDEBUG'])):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary).resolve() / 'aggregate-contract'
                command = [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-pedantic',
                           *flags, '-I', str(ROOT / 'Native/Loader'),
                           str(ROOT / '.ci/native-tests/fixtures/fault_aggregate_compatibility.cpp'),
                           '-o', str(output)]
                compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                self.assertEqual(compiled.stderr, '')
                observed = subprocess.run([str(output)], capture_output=True, text=True, timeout=10)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(observed.stderr, '')
                self.assertEqual(json.loads(observed.stdout),
                                 {'checks': 18, 'guest_execution': False, 'engine_linked': False})


if __name__ == '__main__':
    unittest.main(verbosity=2)
