#!/usr/bin/env python3
"""Portable rejection tests for the native diagnostic fixture's strict driver.

Separate from run_tests.py so its existing eight-case aggregate stays stable.
Does not execute the emulator, fetch dependencies, or run Apple code.
"""
import copy
import json
import sys
import unittest

sys.dont_write_bytecode = True
from test_constructor_diagnostics import (
    EXPECTED_CASE_IDS, EXPECTED_CHECKS, parse_fixture_result, sanitizer_environment,
)


class ConstructorDiagnosticDriverTests(unittest.TestCase):
    def setUp(self):
        self.valid = {'schema': 1, 'checks': EXPECTED_CHECKS, 'failures': 0, 'skipped': 0,
                      'case_ids': list(EXPECTED_CASE_IDS), 'ADI_executed': False, 'device_validation': False}

    @staticmethod
    def line(value):
        return json.dumps(value, separators=(',', ':')) + '\n'

    def rejected(self, value):
        with self.assertRaises(RuntimeError):
            parse_fixture_result(self.line(value), '', 0)

    def test_exact_sealed_result_is_accepted(self):
        self.assertEqual(parse_fixture_result(self.line(self.valid), '', 0), self.valid)

    def test_execution_and_recovered_sanitizer_findings_are_rejected(self):
        for returncode in (-11, -6, 1, 2):
            with self.subTest(returncode=returncode), self.assertRaises(RuntimeError):
                parse_fixture_result(self.line(self.valid), '', returncode)
        for stderr in ('runtime error: signed integer overflow\n', 'ERROR: AddressSanitizer\n',
                       'LeakSanitizer has encountered a fatal error\n', 'warning\n', '\n'):
            with self.subTest(stderr=stderr), self.assertRaises(RuntimeError):
                parse_fixture_result(self.line(self.valid), stderr, 0)

    def test_exact_schema_keys_and_scalar_types_are_required(self):
        for key in self.valid:
            missing = copy.deepcopy(self.valid);del missing[key]
            self.rejected(missing)
        extra = copy.deepcopy(self.valid);extra['unsealed'] = 0
        self.rejected(extra)
        for key in ('schema', 'checks', 'failures', 'skipped'):
            for value in (True, False, str(self.valid[key]), float(self.valid[key]), None, [], {}):
                with self.subTest(key=key, value=value):
                    changed = copy.deepcopy(self.valid);changed[key] = value
                    self.rejected(changed)
        for key in ('ADI_executed', 'device_validation'):
            for value in (True, 0, 1, 'false', None):
                with self.subTest(key=key, value=value):
                    changed = copy.deepcopy(self.valid);changed[key] = value
                    self.rejected(changed)

    def test_exact_counts_and_case_ids_are_required(self):
        for key, values in {'schema': (0, 2), 'checks': (0, 1, 2104, 2106),
                            'failures': (-1, 1), 'skipped': (-1, 1)}.items():
            for value in values:
                changed = copy.deepcopy(self.valid);changed[key] = value
                self.rejected(changed)
        cases = self.valid['case_ids']
        for value in (None, {}, ','.join(cases), [], cases[:-1], cases + ['extra'],
                      cases[::-1], cases[:-1] + [cases[0]], cases[:-1] + [False]):
            changed = copy.deepcopy(self.valid);changed['case_ids'] = value
            self.rejected(changed)

    def test_duplicate_keys_nonfinite_and_malformed_json_are_rejected(self):
        valid = self.line(self.valid)
        invalid = (valid.replace('"schema":1', '"schema":1,"schema":1'),
                   valid.replace('"checks":2105', '"checks":NaN'),
                   valid.replace('"checks":2105', '"checks":Infinity'),
                   '{}\n', '[]\n', 'null\n', 'not json\n', valid[:-1], '\n' + valid,
                   valid + valid, valid + 'trailing', ' ' + valid,
                   '{"unexpected":"é"}\n', '{' + ' ' * 2048 + '}\n')
        for value in invalid:
            with self.subTest(value=value[:60]), self.assertRaises(RuntimeError):
                parse_fixture_result(value, '', 0)

    def test_sanitizer_environment_replaces_inherited_recovery_options(self):
        inherited = {'ASAN_OPTIONS': 'halt_on_error=0:log_path=hidden',
                     'UBSAN_OPTIONS': 'halt_on_error=0:suppressions=hidden',
                     'LSAN_OPTIONS': 'exitcode=0:suppressions=hidden', 'KEEP': 'value'}
        for disabled in (False, True):
            actual = sanitizer_environment(inherited, disabled)
            self.assertEqual(actual['ASAN_OPTIONS'], 'halt_on_error=1:abort_on_error=1:detect_leaks=' + ('0' if disabled else '1'))
            self.assertEqual(actual['UBSAN_OPTIONS'], 'halt_on_error=1:print_stacktrace=1')
            self.assertEqual(actual['LSAN_OPTIONS'], 'exitcode=23')
            self.assertEqual(actual['KEEP'], 'value')
        self.assertIn('halt_on_error=0', inherited['ASAN_OPTIONS'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
