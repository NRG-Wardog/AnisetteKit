#!/usr/bin/env python3
"""Source-owned logging policy/fake-output checks; no Unicorn, ELF, APK or auth."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "Native/Loader/native_logging_policy.h"
LOADER = ROOT / "Native/Loader/elf_loader_emulator.cpp"
CORE = ROOT / "Native/anisette_core_uc.cpp"


def calls(text):
    """Extract full LOG_UC statements, respecting strings and parentheses."""
    out = []
    for match in re.finditer(r"\bLOG_UC\(", text):
        start = match.start()
        index = match.end()
        depth, quoted, escaped = 1, False, False
        while depth:
            char = text[index]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            index += 1
        if text[index] != ";":
            raise ValueError("logging statement lacks terminator")
        out.append(text[start:index + 1])
    return out


POLICY_HARNESS = r'''
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <thread>
#include <vector>
static int writes = 0, fail_at = 0;
static int fake_setenv(const char *name, const char *value, int overwrite) {
    ++writes;
    if (writes == fail_at) return -1;
    return ::setenv(name, value, overwrite);
}
#ifdef TEST_WINDOWS_BRANCH
static int _putenv_s(const char *name, const char *value) {
    return fake_setenv(name, value, 1);
}
#define _WIN32 1
#else
#define setenv fake_setenv
#endif
#include "native_logging_policy.h"
#ifndef TEST_WINDOWS_BRANCH
#undef setenv
#endif
static void require(bool condition) { if (!condition) std::exit(91); }
int main(int argc, char **argv) {
    require(argc == 5);
    const char *mode = argv[1];
    const int expected = std::atoi(argv[2]);
    fail_at = std::atoi(argv[3]);
    const bool threads = std::atoi(argv[4]) != 0;
    ::setenv("UNICORN_LOG_LEVEL", "0xFFFFFFFF", 1);
    ::setenv("UNICORN_LOG_DETAIL_LEVEL", "1", 1);
    if (!std::strcmp(mode, "unset")) ::unsetenv("ANISETTEKIT_UNICORN_DIAGNOSTICS");
    else ::setenv("ANISETTEKIT_UNICORN_DIAGNOSTICS", mode, 1);
    std::atomic<int> opened{0};
    auto fake_vm = [&]() {
        auto state = anisette_native_logging::configure_before_first_vm();
        require(static_cast<int>(state) == expected);
        if (state == anisette_native_logging::StartupMode::Failed) return;
        require(!std::strcmp(std::getenv("UNICORN_LOG_LEVEL"), expected ? "0xC10" : "0"));
        require(!std::strcmp(std::getenv("UNICORN_LOG_DETAIL_LEVEL"), "2"));
        ++opened; // Fake only: no engine is linked or called.
    };
    if (threads) {
        std::vector<std::thread> jobs;
        for (int i = 0; i < 8; ++i) jobs.emplace_back(fake_vm);
        for (auto &job : jobs) job.join();
    } else fake_vm();
    const int before = writes;
    ::setenv("ANISETTEKIT_UNICORN_DIAGNOSTICS", expected == 1 ? "off" : "errors", 1);
    fake_vm(); // A later preference change cannot reconfigure this process.
    require(writes == before);
    require(writes == (fail_at ? fail_at : expected == 1 ? 3 : 2));
    require(opened == (expected < 0 ? 0 : threads ? 9 : 2));
    std::printf("mode=%d writes=%d fake_opens=%d\n", expected, writes, opened.load());
}
'''


class NativeLoggingContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which(os.environ.get("CXX", "c++"))
        if not cls.compiler:
            raise RuntimeError("A C++17 compiler is required; do not silently skip fake tests")
        cls.tmp = tempfile.TemporaryDirectory(prefix="anisette-native-log-tests-")
        cls.directory = Path(cls.tmp.name)
        cls.executables = []
        for flags, name in [([], "posix"), (["-DTEST_WINDOWS_BRANCH=1"], "windows-env-fake"),
                            (["-DNDEBUG", "-O2"], "optimized")]:
            cls.executables.append(cls.compile(POLICY_HARNESS, name, flags))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def compile(cls, source, name, flags=()):
        cpp, exe = cls.directory / (name + ".cpp"), cls.directory / name
        cpp.write_text(source)
        subprocess.run([cls.compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
                        *flags, "-I", str(HEADER.parent), str(cpp), "-o", str(exe)], check=True,
                       capture_output=True, text=True, timeout=60)
        return exe

    def run_modes(self, mode, expected, fail_at=0, threads=0):
        for exe in self.executables:
            result = subprocess.run([str(exe), mode, str(expected), str(fail_at), str(threads)],
                                    check=True, capture_output=True, text=True, timeout=10)
            self.assertIn(f"mode={expected}", result.stdout)

    def test_default_off_overrides_unmanaged_all_bits(self):
        self.run_modes("unset", 0)
        self.run_modes("off", 0)

    def test_explicit_allowlist_and_restart_semantics(self):
        self.run_modes("errors", 1)

    def test_unknown_or_numeric_values_do_not_enable_logging(self):
        for value in ("", "ERRORS", "errors,mmu", "1", "0xFFFFFFFF", " errors", "errors "):
            self.run_modes(value, 0)

    def test_once_only_under_concurrent_creation(self):
        self.run_modes("errors", 1, threads=1)
        self.run_modes("off", 0, threads=1)

    def test_each_environment_failure_prevents_fake_open_and_stays_failed(self):
        for failure in (1, 2, 3):
            self.run_modes("errors", -1, fail_at=failure)

    def test_configuration_precedes_actual_uc_open(self):
        source = LOADER.read_text()
        constructor = source[source.index("EmulatorVM::EmulatorVM("):]
        config = constructor.index("configure_before_first_vm()")
        failed = constructor.index("StartupMode::Failed")
        throws = constructor.index('throw std::runtime_error("Native diagnostic startup configuration failed")')
        opened = constructor.index("uc_open(")
        self.assertLess(config, failed)
        self.assertLess(failed, throws)
        self.assertLess(throws, opened)
        self.assertEqual(source.count("uc_open("), 2)  # call and fixed failure message

    def test_guest_strings_are_not_read_and_only_fake_metadata_is_printed(self):
        source = LOADER.read_text()
        start = source.index("static void hook_android_log_print(")
        end = source.index("\n}\n", start) + 2
        function = source[start:end]
        self.assertNotIn("uc_mem_read", function)
        self.assertNotIn("std::string", function)
        harness = r'''
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#define LOG_UC(...) std::printf(__VA_ARGS__)
enum { UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2 };
struct FakeEngine { uint64_t registers[3]; };
struct EmulatorVM { FakeEngine *uc; };
static void uc_reg_read(FakeEngine *uc, int reg, void *out) { std::memcpy(out, &uc->registers[reg], 8); }
static void uc_reg_write(FakeEngine *uc, int reg, const void *in) { std::memcpy(&uc->registers[reg], in, 8); }
''' + function + r'''
int main() {
    const char tag[] = "FAKE_ACCOUNT_TAG_123";
    const char format[] = "FAKE_OTP_PAYLOAD_%s";
    FakeEngine engine{{6, reinterpret_cast<uint64_t>(tag), reinterpret_cast<uint64_t>(format)}};
    EmulatorVM vm{&engine};
    hook_android_log_print(&vm);
    if (engine.registers[0] != 0) return 92;
}
'''
        exe = self.compile(harness, "guest-log-fake")
        out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
        self.assertEqual(out, "[Android Log] priority=6 tag_present=1 format_present=1 text=omitted\n")
        self.assertNotIn("FAKE_", out)

    def test_path_library_and_phase_output_uses_no_fake_secrets(self):
        loader_calls, core_calls = calls(LOADER.read_text()), calls(CORE.read_text())
        selected = [x for x in loader_calls if any(key in x for key in
                    ('[Hook] open(', '[Hook] lstat(', 'Loading ELF library', 'Failed loading'))]
        selected += [x for x in core_calls if 'phase=' in x]
        self.assertEqual(len(selected), 17)
        self.assertNotIn("Native operation progress", CORE.read_text())
        harness = r'''
#include <cstdio>
#include <string>
#include "native_logging_policy.h"
#define LOG_UC(...) std::printf(__VA_ARGS__)
int main() {
    // Inputs are deliberately fake. Actual source log calls are compiled below.
    const std::string path = "/FAKE_PRIVATE/FAKE_UUID/adi.pb";
    const std::string file_path = path;
    const std::string so_name = "FAKE_SECRET_LIBRARY";
    const char *reason = "file open failed";
    int flags = 3, host_flags = 2, mode = 0600, observed_open_errno = 13;
    long long guest_fd = -1;
    int res = -45075, observed_lstat_errno = 2;
    int load_res = -45075, prov_res = -45054, id_res = 0;
    unsigned spim_len = 17, final_cpim_len = 23, ptm_len = 31, tk_len = 47;
    unsigned long long final_cpim_addr = 0x1234;
''' + "\n".join(selected) + r'''
    std::printf("known=%s,%s unknown=%s\n",
        anisette_native_logging::library_label("libCoreADI.so"),
        anisette_native_logging::library_label("libstoreservicescore.so"),
        anisette_native_logging::library_label(nullptr));
}
'''
        exe = self.compile(harness, "wrapper-output-fake")
        out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
        self.assertNotIn("FAKE_", out)
        self.assertNotIn("0x1234", out)
        for wanted in ("errno=13", "errno=2", "phase=library.init result=-45075",
                       "phase=provisioning_path result=-45054", "phase=android_id result=0",
                       "phase=otp result=-45075", "spim_bytes=17", "cpim_bytes=23",
                       "ptm_bytes=31 tk_bytes=47", "file open failed",
                       "known=libCoreADI.so,libstoreservicescore.so unknown=other"):
            self.assertIn(wanted, out)
        for statement in loader_calls:
            self.assertNotRegex(statement, r"(?<!library_label\()\b(?:path|file_path|so_name|lib.name)\.c_str\(\)")

    def test_mutable_swift_logging_does_not_reconfigure_unicorn(self):
        source = (ROOT / "Sources/AnisetteKitLogging.swift").read_text()
        method = source.split("public static func setLogging(_ enabled: Bool) {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("lock.withLock { isEnabled = enabled }", method)
        self.assertIn("anisetteCoreSetLogging(enabled ? 1 : 0)", method)
        self.assertNotIn("setenv", method)
        self.assertNotIn("UNICORN", method)
        self.assertIn("Restart to enable or disable", source)

    def test_failure_reasons_remain_fixed_source_literals(self):
        parser = (ROOT / "Native/Loader/elf_metadata_bounds.h").read_text()
        reasons = re.findall(r"return fail\((.*?)\);", parser)
        self.assertGreater(len(reasons), 20)
        for reason in reasons:
            self.assertRegex(reason, r'^"[^"\\]*"$')
        self.assertEqual(re.findall(r"\berror\s*=\s*([^;]+);", parser), ["nullptr", "why"])
        loader = LOADER.read_text()
        load = loader.split("bool load_library_to_vm(", 1)[1].split("\nvoid relocate_all_vm_libraries", 1)[0]
        for reason in re.findall(r"return fail\((.*?)\);", load):
            self.assertTrue(reason == "error" or re.fullmatch(r'"[^"\\]*"', reason), reason)
        self.assertIn('apply_table(lib.metadata.rela, "RELA")', loader)
        self.assertIn('apply_table(lib.metadata.jmprel, "PLT/JMPREL")', loader)

    def test_existing_native_wrapper_flag_remains_mutable(self):
        source = (ROOT / "Native/anisette_base.cpp").read_text()
        block = source[source.index("static int g_anisette_logging_enabled = 0;"):source.index("const char* get_anisette_error_description")]
        harness = "#include <stdio.h>\n#include <stdarg.h>\n" + block + r'''
}
int main() {
    anisetteCoreLog("unexpected-off-output\n");
    anisetteCoreSetLogging(1);
    if (anisetteCoreIsLoggingEnabled() != 1) return 93;
    anisetteCoreLog("enabled-result=%d\n", -45075);
    anisetteCoreSetLogging(0);
    if (anisetteCoreIsLoggingEnabled() != 0) return 94;
    anisetteCoreLog("unexpected-disabled-output\n");
}
'''
        exe = self.compile(harness, "existing-native-flag-fake")
        out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
        self.assertEqual(out, "enabled-result=-45075\n")

    def test_existing_native_gates_include_policy_without_removing_checks(self):
        runner = (ROOT / ".ci/native-tests/run_tests.py").read_text()
        self.assertIn("'bounded_asset_digest.h', 'native_logging_policy.h')", runner)
        self.assertIn('#include "Loader/native_logging_policy.h"', runner)
        setup = (ROOT / ".ci/native-tests/test_vm_setup_host.py").read_text()
        self.assertIn("'vm_initialization_diagnostics.h','native_logging_policy.h')", setup)
        workflow = (ROOT / ".github/workflows/native-source-parity.yml").read_text()
        self.assertIn("run: python3 .ci/native-tests/run_tests.py", workflow)
        self.assertIn("run: python3 .ci/native-logging/test_native_logging_contract.py", workflow)
        self.assertIn("git diff --exit-code", workflow)
        self.assertNotIn("continue-on-error", workflow)

    def test_artifact_pin_and_excluded_categories(self):
        source = HEADER.read_text()
        self.assertNotIn('"0xFFFFFFFF"', source)
        self.assertEqual(0xC10, (1 << 4) | (1 << 10) | (1 << 11))
        self.assertEqual(0, 0xC10 & ((1 << 1) | (1 << 12) | (1 << 19)))
        package = (ROOT / "Package.swift").read_text()
        self.assertIn("2.1.4-xcf-a53ddc9/Unicorn.xcframework.zip#AnisetteKit", package)
        self.assertIn("52e4ac9e2d704c4941adc2c381df8706aabf673dc843611a90b33ad349d562db", package)


if __name__ == "__main__":
    unittest.main(verbosity=2)
