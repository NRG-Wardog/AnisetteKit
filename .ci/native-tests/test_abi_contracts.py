#!/usr/bin/env python3
"""Compile the production import router/hooks against bounded guest-memory doubles.

No patch is injected into the tested functions. No Apple libraries, credentials,
provisioning, or network are used. This is ABI regression evidence, not login proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def definition(text: str, name: str) -> str:
    match = re.search(r'^static void ' + re.escape(name) + r'\([^;]*?\)\s*\{', text, re.M)
    if match is None:
        raise ValueError('Missing production definition: ' + name)
    opening = text.index('{', match.start())
    depth = 0
    for i in range(opening, len(text)):
        depth += (text[i] == '{') - (text[i] == '}')
        if depth == 0:
            return text[match.start():i + 1]
    raise ValueError('Unterminated production definition: ' + name)


PRELUDE = r'''
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
enum { UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_Q0 };
using uc_err = int;
constexpr uc_err UC_ERR_OK = 0, UC_ERR_ARG = 1;
struct uc_engine {
    std::array<std::array<uint8_t, 16>, 4> regs{};
    std::array<uint8_t, 65536> mem{};
    unsigned x1_reads = 0, writes = 0;
};
uc_err uc_reg_read(uc_engine *u, int r, void *p) {
    if (r == UC_ARM64_REG_X1) ++u->x1_reads;
    std::memcpy(p, u->regs.at(r).data(), r == UC_ARM64_REG_Q0 ? 16 : 8);
    return UC_ERR_OK;
}
uc_err uc_reg_write(uc_engine *u, int r, const void *p) {
    std::memcpy(u->regs.at(r).data(), p, r == UC_ARM64_REG_Q0 ? 16 : 8);
    return UC_ERR_OK;
}
uc_err uc_mem_read(uc_engine *u, uint64_t a, void *p, size_t n) {
    if (a > u->mem.size() || n > u->mem.size() - a) return UC_ERR_ARG;
    std::memcpy(p, u->mem.data() + a, n);
    return UC_ERR_OK;
}
uc_err uc_mem_write(uc_engine *u, uint64_t a, const void *p, size_t n) {
    ++u->writes;
    if (a > u->mem.size() || n > u->mem.size() - a) return UC_ERR_ARG;
    std::memcpy(u->mem.data() + a, p, n);
    return UC_ERR_OK;
}
struct EmulatorVM {
    uc_engine *uc;
    std::unordered_map<uint64_t, std::string> import_stubs;
};
static EmulatorVM *g_active_vm = nullptr;
'''

CASES = r'''
int main() {
    uc_engine u{};
    EmulatorVM vm{&u, {}};
    unsigned checks = 0, failures = 0;
    auto check = [&](bool ok, const char *label) {
        ++checks;
        if (!ok) ++failures;
        std::cout << (ok ? "PASS " : "FAIL ") << label << "\n";
    };
    auto set = [&](int r, uint64_t v) { uc_reg_write(&u, r, &v); };
    auto get = [&](int r) { uint64_t v = 0; uc_reg_read(&u, r, &v); return v; };
    auto input = [&](const std::string &s, uint64_t ep, unsigned base) {
        std::fill(u.mem.begin(), u.mem.end(), 0xA5);
        uc_mem_write(&u, 0x1000, s.c_str(), s.size() + 1);
        set(UC_ARM64_REG_X0, 0x1000);
        set(UC_ARM64_REG_X1, ep);
        set(UC_ARM64_REG_X2, base);
        u.x1_reads = u.writes = 0;
    };
    auto call = [&](const std::string &symbol) {
        vm.import_stubs[0x9000] = symbol;
        import_callback_router(&u, 0x9000, 4, &vm);
    };
    struct IntegerCase { const char *text; unsigned base; uint64_t expected; };
    const IntegerCase integers[] = {
        {"1234", 16, 0x1234},
        {"7fffffffffffffff", 16, 0x7fffffffffffffffULL},
        {"8000000000000000", 16, 0x8000000000000000ULL},
        {"ffffffffffffffff", 16, UINT64_MAX},
        {"18446744073709551615", 10, UINT64_MAX},
        {"0xffffffffffffffff", 0, UINT64_MAX},
        {"  +123tail", 10, 123},
        {"-1", 10, UINT64_MAX},
        {"", 10, 0},
        {"not-a-number", 10, 0}
    };
    for (const auto &test : integers) {
        input(test.text, 0x2000, test.base);
        call("strtoull");
        check(get(UC_ARM64_REG_X0) == test.expected, "strtoull exact unsigned result");
        char *reference_end = nullptr;
        (void)std::strtoull(test.text, &reference_end, test.base);
        uint64_t actual_end = 0;
        uc_mem_read(&u, 0x2000, &actual_end, 8);
        check(actual_end == 0x1000 + uint64_t(reference_end - test.text), "strtoull end pointer");
    }
    for (const char *name : {"strtol", "strtoll"}) {
        input("-2", 0, 10); call(name);
        check(get(UC_ARM64_REG_X0) == UINT64_MAX - 1, "signed negative unchanged");
    }
    input("-9223372036854775808", 0, 10); call("strtoll");
    check(get(UC_ARM64_REG_X0) == 0x8000000000000000ULL, "signed minimum unchanged");
    input("8000000000000000", 0, 16); call("strtoull");
    check(u.writes == 0, "strtoull null endptr has no memory writes");
    for (uint64_t poison : {uint64_t(0), uint64_t(0x3000), UINT64_MAX}) {
        input("1.25", poison, 0); call("atof");
        double value = 0;
        std::memcpy(&value, u.regs[UC_ARM64_REG_Q0].data(), sizeof(value));
        check(value == 1.25, "atof numerical result");
        check(u.x1_reads == 0 && u.writes == 0, "atof ignores unspecified X1 and never writes memory");
        check(std::all_of(u.mem.begin()+0x3000, u.mem.begin()+0x3008,
            [](uint8_t b) { return b == 0xA5; }), "atof canary preserved");
    }
    input("1.25tail", 0x3000, 0); call("strtod");
    uint64_t end = 0; uc_mem_read(&u, 0x3000, &end, 8);
    check(end == 0x1004, "strtod legitimate endptr unchanged");
    for (auto lock : {std::pair<const char *, size_t>{"pthread_mutex_init", 40},
                      {"pthread_rwlock_init", 56}}) {
        std::fill(u.mem.begin(), u.mem.end(), 0xA5);
        set(UC_ARM64_REG_X0, 0x4000); call(lock.first);
        check(get(UC_ARM64_REG_X0) == 0, "lock init result unchanged");
        check(std::all_of(u.mem.begin()+0x4000, u.mem.begin()+0x4000+lock.second,
            [](uint8_t b) { return b == 0; }), "guest lock initialized");
        check(std::all_of(u.mem.begin()+0x4000+lock.second, u.mem.begin()+0x4040,
            [](uint8_t b) { return b == 0xA5; }), "adjacent guest memory preserved");
        check(u.mem[0x3fff] == 0xA5 && u.mem[0x4040] == 0xA5, "outer lock canaries preserved");
    }
    std::cout << "CHECKS=" << checks << " FAILURES=" << failures << "\n";
    return failures ? 1 : 0;
}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path,
        default=Path(__file__).resolve().parents[2] / 'Native/Loader/elf_loader_emulator.cpp')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--sanitizers', action='store_true')
    args = parser.parse_args()
    compiler = shutil.which('clang++') or shutil.which('c++')
    if compiler is None:
        raise SystemExit('C++17 compiler is required; this test cannot be skipped')
    raw = args.source.read_bytes()
    text = raw.decode('utf-8')
    router = definition(text, 'import_callback_router')
    selected = ['hook_strtoll', 'hook_strtod']
    for optional in ('hook_strtoull', 'hook_atof'):
        if re.search(r'^static void ' + optional + r'\(', text, re.M):
            selected.append(optional)
    other = sorted(set(re.findall(r'\b(hook_\w+)\(vm\)', router)) - set(selected))
    stubs = '\n'.join('static void ' + name + '(EmulatorVM*) { throw std::runtime_error("unexpected import"); }'
                      for name in other)
    unit = PRELUDE + stubs + '\n' + '\n'.join(definition(text, n) for n in selected) + '\n' + router + '\n' + CASES
    with tempfile.TemporaryDirectory(prefix='adi-abi-contracts-') as folder:
        build = Path(folder)
        source = build / 'contracts.cpp'
        binary = build / 'contracts'
        source.write_text(unit, encoding='utf-8')
        command = [compiler, '-std=c++17', '-O1', '-g']
        if args.sanitizers:
            command.append('-fsanitize=address,undefined')
        command += [str(source), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=90)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
    print(run.stdout, end='')
    print(run.stderr, end='')
    report = {'scope': 'production router/hooks with guest-memory doubles, not ADI/device login',
              'source_git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
              'source_sha256': hashlib.sha256(raw).hexdigest(), 'returncode': run.returncode,
              'sanitizers': args.sanitizers, 'stdout': run.stdout, 'stderr': run.stderr}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return run.returncode


if __name__ == '__main__':
    raise SystemExit(main())
