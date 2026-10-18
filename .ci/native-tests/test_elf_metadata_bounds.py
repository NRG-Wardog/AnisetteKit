#!/usr/bin/env python3
"""Run host-only units against the production ELF metadata protection code.

No Unicorn engine, guest executable payload, downloaded library, account data
or network operation is used. This is not a device bug-reproduction build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPECTED = {"schema": 1, "checks": 713, "failures": 0,
            "guest_execution": False, "proprietary_input": False}
SOURCES = ["Native/Loader/elf_metadata_bounds.h", "Native/anisette_base.h",
           "Native/include/anisette_core.h",
           ".ci/native-tests/fixtures/elf_metadata_bounds_unit.cpp"]


def run_checked(command, environment, directory, label):
    result = subprocess.run(command, env=environment, capture_output=True,
                            text=True, timeout=120)
    (directory / (label + ".command.json")).write_text(json.dumps(command) + "\n")
    (directory / (label + ".stdout")).write_text(result.stdout)
    (directory / (label + ".stderr")).write_text(result.stderr)
    (directory / (label + ".exit-code.txt")).write_text(str(result.returncode) + "\n")
    if result.returncode or result.stderr:
        raise RuntimeError(f"{label} failed ({result.returncode}): {result.stderr}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True,
                        help="Directory for exact commands, outputs and hashes")
    parser.add_argument("--disable-leak-sanitizer", action="store_true",
                        help="Explicitly disclose an executor that cannot run LeakSanitizer")
    args = parser.parse_args()
    compiler = shutil.which("c++") or shutil.which("g++")
    if not compiler:
        raise RuntimeError("A C++17 compiler is required; no tests were run")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
              for name in SOURCES}
    results = {}
    with tempfile.TemporaryDirectory(prefix="elf-metadata-unit-") as temporary:
        for variant, flags in (
            ("normal", []),
            ("optimized", ["-O2", "-DNDEBUG"]),
            ("sanitized", ["-O1", "-g", "-fsanitize=address,undefined",
                           "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]),
        ):
            executable = Path(temporary) / variant
            command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", *flags]
            for include in ("Native/Loader", "Native", "Native/include"):
                command.extend(["-I", str(ROOT / include)])
            command.extend([str(ROOT / SOURCES[-1]), "-o", str(executable)])
            environment = os.environ.copy()
            environment["ASAN_OPTIONS"] = (f"detect_leaks={int(not args.disable_leak_sanitizer)}:"
                                           "halt_on_error=1:abort_on_error=1")
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
            run_checked(command, environment, output, variant + "-compile")
            text = run_checked([str(executable)], environment, output, variant + "-run")
            result = json.loads(text)
            if (result != EXPECTED or set(result) != set(EXPECTED)
                    or any(type(result[key]) is not type(value) for key, value in EXPECTED.items())):
                raise RuntimeError(f"{variant} returned an unexpected unit-test result: {text}")
            results[variant] = result
    after = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
             for name in SOURCES}
    if hashes != after:
        raise RuntimeError("Tested source changed during verification")
    receipt = {"schema": 1, "source_sha256": hashes, "results": results,
               "sanitizers": ["address", "undefined"],
               "leak_sanitizer_enabled": not args.disable_leak_sanitizer,
               "guest_execution": False, "device_validation": False,
               "proprietary_input": False}
    (output / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"variants": len(results), "checks_per_variant": EXPECTED["checks"],
                      "failures": 0, "skipped": 0}))


if __name__ == "__main__":
    main()
