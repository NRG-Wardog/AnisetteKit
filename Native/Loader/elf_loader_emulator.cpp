#include "adi_consumption_debug.h"
//
//  elf_loader_emulator.cpp
//  AnisetteKit
//
//  Created by Magesh K on 17/08/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "elf_loader_emulator.h"
#include "android_tls_runtime.h"
#include "cxx_allocation_runtime.h"
#include "work_queue_abi.h"
#include "bounded_asset_digest.h"
#include "bounded_fault_runtime.h"
#include "native_logging_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#if defined(_WIN32) || defined(_MSC_VER)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <direct.h>
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#define close _close
#define read _read
#define write _write
#define open _open
#define fstat _fstat64
#define lstat _stat64
#define stat _stat64
#define ftruncate _chsize
#define mkdir(p, m) _mkdir(p)
#define rmdir _rmdir
typedef int mode_t;

static inline int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    if (tv) {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        uint64_t unix_time_100ns = uli.QuadPart - 116444736000000000ULL;
        tv->tv_sec = (long)(unix_time_100ns / 10000000ULL);
        tv->tv_usec = (long)((unix_time_100ns % 10000000ULL) / 10);
    }
    return 0;
}

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif
#ifndef O_SYNC
#define O_SYNC 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY _O_BINARY
#else
#define O_BINARY 0
#endif
#endif

#else
#include <unistd.h>
#include <sys/time.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <random>
#include <stdexcept>
#include <memory>

const AndroidSystemProperties kAndroidProperties;

// Only called by the owning native worker. Cancellation never calls Unicorn
// from another thread and cannot falsely acknowledge a blocked host callback.
static bool owned_attempt_poll(EmulatorVM *vm) {
    if (!vm->attempt_control || vm->attempt_control->check()) return true;
    vm->initialization_failed = true;
    if (vm->uc) uc_emu_stop(vm->uc);
    return false;
}

static thread_local uint64_t g_last_pcs[16];
static thread_local size_t g_pc_idx = 0;

static void trace_pc_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    auto *vm = static_cast<EmulatorVM *>(user_data);
    if (vm && vm->attempt_control && (++vm->attempt_poll_count % 256 == 0) && !owned_attempt_poll(vm)) return;

    (void)uc; (void)size; (void)user_data;
    g_last_pcs[g_pc_idx % 16] = address;
    g_pc_idx++;
}

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
                             uint64_t address, int size, int64_t value,
                             void *user_data) {
    (void)size;
    (void)value;
    (void)user_data;
    uint64_t page_addr = address & ~0xFFFFULL;

    if (type == UC_MEM_FETCH_UNMAPPED) {
        LOG_UC("[Emulator - UC] FETCH_UNMAPPED at 0x%llx - stopping VM\n", (unsigned long long)address);
        LOG_UC("[TRACE] Last PCs before stop:\n");
        for (int i = 15; i >= 0; i--) {
            size_t idx = (g_pc_idx + 16 - 1 - i) % 16;
            LOG_UC("  [-%d] PC=0x%llx\n", i, (unsigned long long)g_last_pcs[idx]);
        }
        fflush(stdout);
        uc_emu_stop(uc);
        return false;
    }

    if (page_addr == 0 && type == UC_MEM_WRITE_UNMAPPED) {
        LOG_UC("[Emulator - UC] Null pointer write to address 0x%llx - stopping VM safely\n",
               (unsigned long long)address);
        fflush(stdout);
        uc_emu_stop(uc);
        return false;
    }

    uint64_t crash_pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &crash_pc);
    LOG_UC("[Emulator - UC] Dynamically mapping page at 0x%llx (type %d, target=0x%llx) PC=0x%llx\n",
           (unsigned long long)page_addr, (int)type, (unsigned long long)address, (unsigned long long)crash_pc);
    fflush(stdout);

    uc_err err = uc_mem_map(uc, page_addr, 0x10000, UC_PROT_ALL);
    if (err == UC_ERR_OK || err == UC_ERR_MAP) {
        return true;
    }

    uc_emu_stop(uc);
    return false;
}

// Observation only. No engine calls, allocation, mapping, protection or retry.
static bool hook_mem_protection(uc_engine *, uc_mem_type type, uint64_t address,
                                int size, int64_t, void *user_data) noexcept {
    using bounded_fault_diagnostics::Access;
    auto *vm = static_cast<EmulatorVM *>(user_data);
    Access access = Access::Unknown;
    if (type == UC_MEM_READ_PROT) access = Access::ReadProtection;
    else if (type == UC_MEM_WRITE_PROT) access = Access::WriteProtection;
    else if (type == UC_MEM_FETCH_PROT) access = Access::FetchProtection;
    if (vm) vm->protection_fault.record(access, address, size);
    return false;
}

uint64_t PageAllocator::alloc(uint64_t bytes) {
    // Reject before any arithmetic or mutation; guest exhaustion must not abort
    // the host process. Callers treat zero as a failed reservation.
    if (!can_allocate(bytes)) return 0;
    uint64_t align_mask = alignment - 1;
    uint64_t aligned_size = (bytes + align_mask) & ~align_mask;
    if (aligned_size == 0) aligned_size = alignment;

    uint64_t addr = base + offset;
    offset += aligned_size;
    return addr;
}

static void import_callback_router(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data);

EmulatorVM::EmulatorVM(bool checked, std::shared_ptr<anisette_owned_attempt::Control> control)
    : attempt_control(std::move(control)), uc(nullptr),
      heap(kHeapAddress, kHeapSize, 64),
      library_alloc(kLibraryAddress, kLibrarySize, 0x10000),
      next_import_address(kImportAddress),
      next_guest_fd(10)
{
    // Retain the argument for source compatibility; every VM is checked.
    (void)checked;
    if (attempt_control && !attempt_control->check()) throw std::runtime_error("Attempt stopped before VM creation");
    const auto logging_mode = anisette_native_logging::configure_before_first_vm();
    if (logging_mode == anisette_native_logging::StartupMode::Failed) {
        throw std::runtime_error("Native diagnostic startup configuration failed");
    }
    LOG_UC("[Emulator] Startup diagnostics=%s; restart required to change Unicorn logging\n",
           logging_mode == anisette_native_logging::StartupMode::Errors ? "errors-0xC10" : "off");
    uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        LOG_UC("[Emulator] Failed on uc_open() with error returned: %u (%s)\n", err, uc_strerror(err));
        // No engine is owned on a failed uc_open.
        uc = nullptr;
        throw std::runtime_error("VM engine initialization failed");
    }

    auto check = [&](uc_err result) {
        if (result != UC_ERR_OK || (attempt_control && !attempt_control->check())) {
            uc_close(uc); uc = nullptr;
            throw std::runtime_error("VM mapping or hook initialization failed");
        }
    };
    check(uc_mem_map(uc, kHeapAddress, kHeapSize, UC_PROT_READ | UC_PROT_WRITE));

    check(uc_mem_map(uc, kStackAddress, kStackSize, UC_PROT_READ | UC_PROT_WRITE));

    check(uc_mem_map(uc, kImportAddress, kImportSize, UC_PROT_ALL));

    check(uc_mem_map(uc, 0x0, 0x10000, UC_PROT_NONE));

    errno_addr = 0x3FF00000;
    check(uc_mem_map(uc, errno_addr, 0x10000, UC_PROT_READ | UC_PROT_WRITE));
    uint32_t zero = 0;
    check(uc_mem_write(uc, errno_addr, &zero, sizeof(zero)));

    check(uc_hook_add(uc, &invalid_hook, UC_HOOK_MEM_UNMAPPED, (void *)hook_mem_invalid, this, 1, 0));

    check(uc_hook_add(uc, &protection_hook,
        UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
        (void *)hook_mem_protection, this, 1, 0));

    // Each engine owns one Bionic TLS stack guard. Never reuse device identity
    // data as entropy, and never initialize this per procedure/constructor.
    try {
        static_assert(android_tls_runtime::page >= kStackAddress + kStackSize, "TLS overlaps stack");
        static_assert(android_tls_runtime::page + android_tls_runtime::page_size <= kImportAddress, "TLS overlaps imports");
        // Library allocator ends at0x40000000; heap ends at0x68000000.
        const uint64_t guard = android_tls_runtime::make_guard([]() -> uint64_t {
            uint64_t value = 0;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
            arc4random_buf(&value, sizeof(value));
#else
            std::random_device entropy;
            value = std::uniform_int_distribution<uint64_t>()(entropy);
#endif
            return value;
        });
        if (!android_tls_runtime::initialize(uc, guard))
            throw std::runtime_error("Android TLS initialization failed");
    } catch (...) {
        uc_close(uc); uc = nullptr;
        throw;
    }

    uc_hook intr_hook = 0;
    check(uc_hook_add(uc, &intr_hook, UC_HOOK_INTR, (void *)hook_intr, this, 1, 0));

    check(uc_hook_add(uc, &import_hook, UC_HOOK_CODE, (void *)import_callback_router, this,
                kImportAddress, kImportAddress + kImportSize - 1));

    check(uc_hook_add(uc, &pc_trace_hook, UC_HOOK_CODE, (void *)trace_pc_hook, this, 1, 0));
}

EmulatorVM::~EmulatorVM() {
    // V3_ISOLATED_ANISETTE_OTP_V1: dispose guest-owned host descriptors.
    for (const auto &entry : fd_map) close(entry.second);
    fd_map.clear();
    if (uc) {
        uc_close(uc);
        uc = nullptr;
    }
}

uint64_t EmulatorVM::register_import(const std::string &name) {
    auto it = imported_symbols.find(name);
    if (it != imported_symbols.end()) {
        return it->second;
    }

    if (next_import_address < kImportAddress ||
        !elf_metadata_bounds::range(kImportSize, next_import_address - kImportAddress, 8)) {
        initialization_failed = true;
        return 0;
    }
    const uint64_t stub_addr = next_import_address;
    const uint32_t ret_insn = 0xD65F03C0;
    if (uc_mem_write(uc, stub_addr, &ret_insn, sizeof(ret_insn)) != UC_ERR_OK) {
        initialization_failed = true;
        return 0;
    }
    next_import_address += 8;

    imported_symbols[name] = stub_addr;
    import_stubs[stub_addr] = name;

    return stub_addr;
}

static void fail_guest_operation(EmulatorVM *vm) noexcept {
    vm->initialization_failed = true;
    if (vm->uc) uc_emu_stop(vm->uc);
}

static bool checked_guest_read(EmulatorVM *vm, uint64_t address, void *data, size_t size) {
    if (!owned_attempt_poll(vm)) return false;
    uint64_t end = 0;
    // Host memory APIs do not stand in for guest page permissions. Preserve the
    // VM's reserved no-access low page for these host-mediated transfers too.
    if (vm->initialization_failed || (size && address < 0x10000) ||
        !elf_metadata_bounds::add(address, size, end) ||
        uc_mem_read(vm->uc, address, data, size) != UC_ERR_OK) {
        fail_guest_operation(vm);
        return false;
    }
    return true;
}

static bool checked_guest_write(EmulatorVM *vm, uint64_t address, const void *data, size_t size) {
    if (!owned_attempt_poll(vm)) return false;
    uint64_t end = 0;
    if (vm->initialization_failed || (size && address < 0x10000) ||
        !elf_metadata_bounds::add(address, size, end) ||
        uc_mem_write(vm->uc, address, data, size) != UC_ERR_OK) {
        fail_guest_operation(vm);
        return false;
    }
    return true;
}

static bool checked_register_read(EmulatorVM *vm, int reg, void *value) {
    if (vm->initialization_failed || uc_reg_read(vm->uc, reg, value) != UC_ERR_OK) {
        fail_guest_operation(vm);
        return false;
    }
    return true;
}

static bool checked_register_write(EmulatorVM *vm, int reg, const void *value) {
    if (vm->initialization_failed || uc_reg_write(vm->uc, reg, value) != UC_ERR_OK) {
        fail_guest_operation(vm);
        return false;
    }
    return true;
}

uint64_t EmulatorVM::allocate_guest(uint64_t bytes, uint64_t padding) {
    uint64_t reserved = 0;
    if (initialization_failed || !elf_metadata_bounds::add(bytes, padding, reserved)) {
        fail_guest_operation(this);
        return 0;
    }
    const uint64_t address = heap.alloc(reserved);
    if (!address) { fail_guest_operation(this); return 0; }
    try {
        heap_allocation_sizes.emplace(address, bytes);
    } catch (const std::exception &) {
        fail_guest_operation(this);
        return 0;
    }
    return address;
}

uint64_t EmulatorVM::write_bytes(const uint8_t *data, size_t len) {
    if (!data || len == 0) return 0;
    uint64_t addr = allocate_guest(len, 16);
    if (!addr || !checked_guest_write(this, addr, data, len)) return 0;
    return addr;
}

uint64_t EmulatorVM::write_string(const char *str) {
    if (!str) return 0;
    size_t len = strlen(str) + 1;
    return write_bytes((const uint8_t *)str, len);
}

static thread_local EmulatorVM *g_active_vm = nullptr;

static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data) {
    (void)user_data;
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    LOG_UC("[Emulator] Interrupt %u at PC=0x%llx\n", intno, (unsigned long long)pc);
    // No interrupt is implemented by this callback. Stop instead of repeatedly
    // executing the faulting instruction or reporting a false normal return.
    if (auto *vm = static_cast<EmulatorVM *>(user_data)) vm->unsupported_interrupt = true;
    uc_emu_stop(uc);
}

static void hook_malloc(EmulatorVM *vm) {
    uint64_t size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &size)) return;
    const uint64_t ptr = vm->allocate_guest(size, 16);
    if (ptr) checked_register_write(vm, UC_ARM64_REG_X0, &ptr);
}

// Throwing C++ new cannot use the unknown-import zero-return fallback.
// On allocation/register failure stop before the guest can dereference null.
static void hook_cxx_new(EmulatorVM *vm) {
    uint64_t size = 0, pointer = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &size)) return;
    pointer = vm->allocate_guest(size == 0 ? 1 : size);
    if (pointer) checked_register_write(vm, UC_ARM64_REG_X0, &pointer);
}

static bool checked_guest_range(EmulatorVM *vm, uint64_t address, uint64_t size) {
    if (!owned_attempt_poll(vm)) return false;
    uint64_t end = 0;
    if (vm->initialization_failed || (size && address < 0x10000) ||
        !elf_metadata_bounds::add(address, size, end)) {
        fail_guest_operation(vm);
        return false;
    }
    return true;
}

static bool copy_guest_bytes(EmulatorVM *vm, uint64_t destination, uint64_t source, uint64_t size) {
    if (!checked_guest_range(vm, source, size) || !checked_guest_range(vm, destination, size)) return false;
    uint8_t buffer[4096];
    for (uint64_t offset = 0; offset < size;) {
        const size_t count = static_cast<size_t>((std::min)(size - offset, uint64_t(sizeof(buffer))));
        if (!checked_guest_read(vm, source + offset, buffer, count) ||
            !checked_guest_write(vm, destination + offset, buffer, count)) return false;
        offset += count;
    }
    return true;
}

static bool fill_guest_bytes(EmulatorVM *vm, uint64_t destination, uint8_t value, uint64_t size) {
    if (!checked_guest_range(vm, destination, size)) return false;
    uint8_t buffer[4096];
    memset(buffer, value, sizeof(buffer));
    for (uint64_t offset = 0; offset < size;) {
        const size_t count = static_cast<size_t>((std::min)(size - offset, uint64_t(sizeof(buffer))));
        if (!checked_guest_write(vm, destination + offset, buffer, count)) return false;
        offset += count;
    }
    return true;
}

static void hook_calloc(EmulatorVM *vm) {
    uint64_t num = 0, size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &num) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &size)) return;
    uint64_t total = 0;
    if (!elf_metadata_bounds::multiply(num, size, total)) { fail_guest_operation(vm); return; }
    const uint64_t ptr = vm->allocate_guest(total, 16);
    if (!ptr || !fill_guest_bytes(vm, ptr, 0, total)) return;
    checked_register_write(vm, UC_ARM64_REG_X0, &ptr);
}

static void hook_realloc(EmulatorVM *vm) {
    uint64_t ptr = 0, new_size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &ptr) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &new_size)) return;
    uint64_t old_size = 0;
    if (ptr) {
        const auto old = vm->heap_allocation_sizes.find(ptr);
        if (old == vm->heap_allocation_sizes.end()) { fail_guest_operation(vm); return; }
        old_size = old->second;
    }
    const uint64_t new_ptr = vm->allocate_guest(new_size, 16);
    if (!new_ptr) return;
    if (!copy_guest_bytes(vm, new_ptr, ptr, (std::min)(old_size, new_size)) ||
        !checked_register_write(vm, UC_ARM64_REG_X0, &new_ptr)) {
        vm->heap_allocation_sizes.erase(new_ptr);
        return;
    }
    // Existing zero-size semantics are retained: a distinct arena allocation.
    if (ptr) vm->heap_allocation_sizes.erase(ptr);
}

static void hook_free(EmulatorVM *vm) {
    uint64_t ptr = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &ptr)) return;
    vm->heap_allocation_sizes.erase(ptr);
    uint64_t ret = 0;
    checked_register_write(vm, UC_ARM64_REG_X0, &ret);
}

static void hook_strlen(EmulatorVM *vm) {
    uint64_t str_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &str_ptr);
    if (!str_ptr) {
        uint64_t zero = 0;
        uc_reg_write(vm->uc, UC_ARM64_REG_X0, &zero);
        return;
    }
    uint64_t len = 0;
    char c = 0;
    while (true) {
        if (uc_mem_read(vm->uc, str_ptr + len, &c, 1) != UC_ERR_OK || c == '\0') break;
        len++;
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &len);
}

static void hook_strcmp(EmulatorVM *vm) {
    uint64_t s1_ptr = 0, s2_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &s1_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &s2_ptr);
    std::string s1, s2;
    char c = 0;
    if (s1_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, s1_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && s1.size() >= 1048576) { fail_guest_operation(vm); return; } s1.push_back(c); }
    }
    if (s2_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, s2_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && s2.size() >= 1048576) { fail_guest_operation(vm); return; } s2.push_back(c); }
    }
    int64_t cmp_res = (int64_t)s1.compare(s2);
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &cmp_res);
}

static void hook_strncmp(EmulatorVM *vm) {
    uint64_t s1_ptr = 0, s2_ptr = 0, n = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &s1_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &s2_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X2, &n);
    std::string s1, s2;
    char c = 0;
    if (s1_ptr) {
        for (uint64_t i = 0; i < n && owned_attempt_poll(vm) && uc_mem_read(vm->uc, s1_ptr + i, &c, 1) == UC_ERR_OK && c != '\0'; i++) { if (vm->attempt_control && s1.size() >= 1048576) { fail_guest_operation(vm); return; } s1.push_back(c); }
    }
    if (s2_ptr) {
        for (uint64_t i = 0; i < n && owned_attempt_poll(vm) && uc_mem_read(vm->uc, s2_ptr + i, &c, 1) == UC_ERR_OK && c != '\0'; i++) { if (vm->attempt_control && s2.size() >= 1048576) { fail_guest_operation(vm); return; } s2.push_back(c); }
    }
    int64_t cmp_res = (int64_t)s1.compare(s2);
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &cmp_res);
}

static void hook_strcpy(EmulatorVM *vm) {
    uint64_t dst = 0, src = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &dst) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &src)) return;
    for (uint64_t offset = 0;; ++offset) {
        uint64_t from = 0, to = 0;
        if (!elf_metadata_bounds::add(src, offset, from) || !elf_metadata_bounds::add(dst, offset, to)) {
            fail_guest_operation(vm); return;
        }
        char c = 0;
        if (!checked_guest_read(vm, from, &c, 1) || !checked_guest_write(vm, to, &c, 1)) return;
        if (!c) break;
    }
    checked_register_write(vm, UC_ARM64_REG_X0, &dst);
}

static void hook_strncpy(EmulatorVM *vm) {
    uint64_t dst = 0, src = 0, size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &dst) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &src) ||
        !checked_register_read(vm, UC_ARM64_REG_X2, &size) ||
        !checked_guest_range(vm, src, size) || !checked_guest_range(vm, dst, size)) return;
    bool ended = false;
    for (uint64_t offset = 0; offset < size; ++offset) {
        char c = 0;
        if (!ended && !checked_guest_read(vm, src + offset, &c, 1)) return;
        if (!c) ended = true;
        if (!checked_guest_write(vm, dst + offset, &c, 1)) return;
    }
    checked_register_write(vm, UC_ARM64_REG_X0, &dst);
}

static void hook_memcpy(EmulatorVM *vm) {
    uint64_t dst = 0, src = 0, size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &dst) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &src) ||
        !checked_register_read(vm, UC_ARM64_REG_X2, &size)) return;
    if (!copy_guest_bytes(vm, dst, src, size)) return;
    checked_register_write(vm, UC_ARM64_REG_X0, &dst);
}

static void hook_memset(EmulatorVM *vm) {
    uint64_t dst = 0, val = 0, size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &dst) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &val) ||
        !checked_register_read(vm, UC_ARM64_REG_X2, &size)) return;
    if (!fill_guest_bytes(vm, dst, static_cast<uint8_t>(val), size)) return;
    checked_register_write(vm, UC_ARM64_REG_X0, &dst);
}

static void hook_memcmp(EmulatorVM *vm) {
    uint64_t first = 0, second = 0, size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &first) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &second) ||
        !checked_register_read(vm, UC_ARM64_REG_X2, &size) ||
        !checked_guest_range(vm, first, size) || !checked_guest_range(vm, second, size)) return;
    uint8_t left[4096], right[4096];
    int64_t result = 0;
    for (uint64_t offset = 0; offset < size;) {
        const size_t count = static_cast<size_t>((std::min)(size - offset, uint64_t(sizeof(left))));
        if (!checked_guest_read(vm, first + offset, left, count) ||
            !checked_guest_read(vm, second + offset, right, count)) return;
        result = memcmp(left, right, count);
        if (result) break;
        offset += count;
    }
    checked_register_write(vm, UC_ARM64_REG_X0, &result);
}

static void hook_memchr(EmulatorVM *vm) {
    uint64_t s = 0, c = 0, n = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &s);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &c);
    uc_reg_read(vm->uc, UC_ARM64_REG_X2, &n);
    uint64_t res = 0;
    uint8_t target = (uint8_t)c;
    for (uint64_t i = 0; i < n; i++) {
        uint8_t byte = 0;
        if (uc_mem_read(vm->uc, s + i, &byte, 1) != UC_ERR_OK) break;
        if (byte == target) {
            res = s + i;
            break;
        }
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &res);
}

// V3_ISOLATED_ANISETTE_OTP_V1: probe guests cannot mutate the host filesystem.
// Staging occurs in the host wrapper before this VM is initialized. A native
// operation requiring a write fails closed rather than weakening this policy.
static bool deny_read_only_mutation(EmulatorVM *vm) {
    if (!vm->read_only_filesystem) return false;
    uint32_t denied = EPERM;
    uc_mem_write(vm->uc, vm->errno_addr, &denied, sizeof(denied));
    int64_t result = -1;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &result);
    return true;
}

static int linux_to_darwin_open_flags(int linux_flags) {
    int darwin_flags = 0;
    int acc_mode = linux_flags & 3;
    if (acc_mode == 0) darwin_flags |= O_RDONLY;
    else if (acc_mode == 1) darwin_flags |= O_WRONLY;
    else if (acc_mode == 2) darwin_flags |= O_RDWR;

    if (linux_flags & 0x0040)  darwin_flags |= O_CREAT;
    if (linux_flags & 0x0080)  darwin_flags |= O_EXCL;
    if (linux_flags & 0x0100)  darwin_flags |= O_NOCTTY;
    if (linux_flags & 0x0200)  darwin_flags |= O_TRUNC;
    if (linux_flags & 0x0400)  darwin_flags |= O_APPEND;
    if (linux_flags & 0x0800)  darwin_flags |= O_NONBLOCK;
    if (linux_flags & 0x1000)  darwin_flags |= O_SYNC;
    if (linux_flags & 0x80000) darwin_flags |= O_CLOEXEC;

    return darwin_flags;
}

static void hook_open(EmulatorVM *vm) {
    uint64_t path_ptr = 0, flags = 0, mode = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &path_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &flags);
    uc_reg_read(vm->uc, UC_ARM64_REG_X2, &mode);

    // Linux access mode, O_CREAT, O_TRUNC, O_APPEND and O_TMPFILE.
    if (((flags & 3) != 0 || (flags & (0x0040 | 0x0200 | 0x0400 | 0x410000)) != 0) &&
        deny_read_only_mutation(vm)) return;
    std::string path;
    char c = 0;
    bool path_complete = false;
    if (path_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, path_ptr++, &c, 1) == UC_ERR_OK) {
            if (c == '\0') { path_complete = true; break; }
            { if (vm->attempt_control && path.size() >= 1048576) { fail_guest_operation(vm); return; } path.push_back(c); }
        }
    }

    int host_flags = linux_to_darwin_open_flags((int)flags);
    if (vm->attempt_control && (!path_complete || path.size() > 4096 || !owned_attempt_poll(vm))) { fail_guest_operation(vm); return; }
    int host_fd = vm->attempt_filesystem ? vm->attempt_filesystem->open_file(path, host_flags, static_cast<unsigned>(mode)) : open(path.c_str(), host_flags, (mode_t)mode);
    const int observed_open_errno = host_fd < 0 ? errno : 0;
    struct HostFDGuard {
        int fd;
        ~HostFDGuard() { if (fd >= 0) close(fd); }
    } host_fd_guard{host_fd};
    int64_t guest_fd = -1;
    if (host_fd >= 0) {
        guest_fd = vm->next_guest_fd++;
        vm->fd_map[guest_fd] = host_fd;
        host_fd_guard.fd = -1;
        uint32_t zero_err = 0;
        uc_mem_write(vm->uc, vm->errno_addr, &zero_err, sizeof(zero_err));
    } else {
        uint32_t err = (uint32_t)errno;
        uc_mem_write(vm->uc, vm->errno_addr, &err, sizeof(err));
    }
    if (activeADIConsumptionDebug) {
        const int category=activeADIConsumptionDebug->target(path.c_str(),path_complete);
        activeADIConsumptionDebug->record(ADIConsumptionDebug::Open,category,host_fd >= 0 ? 1 : -1,observed_open_errno);
        if (host_fd >= 0) activeADIConsumptionDebug->track(static_cast<int>(guest_fd),category);
    }
    LOG_UC("[Hook] open(path=omitted, linux=0x%x, mac=0x%x, mode=0%o) -> fd %lld (errno=%d)\n",
           (int)flags, host_flags, (int)mode, (long long)guest_fd, observed_open_errno);
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &guest_fd);
}

static void hook_close(EmulatorVM *vm) {
    uint64_t guest_fd = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &guest_fd);
    int64_t res = 0;
    auto it = vm->fd_map.find((int)guest_fd);
    if (it != vm->fd_map.end()) {
        close(it->second);
        vm->fd_map.erase(it);
    } else {
        res = -1;
    }
    if (activeADIConsumptionDebug) {
        activeADIConsumptionDebug->forget(static_cast<int>(guest_fd));
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &res);
}

static void hook_read(EmulatorVM *vm) {
    uint64_t guest_fd = 0, buf_ptr = 0, count = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &guest_fd) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &buf_ptr) ||
        !checked_register_read(vm, UC_ARM64_REG_X2, &count) ||
        !checked_guest_range(vm, buf_ptr, count)) return;
    if (vm->attempt_control && count > anisette_owned_attempt::Filesystem::max_io) { fail_guest_operation(vm); return; }
    int64_t res = -1;
    int observed_read_errno = 0, observed_copy = -1;
    auto it = vm->fd_map.find((int)guest_fd);
    if (it != vm->fd_map.end()) {
        std::vector<uint8_t> tmp(count);
        ssize_t bytes_read = read(it->second, tmp.data(), count);
        observed_read_errno = bytes_read < 0 ? errno : 0;
        if (bytes_read > 0) {
            observed_copy = static_cast<int>(uc_mem_write(vm->uc, buf_ptr, tmp.data(), bytes_read));
            if (observed_copy != UC_ERR_OK) fail_guest_operation(vm);
        }
        if (activeADIConsumptionDebug) activeADIConsumptionDebug->observeRead(
            static_cast<int>(guest_fd), tmp.data(), bytes_read > 0 ? static_cast<uint64_t>(bytes_read) : 0, observed_copy);
        res = (int64_t)bytes_read;
    }
    if (activeADIConsumptionDebug) activeADIConsumptionDebug->record(ADIConsumptionDebug::Read,
        activeADIConsumptionDebug->lookup(static_cast<int>(guest_fd)),res < 0 ? -1 : (res == 0 ? 0 : 1),
        observed_read_errno,count,res > 0 ? static_cast<uint64_t>(res) : 0,observed_copy);
    if (!vm->initialization_failed) checked_register_write(vm, UC_ARM64_REG_X0, &res);
}

static void hook_write(EmulatorVM *vm) {
    if (deny_read_only_mutation(vm)) return;
    uint64_t guest_fd = 0, buf_ptr = 0, count = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &guest_fd) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &buf_ptr) ||
        !checked_register_read(vm, UC_ARM64_REG_X2, &count) ||
        !checked_guest_range(vm, buf_ptr, count)) return;
    if (vm->attempt_control && count > anisette_owned_attempt::Filesystem::max_io) { fail_guest_operation(vm); return; }
    int64_t res = -1;
    auto it = vm->fd_map.find((int)guest_fd);
    if (it != vm->fd_map.end()) {
        std::vector<uint8_t> tmp(count);
        if (!checked_guest_read(vm, buf_ptr, tmp.data(), count)) return;
        if (vm->attempt_control) {
            if (count > 16 * 1048576 - vm->attempt_written_bytes) { fail_guest_operation(vm); return; }
            vm->attempt_written_bytes += count;
            struct stat st{}; const off_t offset = lseek(it->second, 0, SEEK_CUR);
            if (fstat(it->second, &st) != 0 || offset < 0 || uint64_t(offset) > anisette_owned_attempt::Filesystem::max_io ||
                count > anisette_owned_attempt::Filesystem::max_io - uint64_t(offset) ||
                st.st_size < 0 || uint64_t(st.st_size) > anisette_owned_attempt::Filesystem::max_io ||
                count > anisette_owned_attempt::Filesystem::max_io - uint64_t(st.st_size)) { fail_guest_operation(vm); return; }
        }
        res = (int64_t)write(it->second, tmp.data(), count);
    }
    // A successful write advances the stream outside passive read coverage.
    if (res > 0 && activeADIConsumptionDebug)
        activeADIConsumptionDebug->invalidateOffset(static_cast<int>(guest_fd));
    checked_register_write(vm, UC_ARM64_REG_X0, &res);
}

static void hook_ftruncate(EmulatorVM *vm) {
    if (deny_read_only_mutation(vm)) return;
    uint64_t guest_fd = 0, length = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &guest_fd);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &length);
    int64_t res = -1;
    if (vm->attempt_control && length > anisette_owned_attempt::Filesystem::max_io) { fail_guest_operation(vm); return; }
    auto it = vm->fd_map.find((int)guest_fd);
    if (it != vm->fd_map.end()) {
        res = (int64_t)ftruncate(it->second, (off_t)length);
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &res);
}

static void hook_mkdir(EmulatorVM *vm) {
    if (deny_read_only_mutation(vm)) return;
    uint64_t path_ptr = 0, mode = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &path_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &mode);
    std::string path;
    char c = 0;
    if (path_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, path_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && path.size() >= 1048576) { fail_guest_operation(vm); return; } path.push_back(c); }
    }
    int res = vm->attempt_filesystem ? vm->attempt_filesystem->create_directory(path) : mkdir(path.c_str(), (mode_t)mode);
    if (!vm->attempt_control && res != 0 && errno == EEXIST) {
        res = 0;
        uint32_t zero_err = 0;
        uc_mem_write(vm->uc, vm->errno_addr, &zero_err, sizeof(zero_err));
    } else if (res != 0) {
        uint32_t err = (uint32_t)errno;
        uc_mem_write(vm->uc, vm->errno_addr, &err, sizeof(err));
    } else {
        uint32_t zero_err = 0;
        uc_mem_write(vm->uc, vm->errno_addr, &zero_err, sizeof(zero_err));
    }
    int64_t ret = res;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

static void hook_umask(EmulatorVM *vm) {
    if (vm->attempt_control) { int64_t value = 0077; checked_register_write(vm, UC_ARM64_REG_X0, &value); return; }
    if (deny_read_only_mutation(vm)) return;
    uint64_t mask = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &mask);
    int64_t old_mask = (int64_t)umask((mode_t)mask);
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &old_mask);
}

static void hook_chmod(EmulatorVM *vm) {
    if (vm->attempt_control) { int64_t value = -1; checked_register_write(vm, UC_ARM64_REG_X0, &value); return; }
    if (deny_read_only_mutation(vm)) return;
    uint64_t path_ptr = 0, mode = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &path_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &mode);
    std::string path;
    char c = 0;
    if (path_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, path_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && path.size() >= 1048576) { fail_guest_operation(vm); return; } path.push_back(c); }
    }
    int64_t res = (int64_t)chmod(path.c_str(), (mode_t)mode);
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &res);
}

static void hook_lstat(EmulatorVM *vm) {
    uint64_t path_ptr = 0, stat_buf_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &path_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &stat_buf_ptr);
    std::string path;
    char c = 0;
    if (path_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, path_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && path.size() >= 1048576) { fail_guest_operation(vm); return; } path.push_back(c); }
    }
    struct stat host_st;
    int res = vm->attempt_filesystem ? vm->attempt_filesystem->stat_path(path, &host_st) : lstat(path.c_str(), &host_st);
    const int observed_lstat_errno = res < 0 ? errno : 0;
    if (res == 0 && stat_buf_ptr != 0) {
        StatLinux linux_st = {0};
        linux_st.st_dev = (uint64_t)host_st.st_dev;
        linux_st.st_ino = (uint64_t)host_st.st_ino;
        linux_st.st_mode = (uint32_t)host_st.st_mode;
        linux_st.st_nlink = (uint32_t)host_st.st_nlink;
        linux_st.st_uid = (uint32_t)host_st.st_uid;
        linux_st.st_gid = (uint32_t)host_st.st_gid;
        linux_st.st_rdev = (uint64_t)host_st.st_rdev;
        linux_st.st_size = (int64_t)host_st.st_size;
#if defined(_WIN32)
        linux_st.st_blksize = 4096;
        linux_st.st_blocks = (linux_st.st_size + 511) / 512;
#else
        linux_st.st_blksize = (int32_t)host_st.st_blksize;
        linux_st.st_blocks = (int64_t)host_st.st_blocks;
#endif
#if defined(__APPLE__) || defined(__MACH__)
        linux_st.st_atime = (int64_t)host_st.st_atimespec.tv_sec;
        linux_st.st_atime_nsec = (uint64_t)host_st.st_atimespec.tv_nsec;
        linux_st.st_mtime = (int64_t)host_st.st_mtimespec.tv_sec;
        linux_st.st_mtime_nsec = (uint64_t)host_st.st_mtimespec.tv_nsec;
        linux_st.st_ctime = (int64_t)host_st.st_ctimespec.tv_sec;
        linux_st.st_ctime_nsec = (uint64_t)host_st.st_ctimespec.tv_nsec;
#elif defined(_WIN32)
        linux_st.st_atime = (int64_t)host_st.st_atime;
        linux_st.st_atime_nsec = 0;
        linux_st.st_mtime = (int64_t)host_st.st_mtime;
        linux_st.st_mtime_nsec = 0;
        linux_st.st_ctime = (int64_t)host_st.st_ctime;
        linux_st.st_ctime_nsec = 0;
#else
        linux_st.st_atime = (int64_t)host_st.st_atim.tv_sec;
        linux_st.st_atime_nsec = (uint64_t)host_st.st_atim.tv_nsec;
        linux_st.st_mtime = (int64_t)host_st.st_mtim.tv_sec;
        linux_st.st_mtime_nsec = (uint64_t)host_st.st_mtim.tv_nsec;
        linux_st.st_ctime = (int64_t)host_st.st_ctim.tv_sec;
        linux_st.st_ctime_nsec = (uint64_t)host_st.st_ctim.tv_nsec;
#endif
        uc_mem_write(vm->uc, stat_buf_ptr, &linux_st, sizeof(linux_st));
        uint32_t zero_err = 0;
        uc_mem_write(vm->uc, vm->errno_addr, &zero_err, sizeof(zero_err));
    } else {
        uint32_t err = (uint32_t)errno;
        uc_mem_write(vm->uc, vm->errno_addr, &err, sizeof(err));
    }
    LOG_UC("[Hook] lstat(path=omitted) -> res %d (errno=%d)\n", res, observed_lstat_errno);
    int64_t ret = res;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

static void hook_fstat(EmulatorVM *vm) {
    uint64_t guest_fd = 0, stat_buf_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &guest_fd);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &stat_buf_ptr);
    int64_t res = -1;
    auto it = vm->fd_map.find((int)guest_fd);
    if (it != vm->fd_map.end() && stat_buf_ptr != 0) {
        struct stat host_st;
        if (fstat(it->second, &host_st) == 0) {
            StatLinux linux_st = {0};
            linux_st.st_dev = (uint64_t)host_st.st_dev;
            linux_st.st_ino = (uint64_t)host_st.st_ino;
            linux_st.st_mode = (uint32_t)host_st.st_mode;
            linux_st.st_nlink = (uint32_t)host_st.st_nlink;
            linux_st.st_uid = (uint32_t)host_st.st_uid;
            linux_st.st_gid = (uint32_t)host_st.st_gid;
            linux_st.st_rdev = (uint64_t)host_st.st_rdev;
            linux_st.st_size = (int64_t)host_st.st_size;
#if defined(_WIN32) || defined(_MSC_VER)
            linux_st.st_blksize = 4096;
            linux_st.st_blocks = (linux_st.st_size + 511) / 512;
#else
            linux_st.st_blksize = (int32_t)host_st.st_blksize;
            linux_st.st_blocks = (int64_t)host_st.st_blocks;
#endif
#if defined(__APPLE__) || defined(__MACH__)
            linux_st.st_atime = (int64_t)host_st.st_atimespec.tv_sec;
            linux_st.st_atime_nsec = (uint64_t)host_st.st_atimespec.tv_nsec;
            linux_st.st_mtime = (int64_t)host_st.st_mtimespec.tv_sec;
            linux_st.st_mtime_nsec = (uint64_t)host_st.st_mtimespec.tv_nsec;
            linux_st.st_ctime = (int64_t)host_st.st_ctimespec.tv_sec;
            linux_st.st_ctime_nsec = (uint64_t)host_st.st_ctimespec.tv_nsec;
#elif defined(_WIN32)
            linux_st.st_atime = (int64_t)host_st.st_atime;
            linux_st.st_atime_nsec = 0;
            linux_st.st_mtime = (int64_t)host_st.st_mtime;
            linux_st.st_mtime_nsec = 0;
            linux_st.st_ctime = (int64_t)host_st.st_ctime;
            linux_st.st_ctime_nsec = 0;
#else
            linux_st.st_atime = (int64_t)host_st.st_atim.tv_sec;
            linux_st.st_atime_nsec = (uint64_t)host_st.st_atim.tv_nsec;
            linux_st.st_mtime = (int64_t)host_st.st_mtim.tv_sec;
            linux_st.st_mtime_nsec = (uint64_t)host_st.st_mtim.tv_nsec;
            linux_st.st_ctime = (int64_t)host_st.st_ctim.tv_sec;
            linux_st.st_ctime_nsec = (uint64_t)host_st.st_ctim.tv_nsec;
#endif
            uc_mem_write(vm->uc, stat_buf_ptr, &linux_st, sizeof(linux_st));
            res = 0;
        }
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &res);
}

static void hook_errno_location(EmulatorVM *vm) {
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &vm->errno_addr);
}

static void hook_system_property_get(EmulatorVM *vm) {
    uint64_t name_ptr = 0, val_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &name_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &val_ptr);
    std::string name;
    char c = 0;
    if (name_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, name_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && name.size() >= 1048576) { fail_guest_operation(vm); return; } name.push_back(c); }
    }
    std::string prop_val = "";
    if (name == "ro.build.version.sdk") prop_val = kAndroidProperties.sdk_version;
    else if (name == "ro.build.version.release") prop_val = kAndroidProperties.release;
    else if (name == "ro.product.model") prop_val = kAndroidProperties.model;
    else if (name == "ro.product.brand") prop_val = kAndroidProperties.brand;
    else if (name == "ro.product.name") prop_val = kAndroidProperties.name;
    else if (name == "ro.product.device") prop_val = kAndroidProperties.device;
    else if (name == "ro.product.manufacturer") prop_val = kAndroidProperties.manufacturer;
    else if (name == "ro.build.fingerprint") prop_val = kAndroidProperties.fingerprint;

    if (val_ptr != 0) {
        std::vector<uint8_t> buf(92, 0);
        memcpy(buf.data(), prop_val.c_str(), (std::min)((size_t)91, prop_val.length()));
        uc_mem_write(vm->uc, val_ptr, buf.data(), 92);
    }
    int64_t ret = (int64_t)prop_val.length();
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

static void hook_arc4random(EmulatorVM *vm) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    uint64_t rnd = (uint64_t)arc4random();
#else
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    uint64_t rnd = (uint64_t)gen();
#endif
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &rnd);
}

static void hook_gettimeofday(EmulatorVM *vm) {
    uint64_t tv_ptr = 0, tz_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &tv_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &tz_ptr);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (tv_ptr) {
        uint64_t tv_sec = (uint64_t)tv.tv_sec;
        uint64_t tv_usec = (uint64_t)tv.tv_usec;
        uc_mem_write(vm->uc, tv_ptr, &tv_sec, 8);
        uc_mem_write(vm->uc, tv_ptr + 8, &tv_usec, 8);
    }
    int64_t ret = 0;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

static void hook_getauxval(EmulatorVM *vm) {
    uint64_t type = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &type);
    uint64_t val = 0;
    if (type == 6  ) val = 4096;
    else if (type == 16  ) val = 0xff;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &val);
}

static void hook_dlopen(EmulatorVM *vm) {
    uint64_t handle = 0x50000000;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &handle);
}

static void hook_dlsym(EmulatorVM *vm) {
    uint64_t handle = 0, sym_name_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &handle);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &sym_name_ptr);
    std::string sym_name;
    char c = 0;
    if (sym_name_ptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, sym_name_ptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && sym_name.size() >= 1048576) { fail_guest_operation(vm); return; } sym_name.push_back(c); }
    }
    uint64_t addr = get_vm_symbol_address(vm, sym_name);
    if (!addr) {
        addr = vm->register_import(sym_name);
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &addr);
}

static void hook_cxa_guard_acquire(EmulatorVM *vm) {
    uint64_t guard_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &guard_ptr);
    uint8_t first_byte = 0;
    if (guard_ptr) {
        uc_mem_read(vm->uc, guard_ptr, &first_byte, 1);
    }
    int64_t ret = (first_byte == 0) ? 1 : 0;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

static void hook_cxa_guard_release(EmulatorVM *vm) {
    uint64_t guard_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &guard_ptr);
    uint8_t one = 1;
    if (guard_ptr) {
        uc_mem_write(vm->uc, guard_ptr, &one, 1);
    }
    int64_t ret = 0;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

static void hook_cxa_allocate_exception(EmulatorVM *vm) {
    uint64_t size = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X0, &size)) return;
    const uint64_t ptr = vm->allocate_guest(size, 128);
    if (ptr) checked_register_write(vm, UC_ARM64_REG_X0, &ptr);
}

static void hook_dynamic_cast(EmulatorVM *vm) {
    uint64_t sub = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &sub);
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &sub);
}

static void hook_strtoll(EmulatorVM *vm) {
    uint64_t nptr = 0, endptr = 0, base = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &nptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &endptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X2, &base);

    std::string str;
    char c = 0;
    if (nptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, nptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && str.size() >= 1048576) { fail_guest_operation(vm); return; } str.push_back(c); }
    }

    char *host_end = nullptr;
    int64_t val = strtoll(str.c_str(), &host_end, (int)base);
    if (endptr != 0 && host_end != nullptr) {
        size_t consumed = host_end - str.c_str();
        uint64_t final_end_addr = (nptr - str.length() - 1) + consumed;
        uc_mem_write(vm->uc, endptr, &final_end_addr, sizeof(final_end_addr));
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &val);
}

static void hook_strtoull(EmulatorVM *vm) {
    uint64_t nptr = 0, endptr = 0, base = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &nptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &endptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X2, &base);

    std::string str;
    char c = 0;
    if (nptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, nptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && str.size() >= 1048576) { fail_guest_operation(vm); return; } str.push_back(c); }
    }

    char *host_end = nullptr;
    uint64_t val = strtoull(str.c_str(), &host_end, (int)base);
    if (endptr != 0 && host_end != nullptr) {
        size_t consumed = host_end - str.c_str();
        uint64_t final_end_addr = (nptr - str.length() - 1) + consumed;
        uc_mem_write(vm->uc, endptr, &final_end_addr, sizeof(final_end_addr));
    }
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &val);
}

static void hook_strtod(EmulatorVM *vm) {
    uint64_t nptr = 0, endptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &nptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &endptr);

    std::string str;
    char c = 0;
    if (nptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, nptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && str.size() >= 1048576) { fail_guest_operation(vm); return; } str.push_back(c); }
    }

    char *host_end = nullptr;
    double val = strtod(str.c_str(), &host_end);
    if (endptr != 0 && host_end != nullptr) {
        size_t consumed = host_end - str.c_str();
        uint64_t final_end_addr = (nptr - str.length() - 1) + consumed;
        uc_mem_write(vm->uc, endptr, &final_end_addr, sizeof(final_end_addr));
    }
    uint8_t d0_val[16] = {0};
    memcpy(d0_val, &val, sizeof(double));
    uc_reg_write(vm->uc, UC_ARM64_REG_Q0, d0_val);
}

// atof has one argument. X1 is not an end-pointer supplied by its caller.
static void hook_atof(EmulatorVM *vm) {
    uint64_t nptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &nptr);
    std::string str;
    char c = 0;
    if (nptr) {
        while (owned_attempt_poll(vm) && uc_mem_read(vm->uc, nptr++, &c, 1) == UC_ERR_OK && c != '\0') { if (vm->attempt_control && str.size() >= 1048576) { fail_guest_operation(vm); return; } str.push_back(c); }
    }
    double val = strtod(str.c_str(), nullptr);
    uint8_t d0_val[16] = {0};
    memcpy(d0_val, &val, sizeof(double));
    uc_reg_write(vm->uc, UC_ARM64_REG_Q0, d0_val);
}

static void hook_android_log_print(EmulatorVM *vm) {
    uint64_t prio = 0, tag_ptr = 0, fmt_ptr = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_X0, &prio);
    uc_reg_read(vm->uc, UC_ARM64_REG_X1, &tag_ptr);
    uc_reg_read(vm->uc, UC_ARM64_REG_X2, &fmt_ptr);
    // Guest strings are arbitrary payloads. Do not read, format or capture them.
    // Retain priority and argument presence, not string contents or addresses.
    LOG_UC("[Android Log] priority=%lld tag_present=%d format_present=%d text=omitted\n",
           (long long)prio, tag_ptr != 0, fmt_ptr != 0);
    int64_t ret = 0;
    uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
}

// Permit only a complete writable 16-byte result in live guest stack or an
// actual tracked allocation. Unicorn host writes alone do not enforce guest
// page permissions. Check those separately before a single bounded write.
static bool work_queue_result_writable(EmulatorVM *vm, uint64_t output, uint64_t sp) {
    if ((output & 7) != 0 || output < 0x10000) return false;
    bool owned = sp >= kStackAddress && sp < kStackAddress + kStackSize &&
        output >= sp && work_queue_abi::fits(output, kStackAddress, kStackSize);
    for (const auto &allocation : vm->heap_allocation_sizes)
        owned = owned || work_queue_abi::fits(output, allocation.first, allocation.second);
    if (!owned) return false;
    uc_mem_region *regions = nullptr;
    uint32_t count = 0;
    const uc_err status = uc_mem_regions(vm->uc, &regions, &count);
    bool writable = false;
    if (status == UC_ERR_OK && regions && count <= 256) {
        unsigned covering = 0;
        for (uint32_t i = 0; i < count; ++i) {
            const auto &region = regions[i];
            if (region.begin <= output && region.end >= output &&
                region.end - output >= 15) {
                ++covering;
                writable = (region.perms & UC_PROT_WRITE) != 0;
            }
        }
        writable = writable && covering == 1;
    }
    if (regions) uc_free(regions);
    return writable;
}

static void hook_empty_work_queue(EmulatorVM *vm) {
    uint64_t output = 0, sp = 0, type = 0;
    if (!checked_register_read(vm, UC_ARM64_REG_X8, &output) ||
        !checked_register_read(vm, UC_ARM64_REG_SP, &sp) ||
        !checked_register_read(vm, UC_ARM64_REG_X1, &type)) return;
    // Only the observed factory type (W1=0) is admitted. Do not reinterpret
    // another enum value as an empty functioning queue.
    if (static_cast<uint32_t>(type) != 0 || !work_queue_result_writable(vm, output, sp)) {
        LOG_UC("[Emulator] Unsupported WorkQueue factory result or type\n");
        fail_guest_operation(vm);
        return;
    }
    const uint64_t empty_shared_ptr[2] = {0, 0};
    // Leave X0, X1, X8, LR and errno unchanged; the return is the X8 object.
    checked_guest_write(vm, output, empty_shared_ptr, sizeof(empty_shared_ptr));
}

static void import_callback_router(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    (void)size;
    EmulatorVM *vm = (EmulatorVM *)user_data;
    if (!vm) vm = g_active_vm;
    if (!vm) return;
    if (!owned_attempt_poll(vm)) return;
    if (vm->initialization_failed) { uc_emu_stop(uc); return; }

    auto it = vm->import_stubs.find(address);
    if (it == vm->import_stubs.end()) {
        return;
    }

    const std::string &name = it->second;

    // Host allocation failures must not unwind through Unicorn's C callback.
    try {
    const auto media_operation = work_queue_abi::classify(name);
    if (media_operation == work_queue_abi::Operation::EmptyFactory) {
        hook_empty_work_queue(vm);
        return;
    }
    if (media_operation == work_queue_abi::Operation::UnsupportedMedia) {
        LOG_UC("[Emulator] Unsupported mediaplatform import\n");
        fail_guest_operation(vm);
        return;
    }
    const auto cxx_operation = cxx_allocation_runtime::classify(name);
    if (cxx_operation == cxx_allocation_runtime::Operation::New) hook_cxx_new(vm);
    // Matches this VM's existing free semantics: arena lifetime is the VM.
    else if (cxx_operation == cxx_allocation_runtime::Operation::Delete) hook_free(vm);
    else if (name == "malloc") hook_malloc(vm);
    else if (name == "calloc") hook_calloc(vm);
    else if (name == "realloc") hook_realloc(vm);
    else if (name == "free") hook_free(vm);
    else if (name == "strlen") hook_strlen(vm);
    else if (name == "strcmp") hook_strcmp(vm);
    else if (name == "strncmp") hook_strncmp(vm);
    else if (name == "strcpy") hook_strcpy(vm);
    else if (name == "strncpy") hook_strncpy(vm);
    else if (name == "memcpy") hook_memcpy(vm);
    else if (name == "memset") hook_memset(vm);
    else if (name == "memcmp") hook_memcmp(vm);
    else if (name == "memchr") hook_memchr(vm);
    else if (name == "open") hook_open(vm);
    else if (name == "close") hook_close(vm);
    else if (name == "read") hook_read(vm);
    else if (name == "write") hook_write(vm);
    else if (name == "ftruncate") hook_ftruncate(vm);
    else if (name == "mkdir") hook_mkdir(vm);
    else if (name == "umask") hook_umask(vm);
    else if (name == "chmod") hook_chmod(vm);
    else if (name == "lstat") hook_lstat(vm);
    else if (name == "fstat") hook_fstat(vm);
    else if (name == "__errno" || name == "__errno_location") hook_errno_location(vm);
    else if (name == "__system_property_get") hook_system_property_get(vm);
    else if (name == "arc4random") hook_arc4random(vm);
    else if (name == "gettimeofday") hook_gettimeofday(vm);
    else if (name == "getauxval") hook_getauxval(vm);
    else if (name == "dlopen") hook_dlopen(vm);
    else if (name == "dlsym") hook_dlsym(vm);
    else if (name == "__cxa_guard_acquire") hook_cxa_guard_acquire(vm);
    else if (name == "__cxa_guard_release") hook_cxa_guard_release(vm);
    else if (name == "__cxa_allocate_exception") hook_cxa_allocate_exception(vm);
    else if (name == "__cxa_begin_catch" || name == "__dynamic_cast") hook_dynamic_cast(vm);
    else if (name == "strtoll" || name == "strtol") hook_strtoll(vm);
    else if (name == "strtoull") hook_strtoull(vm);
    else if (name == "strtod") hook_strtod(vm);
    else if (name == "atof") hook_atof(vm);
    else if (name == "pthread_rwlock_init" || name == "pthread_mutex_init") {
        uint64_t lock_ptr = 0;
        uc_reg_read(vm->uc, UC_ARM64_REG_X0, &lock_ptr);
        if (lock_ptr) {
            // AArch64 Bionic ABI sizes, never the host pthread types.
            const size_t guest_size = name == "pthread_mutex_init" ? 40u : 56u;
            std::vector<uint8_t> dummy_lock(guest_size, 0);
            uc_mem_write(vm->uc, lock_ptr, dummy_lock.data(), dummy_lock.size());
        }
        uint64_t ret = 0;
        uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
    }
    else if (name == "__android_log_print") hook_android_log_print(vm);
    else {

        uint64_t ret = 0;
        uc_reg_write(vm->uc, UC_ARM64_REG_X0, &ret);
    }
    } catch (const std::exception &) {
        fail_guest_operation(vm);
    }
}

static uint64_t vm_resolve_symbol(EmulatorVM *vm, const EmulatorVM::LibraryInfo &current_lib, uint32_t sym_idx) {
    Elf64_Sym sym{};
    std::string sym_name;
    if (!elf_metadata_bounds::symbol(current_lib.metadata, sym_idx, sym) ||
        !elf_metadata_bounds::name(current_lib.metadata, sym.st_name, sym_name)) {
        vm->initialization_failed = true;
        return 0;
    }
    if (sym.st_shndx != elf_metadata_bounds::undefined_section) {
        uint64_t address = 0;
        if (!elf_metadata_bounds::definition_address(current_lib.metadata, current_lib.base_address, sym, address)) {
            vm->initialization_failed = true;
            return 0;
        }
        return address;
    }
    // STN_UNDEF / an unnamed undefined symbol has the ELF value zero. A
    // defined symbol at value zero is handled above, without a sentinel test.
    if (sym_name.empty()) return 0;

    auto self_it = current_lib.symbols.find(sym_name);
    if (self_it != current_lib.symbols.end()) return self_it->second;

    for (const auto &lib : vm->loaded_libraries) {
        auto it = lib.symbols.find(sym_name);
        if (it != lib.symbols.end()) return it->second;
    }

    std::string converted = sym_name;
    size_t pos = converted.find("6__ndk1");
    if (pos != std::string::npos) {
        converted.replace(pos, 7, "3__1");
    } else {
        pos = converted.find("__ndk1");
        if (pos != std::string::npos) {
            converted.replace(pos, 6, "__1");
        }
    }
    if (converted != sym_name) {
        for (const auto &lib : vm->loaded_libraries) {
            auto it = lib.symbols.find(converted);
            if (it != lib.symbols.end()) return it->second;
        }
    }

    uint8_t sym_type = sym.st_info & 0xf;
    bool is_data = (sym_type == 1  ) ||
                   sym_name.rfind("_ZTV", 0) == 0 ||
                   sym_name.rfind("_ZTI", 0) == 0 ||
                   sym_name.rfind("_ZTS", 0) == 0 ||
                   sym_name.rfind("kCF", 0) == 0 ||
                   sym_name.rfind("kAudio", 0) == 0 ||
                   sym_name.rfind("OBJC_", 0) == 0 ||
                   sym_name == "__CFConstantStringClassReference" ||
                   sym_name == "__sF" ||
                   sym_name == "environ" ||
                   sym_name == "__stack_chk_guard" ||
                   sym_name == "__ctype_";

    if (is_data) {
        auto it = vm->imported_symbols.find(sym_name);
        if (it != vm->imported_symbols.end()) return it->second;
        if (!vm->heap.can_allocate(256)) {
            vm->initialization_failed = true;
            return 0;
        }
        uint64_t dummy = vm->heap.alloc(256);
        std::vector<uint8_t> zeros(256, 0);
        if (uc_mem_write(vm->uc, dummy, zeros.data(), 256) != UC_ERR_OK) {
            vm->initialization_failed = true;
            return 0;
        }
        vm->imported_symbols[sym_name] = dummy;
        return dummy;
    }

    return vm->register_import(sym_name);
}

static bool apply_vm_relocations(EmulatorVM *vm, EmulatorVM::LibraryInfo &lib) {
    auto apply_table = [&](const std::vector<Elf64_Rela> &table, const char *label) {
        size_t applied = 0;
        for (const auto &r : table) {
            if (!owned_attempt_poll(vm)) return false;
            const uint32_t type = static_cast<uint32_t>(ELF64_R_TYPE(r.r_info));
            const uint32_t sym_idx = static_cast<uint32_t>(ELF64_R_SYM(r.r_info));
            if (sym_idx >= lib.metadata.symbol_count) return false;
            if (type == 0) continue; // R_AARCH64_NONE
            uint64_t target_addr = 0, final_val = 0;
            if (!elf_metadata_bounds::guest_address(lib.metadata, lib.base_address, r.r_offset,
                                                    sizeof(final_val), target_addr)) return false;
            if (type == R_AARCH64_RELATIVE) {
                if (!elf_metadata_bounds::relative_address(lib.metadata, lib.base_address, r.r_addend, final_val))
                    return false;
            } else if (type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_GLOB_DAT || type == R_AARCH64_ABS64) {
                const uint64_t sym_addr = vm_resolve_symbol(vm, lib, sym_idx);
                if (vm->initialization_failed || !elf_metadata_bounds::signed_add(sym_addr, r.r_addend, final_val))
                    return false;
            } else {
                return false;
            }
            if (uc_mem_write(vm->uc, target_addr, &final_val, sizeof(final_val)) != UC_ERR_OK) return false;
            ++applied;
        }
        LOG_UC("[Emulator] Applied %zu / %zu relocations for %s in '%s'\n",
               applied, table.size(), label, anisette_native_logging::library_label(lib.name.c_str()));
        return true;
    };
    return apply_table(lib.metadata.rela, "RELA") && apply_table(lib.metadata.jmprel, "PLT/JMPREL");
}

bool load_library_to_vm(EmulatorVM *vm, const std::string &file_path, const std::string &so_name) {
    if (!vm || !vm->uc || vm->initialization_failed) return false;
    auto fail = [&](const char *reason) {
        LOG_UC("[Emulator] Failed loading '%s': %s\n", anisette_native_logging::library_label(so_name.c_str()), reason);
        vm->initialization_failed = true;
        return false;
    };
    try {
        LOG_UC("[Emulator] Loading ELF library '%s' (path=omitted)...\n",
               anisette_native_logging::library_label(so_name.c_str()));
        if (!owned_attempt_poll(vm)) return fail("attempt stopped");
        FILE *opened = nullptr;
#if !defined(_WIN32) && !defined(_MSC_VER)
        if (vm->attempt_filesystem) {
            int fd = vm->attempt_filesystem->open_file(file_path, O_RDONLY, 0);
            if (fd >= 0) { opened = fdopen(fd, "rb"); if (!opened) close(fd); }
        } else
#endif
        { opened = fopen(file_path.c_str(), "rb"); }
        std::unique_ptr<FILE, int (*)(FILE *)> file(opened, fclose);
        if (!file) return fail("file open failed");
        if (fseek(file.get(), 0, SEEK_END) != 0) return fail("file seek failed");
        const long length = ftell(file.get());
        if (length < 0 || static_cast<uint64_t>(length) > SIZE_MAX ||
            fseek(file.get(), 0, SEEK_SET) != 0) return fail("invalid file size");
        const size_t file_size = static_cast<size_t>(length);
        if (vm->attempt_control && (file_size > 64 * 1048576 || !owned_attempt_poll(vm))) return fail("owned library budget");
        std::vector<uint8_t> buffer(file_size);
        if (fread(buffer.data(), 1, file_size, file.get()) != file_size) return fail("file read failed");
        file.reset();

        EmulatorVM::LibraryInfo lib{};
        lib.asset_digest = bounded_fault_diagnostics::loaded_buffer_digest(buffer.data(), buffer.size());
        const char *error = nullptr;
        if (!elf_metadata_bounds::parse(buffer.data(), buffer.size(), lib.metadata, error)) return fail(error);
        lib.name = so_name;
        lib.min_vaddr = lib.metadata.min_vaddr;
        lib.max_vaddr = lib.metadata.max_vaddr;
        const uint64_t total_span = lib.max_vaddr - lib.min_vaddr;
        // Reject an exhausted arena before reserving its checked span.
        if (!vm->library_alloc.can_allocate(total_span)) return fail("library arena exhausted");
        lib.base_address = vm->library_alloc.alloc(total_span);
        auto translate = [&](uint64_t value, uint64_t bytes, uint64_t &address) {
            return elf_metadata_bounds::guest_address(lib.metadata, lib.base_address, value, bytes, address);
        };
        if (!translate(lib.metadata.dynamic, sizeof(Elf64_Dyn), lib.dynamic_address) ||
            !translate(lib.metadata.symtab, lib.metadata.symbol_count * sizeof(Elf64_Sym), lib.symtab) ||
            !translate(lib.metadata.strtab, lib.metadata.strsz, lib.strtab)) return fail("invalid metadata address");
        lib.strsz = static_cast<size_t>(lib.metadata.strsz);
        lib.relasz = lib.metadata.rela.size() * sizeof(Elf64_Rela);
        lib.pltrelsz = lib.metadata.jmprel.size() * sizeof(Elf64_Rela);
        lib.init_arraysz = static_cast<size_t>(lib.metadata.init_arraysz);
        if ((lib.relasz && !translate(lib.metadata.rela_address, lib.relasz, lib.rela)) ||
            (lib.pltrelsz && !translate(lib.metadata.jmprel_address, lib.pltrelsz, lib.jmprel)) ||
            (lib.metadata.init && !translate(lib.metadata.init, 4, lib.init_func)) ||
            (lib.init_arraysz && !translate(lib.metadata.init_array, lib.init_arraysz, lib.init_array)))
            return fail("invalid table address");
        for (size_t index = 0; index < lib.metadata.symbol_count; ++index) {
            if (!owned_attempt_poll(vm)) return fail("attempt stopped");
            Elf64_Sym sym{};
            std::string symbol_name;
            if (!elf_metadata_bounds::symbol(lib.metadata, index, sym) ||
                !elf_metadata_bounds::name(lib.metadata, sym.st_name, symbol_name)) return fail("invalid symbol");
            if (symbol_name.empty() || !elf_metadata_bounds::ordinary_definition(sym)) continue;
            uint64_t address = 0;
            if (!elf_metadata_bounds::definition_address(lib.metadata, lib.base_address, sym, address))
                return fail("invalid export address");
            lib.symbols[symbol_name] = address;
        }
        // No metadata-dependent file access remains unchecked. Keep immutable
        // symbol/string/relocation snapshots so a guest write cannot change
        // parser inputs while relocations are being applied.
        const uc_err map_status = uc_mem_map(vm->uc, lib.base_address, total_span, UC_PROT_ALL);
        if (map_status != UC_ERR_OK) return fail("library mapping failed");
        for (const auto &segment : lib.metadata.loads) {
            uint64_t destination = 0;
            if (!translate(segment.p_vaddr, segment.p_memsz, destination)) return fail("invalid load destination");
            if (segment.p_filesz && uc_mem_write(vm->uc, destination,
                buffer.data() + static_cast<size_t>(segment.p_offset), static_cast<size_t>(segment.p_filesz)) != UC_ERR_OK)
                return fail("segment write failed");
            uint64_t bss_address = 0;
            if (!elf_metadata_bounds::add(destination, segment.p_filesz, bss_address)) return fail("BSS address overflow");
            uint64_t remaining = segment.p_memsz - segment.p_filesz;
            const uint8_t zeros[4096] = {};
            while (remaining) {
                if (!owned_attempt_poll(vm)) return fail("attempt stopped");
                const size_t count = remaining < sizeof(zeros) ? static_cast<size_t>(remaining) : sizeof(zeros);
                if (uc_mem_write(vm->uc, bss_address, zeros, count) != UC_ERR_OK) return fail("BSS write failed");
                bss_address += count;
                remaining -= count;
            }
        }
        vm->loaded_libraries.push_back(std::move(lib));
        return true;
    } catch (const std::exception &) {
        return fail("metadata allocation or read failed");
    }
}

void relocate_all_vm_libraries(EmulatorVM *vm) {
    if (!vm || !vm->uc || vm->initialization_failed) return;
    LOG_UC("[Emulator] Relocating all %zu loaded libraries...\n", vm->loaded_libraries.size());
    try {
        for (auto &lib : vm->loaded_libraries) {
            if (!apply_vm_relocations(vm, lib)) {
                vm->initialization_failed = true;
                return;
            }
        }
    } catch (const std::exception &) {
        vm->initialization_failed = true;
    }
}

bool run_library_constructors(EmulatorVM *vm, vm_initialization_diagnostics::ConstructorFailure *failure) {
    using namespace vm_initialization_diagnostics;
    if (failure) *failure = {};
    if (!vm || !vm->uc || vm->initialization_failed) {
        if (failure) failure->reason = vm && vm->initialization_failed ? Reason::PreviouslyFailed : Reason::InvalidVM;
        return false;
    }
    auto failed = [&](Kind kind, Reason reason, int engine, size_t library, size_t initializer,
                      bounded_fault_diagnostics::Snapshot fault = {}) {
        // Snapshot the first failure before poisoning the VM. No raw pending
        // address escapes into the returned snapshot.
        if (failure) *failure = {kind, reason, engine, ordinal(library), ordinal(initializer), fault};
        vm->initialization_failed = true;
        return false;
    };
    for (size_t library = 0; library < vm->loaded_libraries.size(); ++library) {
        const auto &lib = vm->loaded_libraries[library];
        if (lib.init_func) {
            LOG_UC("[Emulator] Calling DT_INIT at 0x%llx for '%s'...\n",
                   (unsigned long long)lib.init_func, anisette_native_logging::library_label(lib.name.c_str()));
            bool completed = false;
            ProcedureFailure execution;
            run_vm_procedure(vm, lib.init_func, {}, 0, 0, &completed, &execution);
            if (!completed) return failed(Kind::DTInit, execution.reason, execution.engine, library, 0, execution.fault);
        }
        if (lib.init_array && lib.init_arraysz) {
            size_t count = lib.init_arraysz / 8;
            for (size_t i = 0; i < count; i++) {
                uint64_t ctor_ptr = 0;
                const uc_err read_status = uc_mem_read(vm->uc, lib.init_array + i * 8, &ctor_ptr, 8);
                if (read_status != UC_ERR_OK)
                    return failed(Kind::ArrayEntryRead, Reason::EntryRead, static_cast<int>(read_status), library, i);
                if (ctor_ptr != 0) {
                    LOG_UC("[Emulator] Calling DT_INIT_ARRAY[%zu] at 0x%llx for '%s'...\n",
                           i, (unsigned long long)ctor_ptr, anisette_native_logging::library_label(lib.name.c_str()));
                    bool completed = false;
                    ProcedureFailure execution;
                    run_vm_procedure(vm, ctor_ptr, {}, 0, 0, &completed, &execution);
                    if (!completed) return failed(Kind::DTInitArray, execution.reason, execution.engine, library, i, execution.fault);
                }
            }
        }
    }
    return true;
}

uint64_t get_vm_symbol_address(EmulatorVM *vm, const std::string &name) {
    for (const auto &lib : vm->loaded_libraries) {
        auto it = lib.symbols.find(name);
        if (it != lib.symbols.end()) return it->second;
    }
    return 0;
}

int32_t run_vm_procedure(EmulatorVM *vm, uint64_t proc_addr, const std::vector<uint64_t> &args, uint64_t timeout_us, size_t max_count, bool *execution_completed, vm_initialization_diagnostics::ProcedureFailure *failure) {
    using namespace vm_initialization_diagnostics;
    if (execution_completed) *execution_completed = false;
    if (failure) *failure = {};
    if (vm) vm->protection_fault.reset();
    if (!vm || !vm->uc || vm->initialization_failed || !proc_addr) {
        if (failure) failure->reason = vm && vm->initialization_failed ? Reason::PreviouslyFailed : Reason::InvalidVM;
        return -1;
    }
    if (vm->attempt_control) {
        const uint64_t remaining = vm->attempt_control->remaining_us();
        if (!remaining) { vm->initialization_failed = true; return -1007; }
        timeout_us = timeout_us ? std::min(timeout_us, remaining) : remaining;
        max_count = max_count ? std::min(max_count, size_t(50000000)) : size_t(50000000);
    }
    // V3_ISOLATED_ANISETTE_OTP_V1: a temporary VM must not leave a dangling fallback.
    struct ActiveVMScope {
        EmulatorVM *previous;
        explicit ActiveVMScope(EmulatorVM *current) : previous(g_active_vm) { g_active_vm = current; }
        ~ActiveVMScope() { g_active_vm = previous; }
    } active_vm_scope(vm);

    if (vm->read_only_filesystem) {
        if (timeout_us == 0) timeout_us = 5000000;
        if (max_count == 0) max_count = 50000000;
    }

    static const int arm64_arg_regs[8] = {
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7
    };
    for (int i = 0; i < 8; i++) {
        uint64_t zero = 0;
        uc_reg_write(vm->uc, arm64_arg_regs[i], &zero);
    }
    static const int arm64_vregs[32] = {
        UC_ARM64_REG_V0,  UC_ARM64_REG_V1,  UC_ARM64_REG_V2,  UC_ARM64_REG_V3,
        UC_ARM64_REG_V4,  UC_ARM64_REG_V5,  UC_ARM64_REG_V6,  UC_ARM64_REG_V7,
        UC_ARM64_REG_V8,  UC_ARM64_REG_V9,  UC_ARM64_REG_V10, UC_ARM64_REG_V11,
        UC_ARM64_REG_V12, UC_ARM64_REG_V13, UC_ARM64_REG_V14, UC_ARM64_REG_V15,
        UC_ARM64_REG_V16, UC_ARM64_REG_V17, UC_ARM64_REG_V18, UC_ARM64_REG_V19,
        UC_ARM64_REG_V20, UC_ARM64_REG_V21, UC_ARM64_REG_V22, UC_ARM64_REG_V23,
        UC_ARM64_REG_V24, UC_ARM64_REG_V25, UC_ARM64_REG_V26, UC_ARM64_REG_V27,
        UC_ARM64_REG_V28, UC_ARM64_REG_V29, UC_ARM64_REG_V30, UC_ARM64_REG_V31
    };
    uint8_t zero16[16] = {0};
    for (int i = 0; i < 32; i++) {
        uc_reg_write(vm->uc, arm64_vregs[i], zero16);
    }

    for (size_t i = 0; i < args.size() && i < 8; i++) {
        uc_reg_write(vm->uc, arm64_arg_regs[i], &args[i]);
    }

    uint64_t stack_top = kStackAddress + kStackSize - 16;
    uc_reg_write(vm->uc, UC_ARM64_REG_SP, &stack_top);
    uc_reg_write(vm->uc, UC_ARM64_REG_LR, &kReturnAddress);
    uc_reg_write(vm->uc, UC_ARM64_REG_PC, &proc_addr);

    uint32_t first_insn = 0;
    uc_mem_read(vm->uc, proc_addr, &first_insn, 4);
    LOG_UC("[Emulator] Starting emu at 0x%llx (insn=0x%08x), SP=0x%llx, LR=0x%llx...\n",
           (unsigned long long)proc_addr, first_insn, (unsigned long long)stack_top, (unsigned long long)kReturnAddress);

    vm->unsupported_interrupt = false;
    const uc_err engine_status = uc_emu_start(vm->uc, proc_addr, kReturnAddress, timeout_us, max_count);
    uc_err err = engine_status;
    if (err == UC_ERR_OK && vm->unsupported_interrupt) err = UC_ERR_EXCEPTION;

    uint64_t pc = 0;
    const uc_err pc_status = uc_reg_read(vm->uc, UC_ARM64_REG_PC, &pc);
    if (err == UC_ERR_OK && pc_status != UC_ERR_OK) err = pc_status;
    if ((vm->attempt_control && !vm->attempt_control->completed(err == UC_ERR_OK, pc_status == UC_ERR_OK && pc == kReturnAddress)) ||
        vm->initialization_failed || err != UC_ERR_OK || pc != kReturnAddress) {
        if (vm->attempt_control) vm->initialization_failed = true;
        if (failure) {
            failure->reason = vm->unsupported_interrupt ? Reason::UnsupportedInterrupt :
                (err != UC_ERR_OK ? Reason::EngineError : Reason::UnexpectedReturn);
            // Report the real API status, not the synthetic return encoding or W0.
            failure->engine = static_cast<int>(vm->unsupported_interrupt ? engine_status : err);
            // Diagnostics cannot replace the original engine/read status.
            failure->fault = bounded_fault_runtime::snapshot(vm, pc_status == UC_ERR_OK, pc);
        }
        LOG_UC("[Emulator] Execution stopped with status %d: %s at PC=0x%llx (expected 0x%llx)\n",
               (int)err, uc_strerror(err), (unsigned long long)pc, (unsigned long long)kReturnAddress);
        return -1000 - (int32_t)err;
    }

    // Void constructors are successful when execution returned normally;
    // their incidental W0 value is not an initialization status.
    if (execution_completed) *execution_completed = true;
    uint32_t w0_val = 0;
    uc_reg_read(vm->uc, UC_ARM64_REG_W0, &w0_val);
    int32_t ret_val = (int32_t)w0_val;
    LOG_UC("[Emulator] run_vm_procedure exit: proc=0x%llx PC=0x%llx W0=%d err=%d\n",
           (unsigned long long)proc_addr, (unsigned long long)pc, ret_val, (int)err);
    return ret_val;
}
