#ifndef BOUNDED_FAULT_RUNTIME_H
#define BOUNDED_FAULT_RUNTIME_H
#include "elf_loader_emulator.h"
#include "android_tls_runtime.h"
namespace bounded_fault_runtime {
using namespace bounded_fault_diagnostics;
inline bool library_span(const EmulatorVM::LibraryInfo &lib, uint64_t &span) noexcept {
    if (lib.max_vaddr <= lib.min_vaddr) return false;
    span = lib.max_vaddr - lib.min_vaddr;
    return contains(kLibraryAddress, kLibrarySize, lib.base_address, span);
}
inline Region target_region(const EmulatorVM *vm, uint64_t address, int width) noexcept {
    if (width < 1 || width > 256 || uint64_t(width) > UINT64_MAX - address) return Region::Unknown;
    if (contains(0, 0x10000, address, width)) return Region::LowGuard;
    if (contains(kHeapAddress, kHeapSize, address, width)) return Region::Heap;
    if (contains(kStackAddress, kStackSize, address, width)) return Region::Stack;
    if (contains(android_tls_runtime::page, android_tls_runtime::page_size, address, width)) return Region::TLS;
    if (contains(vm->errno_addr, 0x10000, address, width)) return Region::Errno;
    // Cross-region accesses are unknown, never represented by an arbitrary offset.
    const uint64_t bases[] = {0, kHeapAddress, kStackAddress, android_tls_runtime::page, vm->errno_addr};
    const uint64_t spans[] = {0x10000, kHeapSize, kStackSize, android_tls_runtime::page_size, 0x10000};
    for (size_t i = 0; i < 5; ++i)
        if (contains(bases[i], spans[i], address, 1) || contains(bases[i], spans[i], address + width - 1, 1)) return Region::Unknown;
    if (vm->loaded_libraries.size() > 65536) return Region::Unknown;
    unsigned matches = 0;
    bool crossing = false;
    for (const auto &lib : vm->loaded_libraries) {
        uint64_t span = 0;
        if (!library_span(lib, span)) continue;
        if (contains(lib.base_address, span, address, width)) ++matches;
        else if (contains(lib.base_address, span, address, 1) || contains(lib.base_address, span, address + width - 1, 1)) crossing = true;
    }
    if (crossing || matches > 1) return Region::Unknown;
    return matches == 1 ? Region::Library : Region::Other;
}
inline Guard low_guard(uc_engine *uc) noexcept {
    uc_mem_region *regions = nullptr;
    uint32_t count = 0;
    const uc_err status = uc_mem_regions(uc, &regions, &count);
    Guard result = Guard::Unknown;
    if (status == UC_ERR_OK && regions && count <= 256) {
        // Validate the complete bounded list before deciding. Malformed or
        // ambiguous metadata wins over Changed, independent of region order.
        bool malformed = false, covered = false, accessible = false;
        unsigned low_regions = 0;
        for (uint32_t i = 0; i < count; ++i) {
            const auto &r = regions[i];
            if (r.begin > r.end || (r.perms & ~uint32_t(UC_PROT_ALL))) {
                malformed = true;
                continue;
            }
            // Ends are inclusive. Even an overlap away from the low page makes
            // this metadata response unreliable; no guest memory is accessed.
            for (uint32_t j = 0; j < i; ++j) {
                const auto &prior = regions[j];
                if (prior.begin <= prior.end && r.begin <= prior.end && prior.begin <= r.end)
                    malformed = true;
            }
            if (r.begin >= 0x10000) continue;
            ++low_regions;
            if (r.perms != UC_PROT_NONE) accessible = true;
            if (r.begin == 0 && r.end >= 0xffff) covered = true;
        }
        if (!malformed && low_regions == 1) {
            if (accessible) result = Guard::Changed;
            else if (covered) result = Guard::Intact;
        }
    }
    if (regions) uc_free(regions);
    return result;
}
inline Snapshot snapshot(const EmulatorVM *vm, bool pc_known, uint64_t pc) noexcept {
    Snapshot value;
    value.available = true;
    value.access = vm->protection_fault.access;
    value.width = vm->protection_fault.width;
    if (vm->protection_fault.seen)
        value.region = target_region(vm, vm->protection_fault.address, value.width);
    if (pc_known && vm->loaded_libraries.size() <= 65536) {
        unsigned matches = 0;
        for (size_t i = 0; i < vm->loaded_libraries.size(); ++i) {
            const auto &lib = vm->loaded_libraries[i];
            uint64_t span = 0;
            if (library_span(lib, span) && contains(lib.base_address, span, pc, 1)) {
                ++matches; value.pc_library = static_cast<int>(i);
                value.pc_offset = static_cast<int64_t>(pc - lib.base_address);
            }
        }
        if (matches != 1) { value.pc_library = -1; value.pc_offset = -1; }
    }
    for (size_t i = 0; i < 2 && i < vm->loaded_libraries.size(); ++i) value.assets[i] = vm->loaded_libraries[i].asset_digest;
    value.guard = low_guard(vm->uc);
    return normalized(value);
}
}
#endif
