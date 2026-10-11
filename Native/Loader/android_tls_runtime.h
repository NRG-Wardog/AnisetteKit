#ifndef ANDROID_TLS_RUNTIME_H
#define ANDROID_TLS_RUNTIME_H
#include <unicorn/unicorn.h>
#include <unicorn/arm64.h>
#include <cstdint>
#include <stdexcept>
// Minimal single-emulated-thread Bionic TCB contract. This is not an ELF TLS
// module loader. Keep the null page inaccessible and the guard stable per VM.
namespace android_tls_runtime {
constexpr uint64_t page = 0x72000000;
constexpr uint64_t page_size = 0x10000;
constexpr uint64_t thread_pointer = page + 0x100; // reserve negative TCB slots
constexpr uint64_t guard_address = thread_pointer + 5 * sizeof(uint64_t);
// Bounded entropy retry. A failed entropy source must never hang VM creation
// or silently fall back to a zero/fixed guard. Exceptions are owned by caller.
template<class EntropySource> inline uint64_t make_guard(EntropySource source) {
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        const uint64_t value = source() & ~uint64_t(0xff);
        if (value) return value;
    }
    throw std::runtime_error("Android TLS entropy unavailable");
}
inline bool initialize(uc_engine *uc, uint64_t guard) noexcept {
    if (!uc || !guard) return false;
    if (uc_mem_map(uc, page, page_size, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) return false;
    const uint64_t tp = thread_pointer;
    uint64_t actual_tp = 0, actual_guard = 0;
    const bool okay =
        uc_mem_write(uc, guard_address, &guard, sizeof(guard)) == UC_ERR_OK &&
        uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tp) == UC_ERR_OK &&
        uc_reg_read(uc, UC_ARM64_REG_TPIDR_EL0, &actual_tp) == UC_ERR_OK && actual_tp == tp &&
        uc_mem_read(uc, guard_address, &actual_guard, sizeof(actual_guard)) == UC_ERR_OK && actual_guard == guard;
    if (!okay) {
        const uint64_t zero = 0;
        uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &zero);
        uc_mem_unmap(uc, page, page_size);
    }
    return okay;
}
}
#endif
