#ifndef WORK_QUEUE_ABI_H
#define WORK_QUEUE_ABI_H
#include <cstdint>
#include <string>

namespace work_queue_abi {
// ADI-only compatibility, not a functioning queue implementation. The exact
// imported factory returns a non-trivial two-pointer shared_ptr indirectly in
// X8 on AArch64. A scalar X0=0 does not initialize that result object.
inline constexpr const char *make_work_queue =
    "_ZN13mediaplatform9WorkQueue13makeWorkQueueERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS0_13WorkQueueTypeE";
enum class Operation { Other, EmptyFactory, UnsupportedMedia };
inline Operation classify(const std::string &name) {
    if (name == make_work_queue) return Operation::EmptyFactory;
    // No guessed implementations, exception throwing, or guest callback calls.
    if (name.rfind("_ZN13mediaplatform", 0) == 0 ||
        name.rfind("_ZNK13mediaplatform", 0) == 0)
        return Operation::UnsupportedMedia;
    return Operation::Other;
}
inline bool fits(uint64_t address, uint64_t base, uint64_t size) noexcept {
    return address >= base && size >= 16 && address - base <= size - 16;
}
}
#endif
