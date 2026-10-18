#ifndef CXX_ALLOCATION_RUNTIME_H
#define CXX_ALLOCATION_RUNTIME_H
#include <cstdint>
#include <string>

// Exact AArch64 Itanium ABI entry points only. Aligned/nothrow overloads
// have different contracts and are deliberately not treated as these forms.
namespace cxx_allocation_runtime {
enum class Operation { Other, New, Delete };
inline Operation classify(const std::string &name) {
    if (name == "_Znwm" || name == "_Znam") return Operation::New;
    if (name == "_ZdlPv" || name == "_ZdaPv" ||
        name == "_ZdlPvm" || name == "_ZdaPvm") return Operation::Delete;
    return Operation::Other;
}
// The VM heap is a 64-byte-aligned monotonic arena. The throwing new forms
// must never return null and continue executing. The caller stops the VM on
// false because guest C++ exception unwinding is not implemented here.
// Successful zero-size new still consumes one distinct allocation.
template<class Allocator>
inline bool allocate(Allocator &heap, uint64_t size, uint64_t &result) {
    result = 0;
    const uint64_t bytes = size == 0 ? 1 : size;
    if (!heap.can_allocate(bytes)) return false;
    result = heap.alloc(bytes);
    return result != 0;
}
} // namespace cxx_allocation_runtime
#endif
