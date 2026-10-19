#ifndef BOUNDED_FAULT_DIAGNOSTICS_H
#define BOUNDED_FAULT_DIAGNOSTICS_H
#include <cstddef>
#include <cstdint>
#include <cstdio>

// Finite observations, never a dump. Raw pending addresses stay internal and
// are erased before the next call. Serialization accepts only this typed copy.
namespace bounded_fault_diagnostics {
enum class Access { Unknown, ReadProtection, WriteProtection, FetchProtection };
enum class Region { Unknown, LowGuard, Heap, Stack, TLS, Errno, Library, Other };
enum class Guard { Unknown, Intact, Changed };
struct Digest { bool known = false; uint8_t bytes[32] = {}; };
struct Pending {
    bool seen = false;
    Access access = Access::Unknown;
    uint64_t address = 0;
    int width = -1;
    void reset() noexcept { *this = {}; }
    void record(Access kind, uint64_t target, int size) noexcept {
        if (seen || kind == Access::Unknown) return;
        seen = true; access = kind; address = target;
        width = size >= 1 && size <= 256 ? size : -1;
    }
};
struct Snapshot {
    bool available = false;
    Access access = Access::Unknown;
    int width = -1;
    Region region = Region::Unknown;
    int pc_library = -1;
    int64_t pc_offset = -1;
    Guard guard = Guard::Unknown;
    Digest assets[2]; // loaded-library ordinals 0 and 1, not names or paths
};
inline bool contains(uint64_t base, uint64_t span, uint64_t address, uint64_t size) noexcept {
    return span && span <= UINT64_MAX - base && size && address >= base &&
        address - base < span && size <= span - (address - base);
}
inline Snapshot normalized(Snapshot value) noexcept {
    if (!value.available) return {};
    switch (value.access) {
    case Access::ReadProtection: case Access::WriteProtection: case Access::FetchProtection: break;
    default: value.access = Access::Unknown; value.width = -1; value.region = Region::Unknown; break;
    }
    if (value.width < 1 || value.width > 256) { value.width = -1; value.region = Region::Unknown; }
    switch (value.region) {
    case Region::LowGuard: case Region::Heap: case Region::Stack: case Region::TLS:
    case Region::Errno: case Region::Library: case Region::Other: break;
    default: value.region = Region::Unknown; break;
    }
    if (value.pc_library < 0 || value.pc_library > 65535 || value.pc_offset < 0 ||
        value.pc_offset >= 0x30000000) { value.pc_library = -1; value.pc_offset = -1; }
    switch (value.guard) {
    case Guard::Intact: case Guard::Changed: break;
    default: value.guard = Guard::Unknown; break;
    }
    return value;
}
inline void digest_text(const Digest &digest, char (&out)[65]) noexcept {
    if (!digest.known) { out[0] = '-'; out[1] = 0; return; }
    static constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = hex[digest.bytes[i] >> 4]; out[i * 2 + 1] = hex[digest.bytes[i] & 15];
    }
    out[64] = 0;
}
constexpr size_t wire_capacity = 256;
inline bool encode(Snapshot value, char (&out)[wire_capacity]) noexcept {
    out[0] = 0;
    value = normalized(value);
    if (!value.available) return false;
    char first[65] = {}, second[65] = {};
    digest_text(value.assets[0], first); digest_text(value.assets[1], second);
    const int n = std::snprintf(out, sizeof(out), "v1;p0_fault_diag1;%d;%d;%d;%d;%lld;%d;%s;%s",
        static_cast<int>(value.access), value.width, static_cast<int>(value.region),
        value.pc_library, static_cast<long long>(value.pc_offset), static_cast<int>(value.guard), first, second);
    if (n < 0 || static_cast<size_t>(n) >= sizeof(out)) { out[0] = 0; return false; }
    return true;
}
} // namespace bounded_fault_diagnostics
#endif
