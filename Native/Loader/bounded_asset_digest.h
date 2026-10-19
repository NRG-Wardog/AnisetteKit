#ifndef BOUNDED_ASSET_DIGEST_H
#define BOUNDED_ASSET_DIGEST_H
#include "bounded_fault_diagnostics.h"
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#endif
namespace bounded_fault_diagnostics {
// The template is also tested with an explicitly host-only system hash adapter.
// A platform failure becomes unknown; never reopen a path or change load status.
template<class Hasher>
inline Digest digest_buffer(const uint8_t *data, size_t size, Hasher &hash) noexcept {
    Digest result;
    if ((!data && size) || !hash.begin()) return result;
    size_t offset = 0;
    while (offset < size) {
        const size_t left = size - offset;
        const size_t count = left < 65536 ? left : 65536;
        if (!hash.update(data + offset, count)) return result;
        offset += count;
    }
    if (!hash.finish(result.bytes)) return {};
    result.known = true;
    return result;
}
inline Digest loaded_buffer_digest(const uint8_t *data, size_t size) noexcept {
#if defined(__APPLE__)
    struct PlatformHash {
        CC_SHA256_CTX context;
        bool begin() noexcept { return CC_SHA256_Init(&context) == 1; }
        bool update(const uint8_t *p, size_t n) noexcept {
            return n <= 65536 && CC_SHA256_Update(&context, p, static_cast<CC_LONG>(n)) == 1;
        }
        bool finish(uint8_t *out) noexcept { return CC_SHA256_Final(out, &context) == 1; }
    } hash;
    return digest_buffer(data, size, hash);
#else
    // No production OpenSSL dependency and no invented digest on other systems.
    (void)data; (void)size;
    return {};
#endif
}
}
#endif
