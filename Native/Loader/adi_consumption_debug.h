#ifndef ADI_CONSUMPTION_DEBUG_H
#define ADI_CONSUMPTION_DEBUG_H
// DEBUG TEMPORARY. Passive consumer evidence; remove after diagnosis.
// No paths, identifiers, file contents, hashes, FD numbers or guest addresses leave this object.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#ifndef ADI_CONSUMER_DEBUG_ENABLED
#define ADI_CONSUMER_DEBUG_ENABLED 1
#endif
struct ADIConsumptionDebug {
    enum Phase { Unknown, Constructors, LibraryInit, ProvisioningPath, AndroidID, OTP };
    enum Operation { Open, Read };
    enum Target { Other, ExpectedBlob, Relative, Unreadable, Untracked };
    struct Event { int phase, operation, target, result, error; unsigned requested, returned; int copy; };
    struct Descriptor {
        int fd = -1, target = Other;
        uint64_t offset = 0;
        bool offsetKnown = true, copied = true;
    };
    static constexpr unsigned limit = 32, countLimit = 1048576;
    static constexpr unsigned setupLimit = 16, otpLimit = 16;
    Event events[limit] = {};
    Descriptor descriptors[64];
    char expected[4096] = {};
    unsigned count = 0, setupCount = 0, otpCount = 0;
    bool truncated = false;
    Phase phase = Unknown;
    bool expectedValid = false;
    const uint8_t *input = nullptr; // Immutable caller storage, scoped to this invocation.
    uint32_t inputLength = 0;
    unsigned comparison = 0, compared = 0;
    bool inputCovered = false, coverageLost = false;
    ADIConsumptionDebug(const char *root, const uint8_t *id,
        const uint8_t *bytes = nullptr, uint32_t length = 0) noexcept { configure(root,id,bytes,length); }
    void configure(const char *root, const uint8_t *id,
        const uint8_t *bytes = nullptr, uint32_t length = 0) noexcept {
        const int saved = errno;
        expectedValid = false;
        input = bytes && length > 0 && length <= countLimit ? bytes : nullptr;
        inputLength = input ? length : 0;
        if (root && id) {
            int n = snprintf(expected, sizeof(expected), "%s/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x/adi.pb", root,
                id[0],id[1],id[2],id[3],id[4],id[5],id[6],id[7],id[8],id[9],id[10],id[11],id[12],id[13],id[14],id[15]);
            expectedValid = n > 0 && static_cast<size_t>(n) < sizeof(expected);
        }
        errno = saved;
    }
    int target(const char *path, bool complete) const noexcept {
        if (!complete || !expectedValid) return Unreadable;
        if (expectedValid && strcmp(path, expected) == 0) return ExpectedBlob;
        return path[0] == '/' ? Other : Relative;
    }
    static unsigned bounded(uint64_t n) noexcept { return n > countLimit ? countLimit + 1 : static_cast<unsigned>(n); }
    void record(Operation op, int target, int result, int error, uint64_t requested=0, uint64_t returned=0, int copy=-1) noexcept {
#if ADI_CONSUMER_DEBUG_ENABLED
        if (target == Untracked) coverageLost = true;
        if (phase != OTP) {
            if (setupCount == setupLimit) { truncated = true; return; }
            ++setupCount;
        } else if (otpCount == otpLimit) {
            // Keep the latest OTP evidence even after noisy setup or repeated
            // reads. Remove only the oldest OTP row, preserving retained order.
            unsigned oldest = 0;
            while (oldest < count && events[oldest].phase != OTP) ++oldest;
            if (oldest == count) { truncated = true; return; }
            for (unsigned i = oldest + 1; i < count; ++i) events[i - 1] = events[i];
            --count;
            truncated = true;
        } else { ++otpCount; }
        if (count == limit) { truncated = true; return; }
        events[count++] = {phase, op, target, result, error > 0 && error <= 4095 ? error : 0,
            bounded(requested), bounded(returned), copy >= 0 && copy <= 32 ? copy : -1};
#else
        (void)op; (void)target; (void)result; (void)error; (void)requested; (void)returned; (void)copy;
#endif
    }
    void track(int fd, int target, bool offsetKnown = true) noexcept {
        if (fd < 0) { coverageLost = true; return; }
        // Reused descriptor numbers own a new stream, never an old prefix.
        forget(fd);
        for (auto &d : descriptors) if (d.fd == -1) {
            d = {fd,target,0,offsetKnown,true};
            if (target == ExpectedBlob && !offsetKnown) coverageLost = true;
            return;
        }
        truncated = true;
        coverageLost = true;
    }
    int lookup(int fd) const noexcept { for (const auto &d : descriptors) if (d.fd >= 0 && d.fd == fd) return d.target; return Untracked; }
    void forget(int fd) noexcept { for (auto &d : descriptors) if (d.fd >= 0 && d.fd == fd) { d.fd = -1; return; } }
    void invalidateOffset(int fd) noexcept {
        for (auto &d : descriptors) if (d.fd >= 0 && d.fd == fd) {
            d.offsetKnown = false;
            if (d.target == ExpectedBlob) coverageLost = true;
            return;
        }
        coverageLost = true;
    }
    void observeRead(int fd, const uint8_t *hostBytes, uint64_t returned, int copy) noexcept {
#if ADI_CONSUMER_DEBUG_ENABLED
        const int saved = errno;
        Descriptor *stream = nullptr;
        for (auto &d : descriptors) if (d.fd >= 0 && d.fd == fd) { stream = &d; break; }
        if (!stream) { coverageLost = true; errno = saved; return; }
        if (stream->target != ExpectedBlob || !returned) { errno = saved; return; }
        if (!stream->offsetKnown || returned > UINT64_MAX - stream->offset) {
            stream->offsetKnown = false; coverageLost = true; errno = saved; return;
        }
        const uint64_t offset = stream->offset;
        stream->offset += returned;
        if (copy != 0) { stream->copied = false; coverageLost = true; }
        if (!input || !hostBytes) { coverageLost = true; errno = saved; return; }
        const uint64_t available = offset < inputLength ? inputLength - offset : 0;
        const uint64_t overlap = returned < available ? returned : available;
        const uint64_t budget = countLimit - compared;
        const size_t examine = static_cast<size_t>(overlap < budget ? overlap : budget);
        if (examine) {
            if (memcmp(hostBytes, input + static_cast<size_t>(offset), examine) != 0) comparison = 2;
            else if (comparison == 0) comparison = 1;
            compared += static_cast<unsigned>(examine);
        }
        // More observed bytes than the supplied input cannot match that input.
        // Coverage alone never establishes EOF, file length or ADI validity.
        if (returned > available) comparison = 2;
        if (examine < overlap) coverageLost = true;
        if (comparison == 1 && stream->offset == inputLength && stream->copied && examine == overlap)
            inputCovered = true;
        errno = saved;
#else
        (void)fd; (void)hostBytes; (void)returned; (void)copy;
#endif
    }
    unsigned coverage() const noexcept {
        return comparison == 1 && inputCovered && !coverageLost && !truncated ? 1u : 0u;
    }
    void append(char **output) const noexcept {
#if ADI_CONSUMER_DEBUG_ENABLED
        const int saved = errno;
        if (!output || !*output) return;
        const size_t n = strlen(*output);
        if (n < 2 || (*output)[0] != '{' || (*output)[n-1] != '}') return;
        char encoded[2048] = {};
        size_t used = static_cast<size_t>(snprintf(encoded,sizeof(encoded),"v2|%u|%u|%u",truncated ? 1u : 0u,comparison,coverage()));
        for (unsigned i=0;i<count;++i) {
            const auto &e=events[i];
            int written=snprintf(encoded+used,sizeof(encoded)-used,"|%d,%d,%d,%d,%d,%u,%u,%d",e.phase,e.operation,e.target,e.result,e.error,e.requested,e.returned,e.copy);
            if (written < 0 || static_cast<size_t>(written) >= sizeof(encoded)-used) { errno=saved; return; }
            used+=static_cast<size_t>(written);
        }
        const char prefix[]=",\"v3_native_consumption\":\"";
        char *combined=static_cast<char *>(malloc(n+sizeof(prefix)+used+3));
        if (combined) {
            memcpy(combined,*output,n-1);size_t cursor=n-1;
            memcpy(combined+cursor,prefix,sizeof(prefix)-1);cursor+=sizeof(prefix)-1;
            memcpy(combined+cursor,encoded,used);cursor+=used;
            memcpy(combined+cursor,"\"}",3);free(*output);*output=combined;
        }
        errno=saved;
#else
        (void)output;
#endif
    }
};
inline thread_local ADIConsumptionDebug *activeADIConsumptionDebug = nullptr;
struct ADIConsumptionScope {
    ADIConsumptionDebug *previous;
    explicit ADIConsumptionScope(ADIConsumptionDebug *current) noexcept : previous(activeADIConsumptionDebug) {
#if ADI_CONSUMER_DEBUG_ENABLED
        activeADIConsumptionDebug=current;
#else
        (void)current;
#endif
    }
    ~ADIConsumptionScope() { activeADIConsumptionDebug=previous; }
};
inline void adiConsumptionPhase(ADIConsumptionDebug::Phase phase) noexcept {
    if (activeADIConsumptionDebug) activeADIConsumptionDebug->phase=phase;
}
#endif
