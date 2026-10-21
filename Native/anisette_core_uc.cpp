//
//  anisette_core_uc.cpp
//  AnisetteKit
//
//  Created by Magesh K on 25/07/26.
//  Copyright © 2026 Magesh K. All rights reserved.
//

#include "anisette_core.h"
#include "anisette_base.h"
#include "Loader/elf_loader_emulator.h"
#include "Loader/adi_consumption_debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#if !defined(_WIN32) && !defined(_MSC_VER)
#include <unistd.h>
#endif
#include <sys/stat.h>

#if defined(_WIN32) || defined(_MSC_VER)
#define NOMINMAX
#include <io.h>
#include <direct.h>
#define mkdir(p, m) _mkdir(p)
#define rmdir _rmdir
#define stat _stat64
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#endif
#include <string>
#include <vector>
#include <sstream>
#include <mutex>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <errno.h>
#include <chrono>

#define V3_TEMPORARY_ANISETTE_TRACE_ENABLED 1
// DEBUG/TEMPORARY: remove after the Anisette failure is diagnosed.
// The build reads V3TemporaryAnisetteTrace.temporaryAnisetteTraceEnabled.
// This trace belongs to one native call; it never contains data from the call.
enum class NativeOTPStage {
    ArgumentsOK, ArgumentsFailed, RootOK, RootFailed,
    DirectoryCreated, DirectoryExists, DirectoryFailed,
    FileOpenOK, FileOpenFailed, FileStreamOK, FileStreamFailed,
    FileWriteOK, FileWriteFailed, FileFlushOK, FileFlushFailed, FileFlushUnchecked,
    FileCloseOK, FileCloseFailed, FileReadOpenOK, FileReadOpenFailed,
    FileReadbackOK, FileReadbackFailed, FileReadbackUnchecked,
    FileReadCloseOK, FileReadCloseFailed, FileRenameOK, FileRenameFailed,
    VMInitOK, VMInitFailed, VMReused, SetupBegin, SetupOK, SetupFailed,
    LibraryLoadOK, LibraryLoadFailed, LibraryCached, LibraryInitOK, LibraryInitFailed,
    ProvisioningPathOK, ProvisioningPathFailed, ProvisioningPathCached,
    AndroidIDOK, AndroidIDFailed, AndroidIDCached,
    NativeSymbolOK, NativeSymbolFailed, NativeOTPOK, NativeOTPFailed, NativeStartOK, NativeStartFailed, NativeEndOK, NativeEndFailed,
    NativeOutputOK, NativeOutputFailed, NativeOutputUnchecked,
    CleanupOK, CleanupFailed, CleanupNotNeeded, CleanupNotRequested, ResponseAllocationFailed, Truncated
};

struct NativeOTPTrace {
    // Reserve the final entry for a truncation marker. No dynamic allocation
    // occurs during recording, including cleanup and exceptional exits.
    static constexpr size_t max_events = 32, max_bytes = 1024;
    char value[max_bytes + 1] = {};
    size_t count = 0, length = 0;
    char **output;
    char constructor_fault[bounded_fault_diagnostics::wire_capacity] = {};
    void record_constructor_fault(const vm_initialization_diagnostics::ConstructorFailure &failure) noexcept {
        bounded_fault_diagnostics::encode(vm_initialization_diagnostics::normalized(failure).fault, constructor_fault);
    }
    using Clock = std::chrono::steady_clock;
    Clock::time_point began = Clock::now();
    char timing[2049] = {};
    size_t timing_length = 0, timing_count = 0;
    bool timing_truncated = false;
    static uint64_t ms(Clock::time_point end, Clock::time_point begin) noexcept {
        const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
        return value < 0 ? 0 : std::min<uint64_t>(static_cast<uint64_t>(value), 86400000);
    }
    void timed(int stage, int outcome, Clock::time_point start) noexcept {
        if (stage < 0) return;
        if (timing_count >= 64) { timing_truncated = true; return; }
        const auto now = Clock::now();
        char row[80];
        const int n = snprintf(row, sizeof(row), "%s%d,%d,%llu,%llu", timing_count ? ";" : "",
            stage, outcome, static_cast<unsigned long long>(ms(now, began)),
            static_cast<unsigned long long>(ms(now, start)));
        if (n < 0 || static_cast<size_t>(n) >= sizeof(row) || timing_length + n >= sizeof(timing)) {
            timing_truncated = true; return;
        }
        memcpy(timing + timing_length, row, n + 1); timing_length += n; ++timing_count;
    }
    explicit NativeOTPTrace(char **out) : output(out) {}

    void add(NativeOTPStage stage) noexcept {
#if V3_TEMPORARY_ANISETTE_TRACE_ENABLED
        if (stage == NativeOTPStage::VMReused) timed(1, 3, Clock::now());
        if (stage == NativeOTPStage::LibraryCached) timed(2, 3, Clock::now());
        if (stage == NativeOTPStage::ProvisioningPathCached) timed(4, 3, Clock::now());
        if (stage == NativeOTPStage::AndroidIDCached) timed(5, 3, Clock::now());
        if (stage == NativeOTPStage::NativeOutputUnchecked) timed(8, 3, Clock::now());
        if (stage == NativeOTPStage::CleanupNotRequested || stage == NativeOTPStage::CleanupNotNeeded) timed(9, 3, Clock::now());
        static const char *const tokens[] = {
            "arguments.ok", "arguments.failed", "root.ok", "root.failed",
            "uuid_dir.created", "uuid_dir.exists", "uuid_dir.failed",
            "file.open.ok", "file.open.failed", "file.stream.ok", "file.stream.failed",
            "file.write.ok", "file.write.failed", "file.flush.ok", "file.flush.failed", "file.flush.not_checked",
            "file.close.ok", "file.close.failed", "file.read_open.ok", "file.read_open.failed",
            "file.readback.ok", "file.readback.failed", "file.readback.not_checked",
            "file.read_close.ok", "file.read_close.failed", "file.rename.ok", "file.rename.failed",
            "vm.init.ok", "vm.init.failed", "vm.reused", "setup.begin", "setup.ok", "setup.failed",
            "library.load.ok", "library.load.failed", "library.cached", "library.init.ok", "library.init.failed",
            "provisioning_path.ok", "provisioning_path.failed", "provisioning_path.cached",
            "android_id.ok", "android_id.failed", "android_id.cached",
            "native.symbol.ok", "native.symbol.failed", "native.otp.ok", "native.otp.failed", "native.start.ok", "native.start.failed", "native.end.ok", "native.end.failed",
            "native.output.ok", "native.output.failed", "native.output.not_checked",
            "cleanup.ok", "cleanup.failed", "cleanup.not_needed", "cleanup.not_requested", "response.allocation.failed", "trace.truncated"
        };
        const size_t index = static_cast<size_t>(stage);
        if (index >= sizeof(tokens) / sizeof(tokens[0]) || count >= max_events) return;
        const char *token = tokens[index];
        if (count == max_events - 1 || length + strlen(token) + 1 > max_bytes - 16)
            token = "trace.truncated";
        const size_t size = strlen(token);
        if (length + size + (count ? 1 : 0) > max_bytes) return;
        if (count) value[length++] = ',';
        memcpy(value + length, token, size + 1);
        length += size;
        ++count;
        if (strcmp(token, "trace.truncated") == 0) count = max_events;
#else
        (void)stage;
#endif
    }

    ~NativeOTPTrace() noexcept {
#if V3_TEMPORARY_ANISETTE_TRACE_ENABLED
        if (!count || !output || !*output) return;
        const size_t original_length = strlen(*output);
        if (original_length < 2 || (*output)[0] != '{' || (*output)[original_length - 1] != '}') return;
        // This is private metadata, removed by Swift before constructing headers.
        // All trace bytes come from the finite literal table above.
        const char prefix[] = ",\"v3_native_trace\":\"";
        const char fault_prefix[] = ",\"v3_constructor_fault\":\"";
        const size_t fault_length = strlen(constructor_fault);
        const char timing_prefix[] = ",\"v3_login_native_trace\":\"v1;";
        char *combined = static_cast<char *>(malloc(original_length + sizeof(prefix) + length +
            sizeof(timing_prefix) + timing_length + sizeof(fault_prefix) + fault_length + 12));
        if (!combined) return; // Diagnostics must not change the original result.
        memcpy(combined, *output, original_length - 1);
        size_t cursor = original_length - 1;
        memcpy(combined + cursor, prefix, sizeof(prefix) - 1); cursor += sizeof(prefix) - 1;
        memcpy(combined + cursor, value, length); cursor += length;
        combined[cursor++] = '"';
        if (timing_count) {
            memcpy(combined + cursor, timing_prefix, sizeof(timing_prefix) - 1); cursor += sizeof(timing_prefix) - 1;
            combined[cursor++] = timing_truncated ? '1' : '0';
            combined[cursor++] = ';';
            memcpy(combined + cursor, timing, timing_length); cursor += timing_length;
            combined[cursor++] = '"';
        }
        if (fault_length) {
            memcpy(combined + cursor, fault_prefix, sizeof(fault_prefix) - 1); cursor += sizeof(fault_prefix) - 1;
            memcpy(combined + cursor, constructor_fault, fault_length); cursor += fault_length;
            combined[cursor++] = '"';
        }
        memcpy(combined + cursor, "}", 2);
        free_c_string(*output);
        *output = combined;
#endif
    }
};

struct NativeOTPStageScope {
    NativeOTPTrace *trace;
    NativeOTPStage failure;
    bool completed = false;
    NativeOTPTrace::Clock::time_point started = NativeOTPTrace::Clock::now();
    int diagnostic_stage;
    static int stage_id(NativeOTPStage failed) noexcept {
        switch (failed) {
        case NativeOTPStage::SetupFailed: return 0;
        case NativeOTPStage::VMInitFailed: return 1;
        case NativeOTPStage::LibraryLoadFailed: return 2;
        case NativeOTPStage::LibraryInitFailed: return 3;
        case NativeOTPStage::ProvisioningPathFailed: return 4;
        case NativeOTPStage::AndroidIDFailed: return 5;
        case NativeOTPStage::NativeSymbolFailed: return 6;
        case NativeOTPStage::NativeOTPFailed: return 7;
        case NativeOTPStage::NativeOutputFailed: return 8;
        case NativeOTPStage::CleanupFailed: return 9;
        case NativeOTPStage::NativeStartFailed: return 10;
        case NativeOTPStage::NativeEndFailed: return 11;
        default: return -1;
        }
    }
    NativeOTPStageScope(NativeOTPTrace *owner, NativeOTPStage failed)
        : trace(owner), failure(failed), diagnostic_stage(stage_id(failed)) {
        if (trace) trace->timed(diagnostic_stage, 0, started);
    }
    void finish(NativeOTPStage outcome) noexcept {
        if (trace) { trace->add(outcome); trace->timed(diagnostic_stage, outcome == failure ? 2 : 1, started); }
        completed = true;
    }
    ~NativeOTPStageScope() { if (!completed && trace) { trace->add(failure); trace->timed(diagnostic_stage, 2, started); } }
};

// Numeric-only timing scopes refine the existing broad library.init token.
struct NativeLoginTimingScope {
    NativeOTPTrace *trace;
    int stage;
    NativeOTPTrace::Clock::time_point started = NativeOTPTrace::Clock::now();
    bool completed = false;
    NativeLoginTimingScope(NativeOTPTrace *owner, int value) : trace(owner), stage(value) {
        if (trace) trace->timed(stage, 0, started);
    }
    void finish() noexcept { if (trace) trace->timed(stage, 1, started); completed = true; }
    ~NativeLoginTimingScope() { if (!completed && trace) trace->timed(stage, 2, started); }
};

// The active normal-provider fix. This does not replace its VM or identity.
#if defined(__GNUC__)
__attribute__((used))
#endif
extern const char v3_checked_anisette_staging_marker[] = "V3_CHECKED_ANISETTE_STAGING_V1";

struct CheckedAnisetteStagingFailure {
    bool failed = false;
    int posix_error = 0;
    void record(int actual_errno) noexcept {
        if (failed) return;
        failed = true;
        if (actual_errno > 0 && actual_errno <= 4095) posix_error = actual_errno;
    }
    std::string message() const {
        if (!posix_error) return "Checked OTP staging failed";
        return "Checked OTP staging failed (errno " + std::to_string(posix_error) + ")";
    }
};

#if !defined(_WIN32) && !defined(_MSC_VER)
static int checked_anisette_make_uuid_directory(const char *root, const uint8_t *identifier,
    CheckedAnisetteStagingFailure &failure) {
    // Refuse a linked or unsafe root before creating the normal OTP UUID child.
    const std::string uuid = format_uuid_string(identifier);
    const int descriptor = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) { failure.record(errno); return -1; }
    struct stat identity;
    if (fstat(descriptor, &identity) != 0) {
        failure.record(errno); close(descriptor); errno = EPERM; return -1;
    }
    if (!S_ISDIR(identity.st_mode) || identity.st_uid != geteuid() || (identity.st_mode & 0022) != 0) {
        failure.record(0);
        close(descriptor); errno = EPERM; return -1;
    }
    const int result = mkdirat(descriptor, uuid.c_str(), 0755);
    const int saved_errno = errno;
    if (result != 0 && saved_errno != EEXIST) failure.record(saved_errno);
    close(descriptor);
    errno = saved_errno;
    return result;
}

struct CheckedAnisetteStagingFile {
    int root = -1, directory = -1;
    bool owns_temporary = false;
    struct stat temporary_identity = {};
    char temporary_name[96] = {};

    bool remove_owned_temporary() noexcept {
        if (!owns_temporary) return true;
        struct stat current;
        if (fstatat(directory, temporary_name, &current, AT_SYMLINK_NOFOLLOW) != 0)
            return errno == ENOENT;
        if (!S_ISREG(current.st_mode) || current.st_dev != temporary_identity.st_dev ||
            current.st_ino != temporary_identity.st_ino) return false;
        if (unlinkat(directory, temporary_name, 0) != 0) return false;
        owns_temporary = false;
        return true;
    }
    ~CheckedAnisetteStagingFile() {
        remove_owned_temporary();
        if (directory >= 0) close(directory);
        if (root >= 0) close(root);
    }
};

static bool checked_anisette_staging(const char *root, const uint8_t *identifier,
    const uint8_t *bytes, uint32_t length, NativeOTPTrace &trace, CheckedAnisetteStagingFailure &failure) {
    CheckedAnisetteStagingFile owned;
    const std::string uuid = format_uuid_string(identifier);
    struct stat root_identity, directory_identity;
    owned.root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (owned.root < 0) failure.record(errno);
    bool root_ok = owned.root >= 0;
    if (root_ok && fstat(owned.root, &root_identity) != 0) { failure.record(errno); root_ok = false; }
    if (root_ok && (!S_ISDIR(root_identity.st_mode) || root_identity.st_uid != geteuid() ||
        (root_identity.st_mode & 0022) != 0)) { failure.record(0); root_ok = false; }
    trace.add(root_ok ? NativeOTPStage::RootOK : NativeOTPStage::RootFailed);
    if (!root_ok) return false;
    owned.directory = openat(owned.root, uuid.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (owned.directory < 0) failure.record(errno);
    bool directory_ok = owned.directory >= 0;
    if (directory_ok && fstat(owned.directory, &directory_identity) != 0) { failure.record(errno); directory_ok = false; }
    if (directory_ok && (!S_ISDIR(directory_identity.st_mode) || directory_identity.st_uid != geteuid() ||
        (directory_identity.st_mode & 0022) != 0)) { failure.record(0); directory_ok = false; }
    trace.add(directory_ok ? NativeOTPStage::DirectoryExists : NativeOTPStage::DirectoryFailed);
    if (!directory_ok) return false;

    // All names below are bounded leaf names relative to the verified UUID dir.
    // Never follow or overwrite a linked/special destination, and never remove
    // the previous usable adi.pb until the checked temporary is promoted.
    auto destination_ok = [&]() {
        struct stat destination;
        if (fstatat(owned.directory, kADISymbols.adi_pb_filename, &destination, AT_SYMLINK_NOFOLLOW) != 0) {
            const int result_errno = errno;
            if (result_errno == ENOENT) return true;
            failure.record(result_errno); return false;
        }
        const bool okay = S_ISREG(destination.st_mode) && destination.st_uid == geteuid() && destination.st_nlink == 1;
        if (!okay) failure.record(0);
        return okay;
    };
    if (!destination_ok()) { trace.add(NativeOTPStage::FileOpenFailed); return false; }
    // The normal native mutex protects this counter. Never reuse another call's
    // leaf, including a partial file left behind by process termination.
    static uint64_t next_temporary = 0;
    int descriptor = -1;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        snprintf(owned.temporary_name, sizeof(owned.temporary_name), ".adi.pb.checked-%ld-%llu",
            static_cast<long>(getpid()), static_cast<unsigned long long>(next_temporary++));
        descriptor = openat(owned.directory, owned.temporary_name,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (descriptor >= 0) break;
        const int open_errno = errno;
        if (open_errno != EEXIST || attempt == 15) { failure.record(open_errno); break; }
    }
    trace.add(descriptor >= 0 ? NativeOTPStage::FileOpenOK : NativeOTPStage::FileOpenFailed);
    if (descriptor < 0) return false;
    const int temporary_stat = fstat(descriptor, &owned.temporary_identity);
    if (temporary_stat != 0) failure.record(errno);
    if (temporary_stat != 0 || !S_ISREG(owned.temporary_identity.st_mode) ||
        owned.temporary_identity.st_uid != geteuid() || owned.temporary_identity.st_nlink != 1) {
        failure.record(0);
        close(descriptor);
        trace.add(NativeOTPStage::FileStreamFailed);
        return false;
    }
    owned.owns_temporary = true;
    FILE *file = fdopen(descriptor, "wb");
    if (!file) failure.record(errno);
    trace.add(file ? NativeOTPStage::FileStreamOK : NativeOTPStage::FileStreamFailed);
    if (!file) {
        const int closed = close(descriptor);
        trace.add(closed == 0 ? NativeOTPStage::FileCloseOK : NativeOTPStage::FileCloseFailed);
        return false;
    }
    // Clear errno before stdio calls whose short result can be semantic rather
    // than a POSIX error. Never attach a prior operation's stale errno.
    errno = 0;
    bool okay = fwrite(bytes, 1, length, file) == length;
    if (!okay) failure.record(errno);
    trace.add(okay ? NativeOTPStage::FileWriteOK : NativeOTPStage::FileWriteFailed);
    errno = 0;
    const int flushed = fflush(file);
    if (flushed != 0) failure.record(errno);
    trace.add(flushed == 0 ? NativeOTPStage::FileFlushOK : NativeOTPStage::FileFlushFailed);
    errno = 0;
    const int closed = fclose(file);
    if (closed != 0) failure.record(errno);
    trace.add(closed == 0 ? NativeOTPStage::FileCloseOK : NativeOTPStage::FileCloseFailed);
    if (!okay || flushed != 0 || closed != 0) return false;

    descriptor = openat(owned.directory, owned.temporary_name,
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) failure.record(errno);
    trace.add(descriptor >= 0 ? NativeOTPStage::FileReadOpenOK : NativeOTPStage::FileReadOpenFailed);
    if (descriptor < 0) return false;
    struct stat read_identity;
    const int read_stat = fstat(descriptor, &read_identity);
    if (read_stat != 0) failure.record(errno);
    okay = read_stat == 0 && S_ISREG(read_identity.st_mode) &&
        read_identity.st_dev == owned.temporary_identity.st_dev &&
        read_identity.st_ino == owned.temporary_identity.st_ino && read_identity.st_nlink == 1;
    if (!okay) failure.record(0);
    file = fdopen(descriptor, "rb");
    if (!file) {
        failure.record(errno);
        const int read_closed = close(descriptor);
        trace.add(NativeOTPStage::FileReadbackFailed);
        trace.add(read_closed == 0 ? NativeOTPStage::FileReadCloseOK : NativeOTPStage::FileReadCloseFailed);
        return false;
    }
    uint8_t chunk[4096];
    uint32_t offset = 0;
    while (okay && offset < length) {
        const size_t count = std::min(sizeof(chunk), static_cast<size_t>(length - offset));
        errno = 0;
        const size_t read_count = fread(chunk, 1, count, file);
        if (read_count != count) { failure.record(errno); okay = false; }
        else if (memcmp(chunk, bytes + offset, count) != 0) { failure.record(0); okay = false; }
        else offset += static_cast<uint32_t>(count);
    }
    errno = 0;
    const int end = fgetc(file);
    const int end_errno = errno;
    if (end != EOF) { failure.record(0); okay = false; }
    else if (ferror(file)) { failure.record(end_errno); okay = false; }
    trace.add(okay ? NativeOTPStage::FileReadbackOK : NativeOTPStage::FileReadbackFailed);
    errno = 0;
    const int read_closed = fclose(file);
    if (read_closed != 0) failure.record(errno);
    trace.add(read_closed == 0 ? NativeOTPStage::FileReadCloseOK : NativeOTPStage::FileReadCloseFailed);
    if (!okay || read_closed != 0) return false;

    // Detect a removed/replaced UUID directory or temporary before promotion.
    // The existing Swift directory-cleanup race after this point is unchanged.
    struct stat current_root, current_directory, current_temporary;
    bool still_owned = true;
    if (lstat(root, &current_root) != 0) { failure.record(errno); still_owned = false; }
    else if (!S_ISDIR(current_root.st_mode) || current_root.st_dev != root_identity.st_dev ||
        current_root.st_ino != root_identity.st_ino) { failure.record(0); still_owned = false; }
    if (still_owned && fstatat(owned.root, uuid.c_str(), &current_directory, AT_SYMLINK_NOFOLLOW) != 0) {
        failure.record(errno); still_owned = false;
    } else if (still_owned && (!S_ISDIR(current_directory.st_mode) || current_directory.st_dev != directory_identity.st_dev ||
        current_directory.st_ino != directory_identity.st_ino)) { failure.record(0); still_owned = false; }
    if (still_owned && fstatat(owned.directory, owned.temporary_name,
        &current_temporary, AT_SYMLINK_NOFOLLOW) != 0) { failure.record(errno); still_owned = false; }
    if (still_owned && (!S_ISREG(current_temporary.st_mode) || current_temporary.st_dev != owned.temporary_identity.st_dev ||
        current_temporary.st_ino != owned.temporary_identity.st_ino || current_temporary.st_nlink != 1)) {
        failure.record(0); still_owned = false;
    }
    bool promoted = still_owned && destination_ok();
    if (promoted && renameat(owned.directory, owned.temporary_name,
        owned.directory, kADISymbols.adi_pb_filename) != 0) { failure.record(errno); promoted = false; }
    trace.add(promoted ? NativeOTPStage::FileRenameOK : NativeOTPStage::FileRenameFailed);
    if (!promoted) return false;
    owned.owns_temporary = false;
    return true;
}
#else
static int checked_anisette_make_uuid_directory(const char *, const uint8_t *, CheckedAnisetteStagingFailure &failure) {
    failure.record(0);
    errno = EINVAL;
    return -1;
}
static bool checked_anisette_staging(const char *, const uint8_t *, const uint8_t *, uint32_t, NativeOTPTrace &trace,
    CheckedAnisetteStagingFailure &failure) {
    failure.record(0);
    trace.add(NativeOTPStage::FileOpenFailed);
    return false;
}
#endif

thread_local bool g_isolated_otp_logging_suppressed = false;

static EmulatorVM *g_shared_vm = nullptr;
static std::mutex g_vm_mutex;
static std::string g_current_prov_path = "";
static std::string g_current_android_id = "";
static bool g_libraries_initialized = false;
// A constructor can fail before a VM exists; retain that failure as well.
// Accessed only while g_vm_mutex is held.
static bool g_vm_initialization_failed = false;

static bool setup_vm_and_adi(
    EmulatorVM *&vm,
    const char *lib_dir,
    const char *provisioning_dir,
    const uint8_t *identifier,
    std::string &out_uuid_prov_dir,
    std::string &out_err,
    bool isolated = false, NativeOTPTrace *trace = nullptr,
    bool normal_otp_staged = false
) {
    if (trace) trace->add(NativeOTPStage::SetupBegin);
    NativeOTPStageScope setup_stage(trace, NativeOTPStage::SetupFailed);
    if (!normal_otp_staged && !lib_dir) {
        out_err = "Library directory path is null.";
        return false;
    }
    struct stat st;
    if (!normal_otp_staged && (stat(lib_dir, &st) != 0 || !S_ISDIR(st.st_mode))) {
        out_err = std::string("Provided library path is not a valid directory: ") + lib_dir;
        return false;
    }

    if (g_vm_initialization_failed || (g_shared_vm && g_shared_vm->initialization_failed)) {
        out_err = "VM initialization previously failed; restart required";
        return false;
    }
    if (!g_shared_vm) {
        NativeOTPStageScope init_stage(trace, NativeOTPStage::VMInitFailed);
        try { g_shared_vm = new EmulatorVM(); }
        catch (const std::exception &) {
            g_vm_initialization_failed = true;
            out_err = "VM initialization failed";
            return false;
        }
        init_stage.finish(NativeOTPStage::VMInitOK);
    }
    else if (trace && !isolated) trace->add(NativeOTPStage::VMReused);
    vm = g_shared_vm;

    if (!g_libraries_initialized) {
        std::string lib_path(lib_dir);
        if (!lib_path.empty() && lib_path.back() != '/') lib_path += "/";
        std::string ssc_path     = lib_path + kADISymbols.lib_ssc;
        std::string coreadi_path = lib_path + kADISymbols.lib_core_adi;

        NativeOTPStageScope load_stage(trace, NativeOTPStage::LibraryLoadFailed);
        if (!load_library_to_vm(vm, ssc_path, kADISymbols.lib_ssc) ||
            !load_library_to_vm(vm, coreadi_path, kADISymbols.lib_core_adi)) {
            out_err = "Failed to load libraries into VM";
            return false;
        }

        load_stage.finish(NativeOTPStage::LibraryLoadOK);
        NativeOTPStageScope library_stage(trace, NativeOTPStage::LibraryInitFailed);
        NativeLoginTimingScope relocation_timing(trace, 12);
        relocate_all_vm_libraries(vm);
        if (vm->initialization_failed) {
            out_err = "Failed to relocate libraries into VM";
            return false;
        }
        relocation_timing.finish();
        NativeLoginTimingScope constructor_timing(trace, 13);
        adiConsumptionPhase(ADIConsumptionDebug::Constructors);
        vm_initialization_diagnostics::ConstructorFailure constructor_failure;
        if (!run_library_constructors(vm, &constructor_failure)) {
            out_err = vm_initialization_diagnostics::description(constructor_failure);
            if (trace) trace->record_constructor_fault(constructor_failure);
            return false;
        }

        constructor_timing.finish();
        uint64_t load_lib_ptr = get_vm_symbol_address(vm, kADISymbols.load_library);
        if (!load_lib_ptr) {
            out_err = "Required ADI setup symbol missing in VM";
            return false;
        }

        uint64_t lib_path_vm = vm->write_string(lib_path.c_str());
        LOG_UC("[AnisetteKit - UC] phase=library.init begin\n");
        adiConsumptionPhase(ADIConsumptionDebug::LibraryInit);
        NativeLoginTimingScope load_call_timing(trace, 14);
        int32_t load_res = run_vm_procedure(vm, load_lib_ptr, {lib_path_vm, 0}, isolated ? 5000000 : 0, isolated ? 50000000 : 0);
        LOG_UC("[AnisetteKit - UC] phase=library.init result=%d\n", (int)load_res);
        if (load_res != 0) {
            out_err = "ADILoadLibraryWithPath failed: " + std::to_string(load_res);
            return false;
        }
        load_call_timing.finish();
        g_libraries_initialized = true;
        library_stage.finish(NativeOTPStage::LibraryInitOK);
    }

    else if (trace) trace->add(NativeOTPStage::LibraryCached);

    std::string uuid = format_uuid_string(identifier);
    out_uuid_prov_dir = std::string(provisioning_dir) + "/" + uuid;
    // Normal OTP already created and checked this child before any native setup.
    // Provisioning and isolated OTP retain their inherited setup behavior.
    if (!normal_otp_staged) {
        const int directory_result = mkdir(out_uuid_prov_dir.c_str(), 0755);
        const int directory_errno = errno;
        if (trace) trace->add(directory_result == 0 ? NativeOTPStage::DirectoryCreated :
            (directory_errno == EEXIST ? NativeOTPStage::DirectoryExists : NativeOTPStage::DirectoryFailed));
    }

    if (out_uuid_prov_dir != g_current_prov_path) {
        NativeOTPStageScope path_stage(trace, NativeOTPStage::ProvisioningPathFailed);
        uint64_t set_prov_ptr = get_vm_symbol_address(vm, kADISymbols.set_provisioning_path);
        if (!set_prov_ptr) {
            out_err = "Symbol ADISetProvisioningPath missing in VM";
            return false;
        }
        uint64_t prov_path_vm = vm->write_string(out_uuid_prov_dir.c_str());
        LOG_UC("[AnisetteKit - UC] phase=provisioning_path begin\n");
        adiConsumptionPhase(ADIConsumptionDebug::ProvisioningPath);
        int32_t prov_res = run_vm_procedure(vm, set_prov_ptr, {prov_path_vm}, isolated ? 5000000 : 0, isolated ? 50000000 : 0);
        LOG_UC("[AnisetteKit - UC] phase=provisioning_path result=%d\n", (int)prov_res);
        if (prov_res != 0) {
            out_err = "ADISetProvisioningPath failed: " + std::to_string(prov_res);
            return false;
        }
        g_current_prov_path = out_uuid_prov_dir;
        path_stage.finish(NativeOTPStage::ProvisioningPathOK);
    }

    else if (trace) trace->add(NativeOTPStage::ProvisioningPathCached);

    std::string android_id = get_android_id_string(identifier);
    if (android_id != g_current_android_id) {
        NativeOTPStageScope id_stage(trace, NativeOTPStage::AndroidIDFailed);
        uint64_t set_id_ptr = get_vm_symbol_address(vm, kADISymbols.set_android_id);
        if (!set_id_ptr) {
            out_err = "Symbol ADISetAndroidID missing in VM";
            return false;
        }
        uint64_t android_id_vm = vm->write_string(android_id.c_str());
        LOG_UC("[AnisetteKit - UC] phase=android_id begin\n");
        adiConsumptionPhase(ADIConsumptionDebug::AndroidID);
        int32_t id_res = run_vm_procedure(vm, set_id_ptr, {android_id_vm, (uint64_t)android_id.length()}, isolated ? 5000000 : 0, isolated ? 50000000 : 0);
        LOG_UC("[AnisetteKit - UC] phase=android_id result=%d\n", (int)id_res);
        if (id_res != 0) {
            out_err = "ADISetAndroidID failed: " + std::to_string(id_res);
            return false;
        }
        g_current_android_id = android_id;
        id_stage.finish(NativeOTPStage::AndroidIDOK);
    }

    else if (trace) trace->add(NativeOTPStage::AndroidIDCached);

    setup_stage.finish(NativeOTPStage::SetupOK);
    return true;
}

extern "C" {

static int32_t get_anisette_headers_uc_locked(
    const char *lib_dir,
    const char *provisioning_dir,
    const uint8_t *identifier,
    const uint8_t *adi_pb,
    uint32_t adi_pb_len,
    char **out_json,
    bool isolated, NativeOTPTrace &trace
) {
    LOG_UC("[AnisetteKit - UC] Invoked get_anisette_headers_uc\n");
    if (!lib_dir || !provisioning_dir || !identifier || !adi_pb || !out_json) {
        return ANISETTE_ERR_INVALID_ARGUMENT;
    }


    if (!isolated && activeADIConsumptionDebug)
        activeADIConsumptionDebug->configure(provisioning_dir, identifier, adi_pb, adi_pb_len);
    if (!isolated) trace.add(NativeOTPStage::ArgumentsOK);
    CheckedAnisetteStagingFailure staging_failure;
    EmulatorVM *vm = nullptr;
    std::string uuid_prov_dir, err;
    if (!isolated) {
        // Keep invalid library paths ahead of any filesystem mutation and return
        // the inherited loader error. The original null guard remains above.
        struct stat st;
        if (stat(lib_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            trace.add(NativeOTPStage::SetupBegin);
            trace.add(NativeOTPStage::SetupFailed);
            err = std::string("Provided library path is not a valid directory: ") + lib_dir;
            *out_json = strdup(("{\"error\":\"" + err + "\"}").c_str());
            return ANISETTE_ERR_LOADER_FAILED;
        }
        // Temporary ordering experiment under g_vm_mutex: stage the supplied
        // bytes before a cold VM can run constructors or initialize ADI. Reused
        // and freshly provisioned VMs keep their existing context and caches.
        const int made = checked_anisette_make_uuid_directory(provisioning_dir, identifier, staging_failure);
        const int made_errno = errno;
        trace.add(made == 0 ? NativeOTPStage::DirectoryCreated :
            (made_errno == EEXIST ? NativeOTPStage::DirectoryExists : NativeOTPStage::DirectoryFailed));
        if ((made != 0 && made_errno != EEXIST) ||
            !checked_anisette_staging(provisioning_dir, identifier, adi_pb, adi_pb_len, trace, staging_failure)) {
            *out_json = strdup(("{\"error\":\"" + staging_failure.message() + "\"}").c_str());
            return -6;
        }
    }
    if (!setup_vm_and_adi(vm, lib_dir, provisioning_dir, identifier, uuid_prov_dir, err, isolated, &trace, !isolated)) {
        std::stringstream ss;
        ss << "{\"error\":\"" << err << "\"}";
        *out_json = strdup(ss.str().c_str());
        return ANISETTE_ERR_LOADER_FAILED;
    }

    std::string adi_pb_path = uuid_prov_dir + "/" + kADISymbols.adi_pb_filename;

    uint64_t otp_req_ptr = get_vm_symbol_address(vm, kADISymbols.otp_request);
    trace.add(otp_req_ptr ? NativeOTPStage::NativeSymbolOK : NativeOTPStage::NativeSymbolFailed);
    if (!otp_req_ptr) {
        *out_json = strdup("{\"error\":\"Symbol ADIOTPRequest missing\"}");
        return ANISETTE_ERR_SYMBOL_MISSING;
    }

    uint64_t mid_ptr = vm->allocate_guest(8);
    uint64_t mid_len_ptr = vm->allocate_guest(4);
    uint64_t otp_ptr = vm->allocate_guest(8);
    uint64_t otp_len_ptr = vm->allocate_guest(4);
    if (!mid_ptr || !mid_len_ptr || !otp_ptr || !otp_len_ptr) {
        trace.add(NativeOTPStage::NativeOTPFailed);
        *out_json = strdup("{\"error\":\"OTP output allocation failed\"}");
        return ANISETTE_ERR_LOADER_FAILED;
    }

    uint64_t dsid = (uint64_t)-2;
    LOG_UC("[AnisetteKit - UC] phase=otp begin\n");
    NativeOTPStageScope otp_stage(&trace, NativeOTPStage::NativeOTPFailed);
    adiConsumptionPhase(ADIConsumptionDebug::OTP);
    int32_t res = run_vm_procedure(vm, otp_req_ptr, {dsid, mid_ptr, mid_len_ptr, otp_ptr, otp_len_ptr}, isolated ? 5000000 : 0, isolated ? 50000000 : 0);
    LOG_UC("[AnisetteKit - UC] phase=otp result=%d\n", (int)res);

    otp_stage.finish(res == 0 ? NativeOTPStage::NativeOTPOK : NativeOTPStage::NativeOTPFailed);
    if (res != 0) {
        std::stringstream ss;
        ss << "{\"error\":\"ADIOTPRequest failed ("
           << get_anisette_error_description(res) << "): " << res << "\"}";
        *out_json = strdup(ss.str().c_str());
        return res;
    }

    uint64_t final_mid_addr = 0, final_otp_addr = 0;
    uint32_t final_mid_len = 0, final_otp_len = 0;
    
    if (uc_mem_read(vm->uc, mid_ptr, &final_mid_addr, 8) != UC_ERR_OK && isolated) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }
    if (uc_mem_read(vm->uc, mid_len_ptr, &final_mid_len, 4) != UC_ERR_OK && isolated) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }
    if (uc_mem_read(vm->uc, otp_ptr, &final_otp_addr, 8) != UC_ERR_OK && isolated) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }
    if (uc_mem_read(vm->uc, otp_len_ptr, &final_otp_len, 4) != UC_ERR_OK && isolated) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }

    if (isolated && (!final_mid_addr || !final_otp_addr || !final_mid_len || !final_otp_len ||
                     final_mid_len > 4096 || final_otp_len > 4096)) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }
    std::vector<uint8_t> mid_data(final_mid_len);
    if (final_mid_len > 0 && final_mid_addr != 0) {
        if (uc_mem_read(vm->uc, final_mid_addr, mid_data.data(), final_mid_len) != UC_ERR_OK && isolated) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }
    }

    std::vector<uint8_t> otp_data(final_otp_len);
    if (final_otp_len > 0 && final_otp_addr != 0) {
        if (uc_mem_read(vm->uc, final_otp_addr, otp_data.data(), final_otp_len) != UC_ERR_OK && isolated) {
        trace.add(NativeOTPStage::NativeOutputFailed);
        *out_json = strdup("{\"error\":\"Isolated OTP output invalid\"}");
        return ANISETTE_ERR_INVALID_JSON_RESPONSE;
    }
    }

    std::string mid = base64_encode(mid_data.data(), final_mid_len);
    std::string otp = base64_encode(otp_data.data(), final_otp_len);

    std::stringstream ss;
    ss << "{\"X-Apple-I-MD-M\":\"" << mid
       << "\",\"X-Apple-I-MD\":\"" << otp
       << "\",\"X-Apple-I-MD-RINFO\":\"17106176\",\"X-Apple-I-MD-LU\":\"0000000000000000000000000000000000000000000000000000000000000001\"}";
    *out_json = strdup(ss.str().c_str());

    trace.add(isolated ? NativeOTPStage::NativeOutputOK : NativeOTPStage::NativeOutputUnchecked);
    return ANISETTE_OK;
}

// V3_ISOLATED_ANISETTE_OTP_V1. A disposable VM and private copy only.
// Dormant API provenance; the active build gate requires checked normal staging.
extern const char v3_isolated_anisette_otp_marker[] = "V3_ISOLATED_ANISETTE_OTP_V1";

int32_t get_anisette_headers_uc(
    const char *lib_dir, const char *provisioning_dir, const uint8_t *identifier,
    const uint8_t *adi_pb, uint32_t adi_pb_len, char **out_json
) {
    NativeOTPTrace trace(nullptr);
    std::lock_guard<std::mutex> lock(g_vm_mutex);
    ADIConsumptionDebug consumption(nullptr, nullptr);
    ADIConsumptionScope consumption_scope(&consumption);
    const int32_t result = get_anisette_headers_uc_locked(lib_dir, provisioning_dir, identifier,
                                         adi_pb, adi_pb_len, out_json, false, trace);
    // Invalid original arguments do not initialize the caller's output pointer.
    if (result != ANISETTE_ERR_INVALID_ARGUMENT) {
        trace.output = out_json;
        if (result != ANISETTE_OK) consumption.append(out_json);
    }
    // No UUID-directory cleanup here. Checked staging owns only its temporary;
    // the existing Swift directory-cleanup race remains outside this mutex.
    trace.add(NativeOTPStage::CleanupNotRequested);
    return result;
}

static int32_t isolated_otp_error(char **out_json, int32_t code, const char *message) {
    if (*out_json) { free_c_string(*out_json); *out_json = nullptr; }
    // Every caller supplies a fixed, non-sensitive JSON literal.
    *out_json = strdup(message);
    return code;
}

struct IsolatedOTPLogging {
    bool saved = g_isolated_otp_logging_suppressed;
    IsolatedOTPLogging() { g_isolated_otp_logging_suppressed = true; }
    ~IsolatedOTPLogging() { g_isolated_otp_logging_suppressed = saved; }
};

#if !defined(_WIN32) && !defined(_MSC_VER)
struct IsolatedOTPFiles {
    std::string directory, temporary, blob;
    bool owns_directory = false;
    bool cleanup_reported = false;
    NativeOTPTrace &trace;

    IsolatedOTPFiles(const char *root, const uint8_t *identifier, NativeOTPTrace &owner)
        : directory(std::string(root) + "/" + format_uuid_string(identifier)),
          temporary(directory + "/.adi.pb.staging"), blob(directory + "/adi.pb"), trace(owner) {}

    bool cleanup() noexcept {
        if (!owns_directory) {
            if (!cleanup_reported) trace.add(NativeOTPStage::CleanupNotNeeded);
            cleanup_reported = true;
            return true;
        }
        bool okay = true;
        if (unlink(temporary.c_str()) != 0 && errno != ENOENT) okay = false;
        if (unlink(blob.c_str()) != 0 && errno != ENOENT) okay = false;
        if (rmdir(directory.c_str()) != 0 && errno != ENOENT) okay = false;
        if (okay) owns_directory = false;
        trace.add(okay ? NativeOTPStage::CleanupOK : NativeOTPStage::CleanupFailed);
        cleanup_reported = true;
        return okay;
    }
    ~IsolatedOTPFiles() { cleanup(); }

    bool stage(const char *root, const uint8_t *bytes, uint32_t length) {
        struct stat st;
        // The root must be a private directory belonging to this process's user.
        // Never reuse a pre-existing UUID child, including a symbolic link.
        if (lstat(root, &st) != 0 || !S_ISDIR(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 0077) != 0) {
            trace.add(NativeOTPStage::RootFailed);
            return false;
        }
        trace.add(NativeOTPStage::RootOK);
        if (mkdir(directory.c_str(), 0700) != 0) {
            trace.add(errno == EEXIST ? NativeOTPStage::DirectoryExists : NativeOTPStage::DirectoryFailed);
            return false;
        }
        trace.add(NativeOTPStage::DirectoryCreated);
        owns_directory = true;
        int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        trace.add(fd >= 0 ? NativeOTPStage::FileOpenOK : NativeOTPStage::FileOpenFailed);
        if (fd < 0) return false;
        FILE *file = fdopen(fd, "wb");
        trace.add(file ? NativeOTPStage::FileStreamOK : NativeOTPStage::FileStreamFailed);
        if (!file) {
            const int closed = close(fd);
            trace.add(closed == 0 ? NativeOTPStage::FileCloseOK : NativeOTPStage::FileCloseFailed);
            return false;
        }
        bool okay = fwrite(bytes, 1, length, file) == length;
        trace.add(okay ? NativeOTPStage::FileWriteOK : NativeOTPStage::FileWriteFailed);
        const int flushed = fflush(file);
        trace.add(flushed == 0 ? NativeOTPStage::FileFlushOK : NativeOTPStage::FileFlushFailed);
        if (flushed != 0) okay = false;
        const int closed = fclose(file);
        trace.add(closed == 0 ? NativeOTPStage::FileCloseOK : NativeOTPStage::FileCloseFailed);
        if (closed != 0) okay = false;
        if (!okay) return false;

        file = fopen(temporary.c_str(), "rb");
        trace.add(file ? NativeOTPStage::FileReadOpenOK : NativeOTPStage::FileReadOpenFailed);
        if (!file) return false;
        uint8_t chunk[4096];
        uint32_t offset = 0;
        while (okay && offset < length) {
            size_t count = std::min(sizeof(chunk), static_cast<size_t>(length - offset));
            if (fread(chunk, 1, count, file) != count || memcmp(chunk, bytes + offset, count) != 0) {
                okay = false;
            } else { offset += static_cast<uint32_t>(count); }
        }
        if (fgetc(file) != EOF || ferror(file)) okay = false;
        trace.add(okay ? NativeOTPStage::FileReadbackOK : NativeOTPStage::FileReadbackFailed);
        const int read_closed = fclose(file);
        trace.add(read_closed == 0 ? NativeOTPStage::FileReadCloseOK : NativeOTPStage::FileReadCloseFailed);
        if (read_closed != 0) okay = false;
        if (!okay) return false;
        const bool renamed = rename(temporary.c_str(), blob.c_str()) == 0;
        trace.add(renamed ? NativeOTPStage::FileRenameOK : NativeOTPStage::FileRenameFailed);
        return renamed;
    }
};

struct IsolatedOTPVM {
    EmulatorVM *saved_vm;
    std::string saved_path, saved_id;
    bool saved_initialized;
    bool saved_initialization_failed;
    std::unique_ptr<EmulatorVM> probe;

    IsolatedOTPVM()
        : saved_vm(g_shared_vm), saved_initialized(g_libraries_initialized),
          saved_initialization_failed(g_vm_initialization_failed),
          probe(new EmulatorVM(true)) {
        probe->read_only_filesystem = true;
        saved_path.swap(g_current_prov_path);
        saved_id.swap(g_current_android_id);
        g_shared_vm = probe.get();
        g_libraries_initialized = false;
        g_vm_initialization_failed = false;
    }
    ~IsolatedOTPVM() {
        g_shared_vm = saved_vm;
        g_current_prov_path.swap(saved_path);
        g_current_android_id.swap(saved_id);
        g_libraries_initialized = saved_initialized;
        g_vm_initialization_failed = saved_initialization_failed;
        // probe is destroyed after restoring the regular provider's state.
    }
};
#endif

int32_t get_anisette_headers_isolated_uc(
    const char *lib_dir, const char *provisioning_dir, const uint8_t *identifier,
    const uint8_t *adi_pb, uint32_t adi_pb_len, char **out_json
) {
    if (!out_json) return ANISETTE_ERR_INVALID_ARGUMENT;
    *out_json = nullptr;
    NativeOTPTrace trace(out_json);
    if (!lib_dir || !provisioning_dir || !identifier || !adi_pb ||
        !*lib_dir || !*provisioning_dir || adi_pb_len == 0 || adi_pb_len > 1048576) {
        trace.add(NativeOTPStage::ArgumentsFailed);
        return isolated_otp_error(out_json, -1, "{\"error\":\"Invalid isolated OTP argument\"}");
    }
    trace.add(NativeOTPStage::ArgumentsOK);
#if defined(_WIN32) || defined(_MSC_VER)
    return isolated_otp_error(out_json, -1, "{\"error\":\"Isolated OTP unsupported platform\"}");
#else
    // Covers setup, checked staging, OTP, VM destruction and cleanup. Normal
    // native calls use this same mutex and cannot observe swapped globals.
    std::lock_guard<std::mutex> lock(g_vm_mutex);
    IsolatedOTPLogging log_scope;
    try {
        IsolatedOTPFiles files(provisioning_dir, identifier, trace);
        if (!files.stage(provisioning_dir, adi_pb, adi_pb_len)) {
            return isolated_otp_error(out_json, -6, "{\"error\":\"Isolated OTP staging failed\"}");
        }
        int32_t result;
        {
            NativeOTPStageScope init_stage(&trace, NativeOTPStage::VMInitFailed);
            IsolatedOTPVM context;
            init_stage.finish(NativeOTPStage::VMInitOK);
            result = get_anisette_headers_uc_locked(lib_dir, provisioning_dir,
                identifier, adi_pb, adi_pb_len, out_json, true, trace);
        }
        if (!files.cleanup()) {
            return isolated_otp_error(out_json, -6, "{\"error\":\"Isolated OTP cleanup failed\"}");
        }
        if (!*out_json) {
            trace.add(NativeOTPStage::ResponseAllocationFailed);
            return isolated_otp_error(out_json, -7, "{\"error\":\"Isolated OTP allocation failed\"}");
        }
        return result;
    } catch (...) {
        return isolated_otp_error(out_json, -7, "{\"error\":\"Isolated OTP initialization failed\"}");
    }
#endif
}

int32_t start_provision_uc(
    const char *lib_dir,
    const char *provisioning_dir,
    const uint8_t *identifier,
    const uint8_t *spim,
    uint32_t spim_len,
    char **out_json
) {
    LOG_UC("[AnisetteKit - UC] Invoked start_provision_uc\n");
    if (!lib_dir || !provisioning_dir || !identifier || !spim || !out_json) {
        return ANISETTE_ERR_INVALID_ARGUMENT;
    }

    *out_json = nullptr;
    NativeOTPTrace trace(out_json);
    trace.add(NativeOTPStage::ArgumentsOK);
    std::lock_guard<std::mutex> lock(g_vm_mutex);

    EmulatorVM *vm = nullptr;
    std::string uuid_prov_dir, err;
    if (!setup_vm_and_adi(vm, lib_dir, provisioning_dir, identifier, uuid_prov_dir, err, false, &trace)) {
        std::stringstream ss;
        ss << "{\"error\":\"" << err << "\"}";
        *out_json = strdup(ss.str().c_str());
        return ANISETTE_ERR_LOADER_FAILED;
    }

    uint64_t prov_start_ptr = get_vm_symbol_address(vm, kADISymbols.provisioning_start);
    if (!prov_start_ptr) {
        *out_json = strdup("{\"error\":\"Symbol ADIProvisioningStart missing\"}");
        trace.add(NativeOTPStage::NativeSymbolFailed);
        return ANISETTE_ERR_SYMBOL_MISSING;
    }

    trace.add(NativeOTPStage::NativeSymbolOK);
    uint64_t spim_vm = vm->write_bytes(spim, spim_len);
    uint64_t cpim_ptr = vm->allocate_guest(8);
    uint64_t cpim_len_ptr = vm->allocate_guest(4);
    uint64_t session_ptr = vm->allocate_guest(4);
    if ((spim_len && !spim_vm) || !cpim_ptr || !cpim_len_ptr || !session_ptr) {
        trace.add(NativeOTPStage::NativeStartFailed);
        *out_json = strdup("{\"error\":\"Provisioning buffer allocation failed\"}");
        return ANISETTE_ERR_LOADER_FAILED;
    }

    uint64_t zero64 = 0;
    uint32_t zero32 = 0;
    if (uc_mem_write(vm->uc, cpim_ptr, &zero64, sizeof(zero64)) != UC_ERR_OK ||
        uc_mem_write(vm->uc, cpim_len_ptr, &zero32, sizeof(zero32)) != UC_ERR_OK ||
        uc_mem_write(vm->uc, session_ptr, &zero32, sizeof(zero32)) != UC_ERR_OK) {
        vm->initialization_failed = true;
        trace.add(NativeOTPStage::NativeStartFailed);
        *out_json = strdup("{\"error\":\"Provisioning buffer initialization failed\"}");
        return ANISETTE_ERR_LOADER_FAILED;
    }

    uint64_t dsid = (uint64_t)-2;
    LOG_UC("[AnisetteKit - UC] phase=provisioning.start begin spim_bytes=%u\n", (unsigned)spim_len);
    NativeOTPStageScope operation_stage(&trace, NativeOTPStage::NativeStartFailed);
    int32_t res = run_vm_procedure(vm, prov_start_ptr, {dsid, spim_vm, (uint64_t)spim_len, cpim_ptr, cpim_len_ptr, session_ptr});
    LOG_UC("[AnisetteKit - UC] phase=provisioning.start result=%d\n", (int)res);

    if (res != 0) {
        rmdir(uuid_prov_dir.c_str());
        std::stringstream ss;
        ss << "{\"error\":\"ADIProvisioningStart failed ("
           << get_anisette_error_description(res) << "): " << res << "\"}";
        *out_json = strdup(ss.str().c_str());
        return res;
    }

    operation_stage.finish(NativeOTPStage::NativeStartOK);
    uint64_t final_cpim_addr = 0;
    uint32_t final_cpim_len = 0;
    uint32_t session = 0;

    uc_mem_read(vm->uc, cpim_ptr, &final_cpim_addr, 8);
    uc_mem_read(vm->uc, cpim_len_ptr, &final_cpim_len, 4);
    uc_mem_read(vm->uc, session_ptr, &session, 4);

    LOG_UC("[AnisetteKit - UC] phase=provisioning.start output_present=%d cpim_bytes=%u\n", final_cpim_addr != 0, (unsigned)final_cpim_len);
    fflush(stdout);

    std::vector<uint8_t> cpim_data(final_cpim_len);
    if (final_cpim_len > 0 && final_cpim_addr != 0) {
        uc_mem_read(vm->uc, final_cpim_addr, cpim_data.data(), final_cpim_len);
    }

    std::string cpim_b64 = base64_encode(cpim_data.data(), final_cpim_len);

    std::stringstream ss;
    ss << "{\"cpim_base64\":\"" << cpim_b64 << "\",\"session\":" << session << "}";
    *out_json = strdup(ss.str().c_str());

    trace.add(NativeOTPStage::NativeOutputUnchecked);
    if (!*out_json) trace.add(NativeOTPStage::ResponseAllocationFailed);
    return ANISETTE_OK;
}

int32_t end_provision_uc(
    const char *lib_dir,
    const char *provisioning_dir,
    const uint8_t *identifier,
    uint32_t session,
    const uint8_t *ptm,
    uint32_t ptm_len,
    const uint8_t *tk,
    uint32_t tk_len,
    char **out_json
) {
    LOG_UC("[AnisetteKit - UC] Invoked end_provision_uc\n");
    if (!lib_dir || !provisioning_dir || !identifier || !ptm || !tk || !out_json) {
        return ANISETTE_ERR_INVALID_ARGUMENT;
    }

    *out_json = nullptr;
    NativeOTPTrace trace(out_json);
    trace.add(NativeOTPStage::ArgumentsOK);
    std::lock_guard<std::mutex> lock(g_vm_mutex);

    EmulatorVM *vm = nullptr;
    std::string uuid_prov_dir, err;
    if (!setup_vm_and_adi(vm, lib_dir, provisioning_dir, identifier, uuid_prov_dir, err, false, &trace)) {
        std::stringstream ss;
        ss << "{\"error\":\"" << err << "\"}";
        *out_json = strdup(ss.str().c_str());
        return ANISETTE_ERR_LOADER_FAILED;
    }

    uint64_t prov_end_ptr = get_vm_symbol_address(vm, kADISymbols.provisioning_end);
    if (!prov_end_ptr) {
        *out_json = strdup("{\"error\":\"Symbol ADIProvisioningEnd missing\"}");
        trace.add(NativeOTPStage::NativeSymbolFailed);
        return ANISETTE_ERR_SYMBOL_MISSING;
    }

    trace.add(NativeOTPStage::NativeSymbolOK);
    uint64_t ptm_vm = vm->write_bytes(ptm, ptm_len);
    uint64_t tk_vm  = vm->write_bytes(tk, tk_len);

    LOG_UC("[AnisetteKit - UC] phase=provisioning.end begin ptm_bytes=%u tk_bytes=%u\n", (unsigned)ptm_len, (unsigned)tk_len);
    NativeOTPStageScope operation_stage(&trace, NativeOTPStage::NativeEndFailed);
    int32_t res = run_vm_procedure(vm, prov_end_ptr, {(uint64_t)session, ptm_vm, (uint64_t)ptm_len, tk_vm, (uint64_t)tk_len});
    LOG_UC("[AnisetteKit - UC] phase=provisioning.end result=%d\n", (int)res);

    if (res != 0) {
        std::stringstream ss;
        ss << "{\"error\":\"ADIProvisioningEnd failed ("
           << get_anisette_error_description(res) << "): " << res << "\"}";
        *out_json = strdup(ss.str().c_str());
        return res;
    }

    operation_stage.finish(NativeOTPStage::NativeEndOK);
    std::string adi_pb_path = uuid_prov_dir + "/" + kADISymbols.adi_pb_filename;
    FILE* f = fopen(adi_pb_path.c_str(), "rb");
    if (!f) {
        *out_json = strdup("{\"error\":\"Failed to read generated adi.pb\"}");
        return ANISETTE_ERR_READ_FILE_FAILED;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::vector<uint8_t> pb_data(size);
    fread(pb_data.data(), 1, size, f);
    fclose(f);

    std::string adi_pb_b64 = base64_encode(pb_data.data(), size);

    std::stringstream ss;
    ss << "{\"adi_pb_base64\":\"" << adi_pb_b64 << "\"}";
    *out_json = strdup(ss.str().c_str());

    trace.add(NativeOTPStage::NativeOutputUnchecked);
    if (!*out_json) trace.add(NativeOTPStage::ResponseAllocationFailed);
    return ANISETTE_OK;
}

int32_t cancel_provision_uc(
    const char *lib_dir,
    const char *provisioning_dir,
    const uint8_t *identifier,
    uint32_t session
) {
    LOG_UC("[AnisetteKit - UC] Invoked cancel_provision_uc\n");
    if (!lib_dir || !provisioning_dir || !identifier) {
        return ANISETTE_ERR_INVALID_ARGUMENT;
    }

    std::lock_guard<std::mutex> lock(g_vm_mutex);

    if (g_shared_vm) {
        uint64_t destroy_session_ptr = get_vm_symbol_address(g_shared_vm, kADISymbols.destroy_session);
        if (destroy_session_ptr) {
            run_vm_procedure(g_shared_vm, destroy_session_ptr, {session});
        }
    }

    return ANISETTE_OK;
}

}
