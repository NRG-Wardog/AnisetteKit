#ifndef ANISETTE_NATIVE_LOGGING_POLICY_H
#define ANISETTE_NATIVE_LOGGING_POLICY_H

#include <cstdlib>
#include <cstring>

// Specific to the pinned a53ddc9 Unicorn logger. This is not a mutable logger
// bridge: that artifact caches environment settings independently in each TU.
namespace anisette_native_logging {

enum class StartupMode { Failed = -1, Disabled = 0, Errors = 1 };

inline int set_environment(const char *name, const char *value) noexcept {
#if defined(_WIN32) || defined(_MSC_VER)
    return _putenv_s(name, value);
#else
    return setenv(name, value, 1);
#endif
}

inline StartupMode configure_before_first_vm() noexcept {
    // C++ static initialization serializes concurrent AnisetteKit VM creation.
    // The host must choose this before using Unicorn anywhere in this process
    // and must not mutate the Unicorn environment afterward. Restart to change.
    static const StartupMode mode = []() noexcept {
        const char *requested = std::getenv("ANISETTEKIT_UNICORN_DIAGNOSTICS");
        const bool enabled = requested && std::strcmp(requested, "errors") == 0;
        // Override unmanaged/all-bits launch settings before our first uc_open.
        // Fail closed before opening a VM if this cap cannot be installed.
        if (set_environment("UNICORN_LOG_LEVEL", "0") != 0)
            return StartupMode::Failed;
        if (set_environment("UNICORN_LOG_DETAIL_LEVEL", "2") != 0)
            return StartupMode::Failed;
        // LOG_UNIMP | LOG_GUEST_ERROR | CPU_LOG_INT. No TCG IR/MMU/strace bits.
        if (enabled && set_environment("UNICORN_LOG_LEVEL", "0xC10") != 0)
            return StartupMode::Failed;
        return enabled ? StartupMode::Errors : StartupMode::Disabled;
    }();
    return mode;
}

// Library names are caller/ELF-derived strings too: emit only known literals.
inline const char *library_label(const char *name) noexcept {
    if (name && std::strcmp(name, "libstoreservicescore.so") == 0)
        return "libstoreservicescore.so";
    if (name && std::strcmp(name, "libCoreADI.so") == 0)
        return "libCoreADI.so";
    return "other";
}

} // namespace anisette_native_logging
#endif
