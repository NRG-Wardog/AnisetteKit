#pragma once

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>

// An attempt owns this object for its entire native lifetime. Cancellation only
// marks state; only the native owner may touch an emulator or destroy it. A
// timeout is not a claim that a blocked host callback has returned.
namespace anisette_owned_attempt {
enum class Stop : uint8_t { none, cancelled, deadline, failed };
enum class Phase : uint8_t { idle, native, draining, quiescent };

class Control {
public:
    using Clock = std::chrono::steady_clock;
    explicit Control(std::chrono::milliseconds budget)
        : deadline_(Clock::now() + std::max(std::chrono::milliseconds(0), std::min(budget, std::chrono::milliseconds(120000)))) {}
    explicit Control(Clock::time_point deadline) : deadline_(deadline) {}
    Control(const Control &) = delete;
    Control &operator=(const Control &) = delete;

    void cancel() noexcept { stop(Stop::cancelled); }
    void fail() noexcept { stop(Stop::failed); }
    Stop reason() const noexcept { return stop_.load(std::memory_order_acquire); }
    bool check() noexcept {
        if (reason() != Stop::none) return false;
        if (Clock::now() >= deadline_) { stop(Stop::deadline); return false; }
        return true;
    }
    uint64_t remaining_us() noexcept {
        if (!check()) return 0;
        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline_ - Clock::now()).count();
        if (remaining <= 0) { stop(Stop::deadline); return 0; }
        return static_cast<uint64_t>(remaining);
    }
    // Never wait behind an existing call and never admit a call after close.
    bool enter() noexcept {
        if (!check()) return false;
        Phase expected = Phase::idle;
        if (!phase_.compare_exchange_strong(expected, Phase::native, std::memory_order_acq_rel)) return false;
        if (!check()) { leave(); return false; }
        return true;
    }
    void leave() noexcept {
        Phase expected = Phase::native;
        if (!phase_.compare_exchange_strong(expected, Phase::idle, std::memory_order_acq_rel)) {
            // close() requested drain while the native worker still owned it.
            if (expected == Phase::draining) phase_.store(Phase::quiescent, std::memory_order_release);
        }
    }
    void close() noexcept {
        cancel();
        Phase p = phase_.load(std::memory_order_acquire);
        for (;;) {
            if (p == Phase::quiescent || p == Phase::draining) return;
            Phase next = p == Phase::native ? Phase::draining : Phase::quiescent;
            if (phase_.compare_exchange_weak(p, next, std::memory_order_acq_rel)) return;
        }
    }
    bool quiescent() const noexcept { return phase_.load(std::memory_order_acquire) == Phase::quiescent; }
    Phase phase() const noexcept { return phase_.load(std::memory_order_acquire); }
    // An engine timeout can return UC_ERR_OK without reaching its return PC.
    bool completed(bool engine_ok, bool returned) noexcept {
        if (!engine_ok || !returned) { fail(); return false; }
        return check();
    }
private:
    void stop(Stop value) noexcept {
        Stop expected = Stop::none;
        stop_.compare_exchange_strong(expected, value, std::memory_order_acq_rel);
    }
    const Clock::time_point deadline_;
    std::atomic<Stop> stop_{Stop::none};
    std::atomic<Phase> phase_{Phase::idle};
};

class Call {
public:
    explicit Call(Control &control) noexcept : control_(control), entered_(control.enter()) {}
    ~Call() { if (entered_) control_.leave(); }
    explicit operator bool() const noexcept { return entered_; }
    Call(const Call &) = delete;
    Call &operator=(const Call &) = delete;
private:
    Control &control_;
    const bool entered_;
};
}
