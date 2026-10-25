#include "owned_attempt_lifecycle.h"
#include <cassert>
#include <condition_variable>
#include <mutex>
#include <thread>
using namespace anisette_owned_attempt;
int main() {
    for (int boundary = 0; boundary < 8; ++boundary) {
        Control c(std::chrono::seconds(10));
        for (int i=0; i<8; ++i) {
            if (i == boundary) c.cancel();
            Call call(c);
            assert(static_cast<bool>(call) == (i < boundary));
            if (call) assert(c.completed(true, true));
        }
        c.close(); assert(c.quiescent()); assert(!c.enter());
    }
    { Control c(Control::Clock::now()); assert(!c.enter()); assert(c.reason()==Stop::deadline); c.close(); assert(c.quiescent()); }
    { Control c(std::chrono::seconds(10)); Call one(c); assert(one); Call two(c); assert(!two); assert(!c.completed(true,false)); assert(c.reason()==Stop::failed); }
    { Control c(std::chrono::seconds(10)); assert(c.enter()); c.cancel(); assert(!c.completed(true,true)); assert(!c.quiescent()); c.leave(); c.close(); assert(c.quiescent()); }
    // A stuck host callback cannot be declared drained by cancel/close.
    { Control c(std::chrono::seconds(10)); std::mutex m; std::condition_variable cv; bool entered=false, unblock=false;
      std::thread worker([&] { Call call(c); assert(call); std::unique_lock<std::mutex> lock(m); entered=true; cv.notify_all(); cv.wait(lock,[&]{return unblock;}); assert(!c.completed(true,true)); });
      { std::unique_lock<std::mutex> lock(m); cv.wait(lock,[&]{return entered;}); }
      c.close(); assert(c.phase()==Phase::draining); assert(!c.quiescent()); assert(!c.enter());
      { std::lock_guard<std::mutex> lock(m); unblock=true; } cv.notify_all(); worker.join(); assert(c.quiescent());
    }
    // Close versus native return must never resurrect admission.
    for (int i=0; i<1000; ++i) { Control c(std::chrono::seconds(10)); assert(c.enter()); std::thread closer([&]{c.close();}); c.leave(); closer.join(); assert(c.quiescent()); assert(!c.enter()); }
}
