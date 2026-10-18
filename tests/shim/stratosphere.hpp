/**
 * @file stratosphere.hpp (host test shim)
 * @brief Just enough of <stratosphere.hpp> to build the host-safe ldn/ sources
 *
 * Only tests that compile real sysmodule sources with no other Switch
 * dependency add this directory to their include path. os::Mutex keeps the
 * real semantics that matter here: it is non-recursive, so locking it twice
 * on one thread hangs, as it does in a release build on the console.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>

namespace ams::os {

class Mutex {
public:
    explicit Mutex(bool /*recursive*/) {}
    void lock() { m_mutex.lock(); }
    void unlock() { m_mutex.unlock(); }

private:
    std::mutex m_mutex;
};

struct Tick {
    int64_t ns;
};

struct TimeSpan {
    int64_t ns;
    int64_t GetMilliSeconds() const { return ns / 1000000; }
};

inline Tick GetSystemTick() {
    return {static_cast<int64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count())};
}

inline TimeSpan ConvertToTimeSpan(Tick tick) {
    return {tick.ns};
}

} // namespace ams::os
