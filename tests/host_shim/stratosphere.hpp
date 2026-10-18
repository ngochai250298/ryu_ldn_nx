/**
 * @file stratosphere.hpp
 * @brief Host stand-in for <stratosphere.hpp>, for the bsd proxy test suite
 *
 * Provides only what bsd/proxy_socket.cpp, bsd/proxy_socket_manager.cpp and
 * bsd/ephemeral_port_pool.cpp use, mapped onto the C++ standard library, so
 * the host tests compile and exercise the real proxy sources. It is on the
 * include path of the bsd-proxy suite only.
 *
 * @copyright Copyright (c) 2026 ryu_ldn_nx contributors
 * @license GPL-2.0-or-later
 */

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;

namespace ams {

class Result {
public:
    constexpr Result(u32 value = 0) : m_value(value) {}
    constexpr u32 GetValue() const { return m_value; }
private:
    u32 m_value;
};

template<typename... Ts>
constexpr void Unused(const Ts&...) {}

class TimeSpan {
public:
    constexpr TimeSpan(s64 ns = 0) : m_ns(ns) {}
    static constexpr TimeSpan FromNanoSeconds(s64 v) { return TimeSpan(v); }
    static constexpr TimeSpan FromMilliSeconds(s64 v) { return TimeSpan(v * 1000000); }
    static constexpr TimeSpan FromSeconds(s64 v) { return TimeSpan(v * 1000000000); }
    constexpr s64 GetNanoSeconds() const { return m_ns; }
    constexpr s64 GetMilliSeconds() const { return m_ns / 1000000; }
    constexpr TimeSpan operator+(TimeSpan o) const { return TimeSpan(m_ns + o.m_ns); }
    constexpr TimeSpan operator-(TimeSpan o) const { return TimeSpan(m_ns - o.m_ns); }
    constexpr bool operator<(TimeSpan o) const { return m_ns < o.m_ns; }
    constexpr bool operator<=(TimeSpan o) const { return m_ns <= o.m_ns; }
    constexpr bool operator>(TimeSpan o) const { return m_ns > o.m_ns; }
    constexpr bool operator>=(TimeSpan o) const { return m_ns >= o.m_ns; }
    constexpr bool operator==(TimeSpan o) const { return m_ns == o.m_ns; }
private:
    s64 m_ns;
};

namespace os {

class Tick {
public:
    explicit Tick(s64 ns) : m_ns(ns) {}
    TimeSpan ToTimeSpan() const { return TimeSpan(m_ns); }
private:
    s64 m_ns;
};

inline Tick GetSystemTick() {
    return Tick(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

class Mutex {
public:
    explicit Mutex(bool /*recursive*/) {}
    void lock() { m_mutex.lock(); }
    void unlock() { m_mutex.unlock(); }
    bool try_lock() { return m_mutex.try_lock(); }
private:
    std::mutex m_mutex;
};

class SdkMutex {
public:
    void lock() { m_mutex.lock(); }
    void unlock() { m_mutex.unlock(); }
    bool try_lock() { return m_mutex.try_lock(); }
    std::mutex& native() { return m_mutex; }
private:
    std::mutex m_mutex;
};

class SdkConditionVariable {
public:
    bool TimedWait(SdkMutex& m, TimeSpan timeout) {
        std::unique_lock<std::mutex> lk(m.native(), std::adopt_lock);
        const bool ok = m_cv.wait_for(lk, std::chrono::nanoseconds(timeout.GetNanoSeconds()))
                        == std::cv_status::no_timeout;
        lk.release();
        return ok;
    }
    void Broadcast() { m_cv.notify_all(); }
private:
    std::condition_variable m_cv;
};

enum EventClearMode { EventClearMode_ManualClear, EventClearMode_AutoClear };

class Event {
public:
    explicit Event(EventClearMode mode) : m_auto(mode == EventClearMode_AutoClear) {}
    void Signal() { std::lock_guard<std::mutex> lk(m_mutex); m_set = true; m_cv.notify_all(); }
    void Clear() { std::lock_guard<std::mutex> lk(m_mutex); m_set = false; }
    void Wait() {
        std::unique_lock<std::mutex> lk(m_mutex);
        m_cv.wait(lk, [&] { return m_set; });
        if (m_auto) m_set = false;
    }
    bool TimedWait(TimeSpan timeout) {
        std::unique_lock<std::mutex> lk(m_mutex);
        const bool ok = m_cv.wait_for(lk, std::chrono::nanoseconds(timeout.GetNanoSeconds()),
                                      [&] { return m_set; });
        if (ok && m_auto) m_set = false;
        return ok;
    }
private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_set = false;
    bool m_auto;
};

} // namespace os
} // namespace ams

#define R_SUCCEEDED(r) ((r).GetValue() == 0)
#define R_FAILED(r) (!R_SUCCEEDED(r))
#define R_SUCCEED() return ::ams::Result(0)
#define R_THROW(r) return ::ams::Result(r)
#define R_RETURN(r) return (r)
#define R_TRY(expr) do { const ::ams::Result _r = (expr); if (R_FAILED(_r)) { return _r; } } while (0)
#define AMS_UNUSED(...) ::ams::Unused(__VA_ARGS__)
