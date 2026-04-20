// PerfBudget.hpp - Self-imposed performance budget enforcement.
//
// ShadowStrike Phantom Home runs on millions of consumer endpoints. Every
// extra millisecond of startup latency and every extra megabyte of resident
// memory directly degrades the user's experience. This header declares a
// process-local performance budget that components can declare at startup
// and a sampler that tracks live RSS / startup latency against it.
//
// The implementation is header-light and intentionally has zero PhantomCore
// engine dependencies so the Tray and UI processes can use it without
// pulling the engine in.
//
// Behavior:
//   * In Debug builds, exceeding a hard limit triggers a Logger::Error
//     and a debug break (DebugBreak()) so a developer cannot ship a
//     regression unnoticed.
//   * In Release builds, the same condition is logged at Error level but
//     does not terminate the process. The telemetry is still captured for
//     post-incident analysis.
//
// Thread safety: All public APIs are safe to call concurrently. The
// sampler runs on its own dedicated thread.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace ShadowStrike::PhantomHome::UI {

struct PerfBudgetLimits {
    std::uint64_t              soft_rss_bytes      = 96  * 1024ull * 1024ull;
    std::uint64_t              hard_rss_bytes      = 192 * 1024ull * 1024ull;
    std::chrono::milliseconds  soft_startup_ms     {300};
    std::chrono::milliseconds  hard_startup_ms     {1000};
    std::chrono::milliseconds  sample_interval     {60'000};
};

struct PerfBudgetSnapshot {
    std::uint64_t              current_rss_bytes   {0};
    std::uint64_t              peak_rss_bytes      {0};
    std::chrono::milliseconds  startup_ms          {0};
    std::uint64_t              soft_breaches       {0};
    std::uint64_t              hard_breaches       {0};
    std::chrono::system_clock::time_point sampled_at{};
};

class PerfBudget {
public:
    [[nodiscard]] static PerfBudget& Instance() noexcept;

    // Records the wall-clock time of the very first call. Subsequent calls
    // are no-ops. Idempotent and thread-safe.
    void MarkProcessStart() noexcept;

    // Records the moment the process becomes "ready" - first usable state
    // for the user. For the Tray this is "icon visible"; for the UI this
    // is "first frame painted". Computes startup latency vs MarkProcessStart
    // and evaluates it against the configured limits.
    void MarkProcessReady() noexcept;

    // Begins background RSS sampling. Idempotent. Stop() is implicit at
    // process teardown (the sampler thread is detached / cooperatively
    // joined in the destructor).
    void Start(PerfBudgetLimits limits, std::string component_name);
    void Stop() noexcept;

    [[nodiscard]] PerfBudgetSnapshot Sample() const noexcept;

    PerfBudget(const PerfBudget&) = delete;
    PerfBudget& operator=(const PerfBudget&) = delete;

private:
    PerfBudget() noexcept;
    ~PerfBudget();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

}  // namespace ShadowStrike::PhantomHome::UI
