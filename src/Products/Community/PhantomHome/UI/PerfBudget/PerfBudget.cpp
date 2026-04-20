// PerfBudget.cpp - Implementation of the process-local perf budget tracker.

#include "PerfBudget.hpp"

#include "PhantomCore/Utils/Logger.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#pragma comment(lib, "psapi.lib")

namespace ShadowStrike::PhantomHome::UI {

namespace {

[[nodiscard]] std::uint64_t QueryWorkingSetBytes() noexcept {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                              sizeof(pmc))) {
        return 0;
    }
    return static_cast<std::uint64_t>(pmc.WorkingSetSize);
}

}  // namespace

struct PerfBudget::Impl {
    mutable std::mutex                          mu;
    PerfBudgetLimits                            limits{};
    std::string                                 component;
    std::chrono::steady_clock::time_point       process_start{};
    std::chrono::steady_clock::time_point       process_ready{};
    std::atomic<bool>                           start_marked{false};
    std::atomic<bool>                           ready_marked{false};
    std::atomic<bool>                           running{false};
    std::atomic<std::uint64_t>                  peak_rss{0};
    std::atomic<std::uint64_t>                  soft_breaches{0};
    std::atomic<std::uint64_t>                  hard_breaches{0};

    std::thread                                 sampler;
    std::condition_variable                     wake;
    std::mutex                                  wake_mu;
    std::atomic<bool>                           stop_flag{false};
};

PerfBudget& PerfBudget::Instance() noexcept {
    static PerfBudget s_instance;
    return s_instance;
}

PerfBudget::PerfBudget() noexcept : m_impl(std::make_unique<Impl>()) {}

PerfBudget::~PerfBudget() {
    Stop();
}

void PerfBudget::MarkProcessStart() noexcept {
    bool expected = false;
    if (!m_impl->start_marked.compare_exchange_strong(expected, true)) {
        return;
    }
    m_impl->process_start = std::chrono::steady_clock::now();
}

void PerfBudget::MarkProcessReady() noexcept {
    bool expected = false;
    if (!m_impl->ready_marked.compare_exchange_strong(expected, true)) {
        return;
    }
    m_impl->process_ready = std::chrono::steady_clock::now();

    if (!m_impl->start_marked.load(std::memory_order_acquire)) {
        return;
    }

    const auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
        m_impl->process_ready - m_impl->process_start);

    std::chrono::milliseconds hard;
    std::chrono::milliseconds soft;
    std::string component;
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        hard      = m_impl->limits.hard_startup_ms;
        soft      = m_impl->limits.soft_startup_ms;
        component = m_impl->component;
    }
    if (component.empty()) component = "PhantomHome.UI";

    if (hard.count() > 0 && delta > hard) {
        m_impl->hard_breaches.fetch_add(1, std::memory_order_relaxed);
        Utils::Logger::Error(
            "[PerfBudget] {}: HARD startup budget breached: {} ms > {} ms",
            component, static_cast<long long>(delta.count()),
            static_cast<long long>(hard.count()));
#if defined(_DEBUG)
        if (IsDebuggerPresent()) DebugBreak();
#endif
    } else if (soft.count() > 0 && delta > soft) {
        m_impl->soft_breaches.fetch_add(1, std::memory_order_relaxed);
        Utils::Logger::Warn(
            "[PerfBudget] {}: soft startup budget exceeded: {} ms > {} ms",
            component, static_cast<long long>(delta.count()),
            static_cast<long long>(soft.count()));
    } else {
        Utils::Logger::Info(
            "[PerfBudget] {}: startup {} ms (soft {} ms, hard {} ms)",
            component, static_cast<long long>(delta.count()),
            static_cast<long long>(soft.count()),
            static_cast<long long>(hard.count()));
    }
}

void PerfBudget::Start(PerfBudgetLimits limits, std::string component_name) {
    {
        std::lock_guard<std::mutex> lk(m_impl->mu);
        m_impl->limits    = limits;
        m_impl->component = component_name.empty() ? std::string{"PhantomHome.UI"}
                                                   : std::move(component_name);
    }

    bool expected = false;
    if (!m_impl->running.compare_exchange_strong(expected, true)) {
        return;
    }
    m_impl->stop_flag.store(false, std::memory_order_release);

    m_impl->sampler = std::thread([this] {
        const std::chrono::milliseconds interval = [&] {
            std::lock_guard<std::mutex> lk(m_impl->mu);
            return m_impl->limits.sample_interval;
        }();

        for (;;) {
            std::unique_lock<std::mutex> lk(m_impl->wake_mu);
            if (m_impl->wake.wait_for(lk, interval, [&] {
                    return m_impl->stop_flag.load(std::memory_order_acquire);
                })) {
                return;
            }
            lk.unlock();

            const std::uint64_t rss = QueryWorkingSetBytes();
            if (rss == 0) continue;

            std::uint64_t prev = m_impl->peak_rss.load(std::memory_order_relaxed);
            while (rss > prev &&
                   !m_impl->peak_rss.compare_exchange_weak(prev, rss,
                       std::memory_order_relaxed)) {
            }

            std::uint64_t hard;
            std::uint64_t soft;
            std::string   component;
            {
                std::lock_guard<std::mutex> ll(m_impl->mu);
                hard      = m_impl->limits.hard_rss_bytes;
                soft      = m_impl->limits.soft_rss_bytes;
                component = m_impl->component;
            }

            if (hard > 0 && rss > hard) {
                m_impl->hard_breaches.fetch_add(1, std::memory_order_relaxed);
                Utils::Logger::Error(
                    "[PerfBudget] {}: HARD RSS budget breached: {} MB > {} MB",
                    component,
                    static_cast<long long>(rss / (1024ull * 1024ull)),
                    static_cast<long long>(hard / (1024ull * 1024ull)));
#if defined(_DEBUG)
                if (IsDebuggerPresent()) DebugBreak();
#endif
            } else if (soft > 0 && rss > soft) {
                m_impl->soft_breaches.fetch_add(1, std::memory_order_relaxed);
                Utils::Logger::Warn(
                    "[PerfBudget] {}: soft RSS budget exceeded: {} MB > {} MB",
                    component,
                    static_cast<long long>(rss / (1024ull * 1024ull)),
                    static_cast<long long>(soft / (1024ull * 1024ull)));
            }
        }
    });
}

void PerfBudget::Stop() noexcept {
    bool expected = true;
    if (!m_impl->running.compare_exchange_strong(expected, false)) {
        return;
    }
    {
        std::lock_guard<std::mutex> lk(m_impl->wake_mu);
        m_impl->stop_flag.store(true, std::memory_order_release);
    }
    m_impl->wake.notify_all();
    if (m_impl->sampler.joinable()) {
        try {
            m_impl->sampler.join();
        } catch (...) {
            // Defensive: never throw from a destructor / shutdown path.
        }
    }
}

PerfBudgetSnapshot PerfBudget::Sample() const noexcept {
    PerfBudgetSnapshot snap{};
    snap.current_rss_bytes = QueryWorkingSetBytes();
    snap.peak_rss_bytes    = m_impl->peak_rss.load(std::memory_order_relaxed);
    snap.soft_breaches     = m_impl->soft_breaches.load(std::memory_order_relaxed);
    snap.hard_breaches     = m_impl->hard_breaches.load(std::memory_order_relaxed);
    snap.sampled_at        = std::chrono::system_clock::now();
    if (m_impl->ready_marked.load(std::memory_order_acquire) &&
        m_impl->start_marked.load(std::memory_order_acquire)) {
        snap.startup_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            m_impl->process_ready - m_impl->process_start);
    }
    return snap;
}

}  // namespace ShadowStrike::PhantomHome::UI
