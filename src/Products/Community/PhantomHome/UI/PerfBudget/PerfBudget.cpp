// ShadowStrikePhantomUI — PerfBudget implementation
// Enforces UI startup time budget and applies QtQuick engine tuning.

#include "PerfBudget.hpp"

// Logger must come before any Qt headers that pull in windows.h with
// conflicting macros, so include it first via its SolutionDir-relative path.
#include <PhantomCore/Utils/Logger.hpp>

#include <atomic>
#include <chrono>

#include <QCoreApplication>
#include <QGuiApplication>

// The generated MOC file is compiled separately via the CustomBuild step in
// the vcxproj.  No manual #include of the moc output is needed here because
// moc_PerfBudget.cpp is a standalone translation unit in the ItemGroup.

namespace ShadowStrike::PhantomHome::UI {

// ---------------------------------------------------------------------------
// Module-private state
// ---------------------------------------------------------------------------
namespace {

// time_point is trivially copyable, so std::atomic is well-formed.
std::atomic<std::chrono::steady_clock::time_point> s_startupBegin{};

// milliseconds wraps a long long — trivially copyable.
std::atomic<std::chrono::milliseconds> s_lastStartupDuration{std::chrono::milliseconds{0}};

// Tracks whether animations are currently suppressed.
std::atomic<bool> s_animationsPaused{false};

constexpr const wchar_t* kLogCategory = L"PerfBudget";

} // namespace

// ---------------------------------------------------------------------------
// PerfBudgetContext
// ---------------------------------------------------------------------------

bool PerfBudgetContext::animationsPaused() const noexcept
{
    return s_animationsPaused.load(std::memory_order_relaxed);
}

void PerfBudgetContext::setPaused(bool paused)
{
    const bool previous = s_animationsPaused.exchange(paused, std::memory_order_acq_rel);
    if (previous != paused) {
        emit animationsPausedChanged();
    }
}

// ---------------------------------------------------------------------------
// PerfBudget
// ---------------------------------------------------------------------------

void PerfBudget::BeginStartup() noexcept
{
    s_startupBegin.store(std::chrono::steady_clock::now(), std::memory_order_relaxed);
    SS_LOG_INFO(kLogCategory, L"UI startup budget window opened.");
}

void PerfBudget::EndStartupAndValidate() noexcept
{
    const auto end     = std::chrono::steady_clock::now();
    const auto begin   = s_startupBegin.load(std::memory_order_relaxed);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin);

    s_lastStartupDuration.store(elapsed, std::memory_order_relaxed);

    if (elapsed > kStartupBudget) {
#if defined(_DEBUG)
        // In debug builds, fail loudly so the violation cannot be ignored.
        Q_ASSERT_X(
            false,
            "PerfBudget::EndStartupAndValidate",
            "UI startup exceeded the 650 ms budget. "
            "Investigate slow QML load, disk I/O stalls, or V4 JIT cache misses.");
#else
        SS_LOG_WARN(kLogCategory,
            L"UI startup took %lld ms, exceeding the %lld ms budget. "
            L"Investigate slow QML load, disk I/O stalls, or V4 JIT cache misses.",
            static_cast<long long>(elapsed.count()),
            static_cast<long long>(kStartupBudget.count()));
#endif
    } else {
        SS_LOG_INFO(kLogCategory,
            L"UI startup completed in %lld ms (budget: %lld ms).",
            static_cast<long long>(elapsed.count()),
            static_cast<long long>(kStartupBudget.count()));
    }
}

void PerfBudget::ApplyEngineTuning() noexcept
{
    // Use the threaded render loop for consistent frame pacing and to keep
    // the main thread free for event processing.
    qputenv("QSG_RENDER_LOOP", "threaded");

    // Basic style has the smallest QML runtime overhead compared with
    // Fusion, Universal, or Material — suitable for a custom-painted UI.
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");

    // Honour OS DPI setting so the UI is crisp on high-DPI displays.
    qputenv("QT_ENABLE_HIGHDPI_SCALING", "1");

    // Cap the V4 GC stack at 2 MiB to avoid large virtual-address reservation
    // on endpoints that may be memory-constrained.
    qputenv("QV4_GC_MAX_STACK_SIZE", "2097152");

    // Enable the V4 bytecode disk cache for faster cold starts.  Setting this
    // to "0" means "do NOT disable" (double-negative env var naming).
    qputenv("QML_DISABLE_DISK_CACHE", "0");

    // Qt::AA_UseDesktopOpenGL is intentionally NOT set here.
    // On Windows, Qt 6 defaults to Direct3D 11 via the RHI abstraction layer,
    // which is better integrated with the OS compositor (DWM) and avoids
    // OpenGL driver defects that are common on endpoint machines with minimal
    // or OEM GPU driver installations.  Forcing OpenGL would degrade
    // compatibility and performance on a significant fraction of the fleet.

    SS_LOG_INFO(kLogCategory, L"QtQuick engine tuning applied.");
}

void PerfBudget::OnWindowActiveChanged(bool active) noexcept
{
    // Translate window-active state into an animation-pause signal.
    // QML consumers bind to perfBudget.animationsPaused to suspend
    // non-essential animations when the window is in the background.
    Context().setPaused(!active);
}

PerfBudgetContext& PerfBudget::Context() noexcept
{
    // Meyers' singleton — constructed on first call, destroyed at exit.
    static PerfBudgetContext s_ctx;
    return s_ctx;
}

std::chrono::milliseconds PerfBudget::LastStartupDuration() noexcept
{
    return s_lastStartupDuration.load(std::memory_order_relaxed);
}

} // namespace ShadowStrike::PhantomHome::UI
