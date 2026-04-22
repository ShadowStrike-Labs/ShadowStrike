// ShadowStrikePhantomUI — HighContrastContext implementation
// Polls SPI_GETHIGHCONTRAST every 2 000 ms and notifies QML on change.

// Logger first — before any Windows.h pull-ins — to avoid macro conflicts.
// <format> must precede Logger.hpp because Logger.hpp's templates depend on
// std::format_string; Qt headers that we include (QTimer) don't pull it in.
#include <format>
#include <PhantomCore/Utils/Logger.hpp>

#include "HighContrastContext.hpp"

// Windows SDK
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>

#include <QTimer>

namespace ShadowStrike::PhantomHome::UI {

namespace {
constexpr const wchar_t* kLogCat       = L"HighContrastContext";
constexpr int            kPollIntervalMs = 2000;
} // namespace

// ---------------------------------------------------------------------------
// Impl
// ---------------------------------------------------------------------------
struct HighContrastContext::Impl {
    std::atomic<bool> enabled{false};
    QTimer            pollTimer;

    // Query the OS and return the current HCM state.
    [[nodiscard]] static bool QueryHCM() noexcept
    {
        HIGHCONTRASTW hc{};
        hc.cbSize = sizeof(hc);
        if (!::SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(hc), &hc, 0)) {
            // SPI_GETHIGHCONTRAST failing is non-fatal; treat as HCM off.
            SS_LOG_WARN(kLogCat,
                L"SystemParametersInfoW(SPI_GETHIGHCONTRAST) failed — error %lu.",
                ::GetLastError());
            return false;
        }
        return (hc.dwFlags & HCF_HIGHCONTRASTON) != 0;
    }
};

// ---------------------------------------------------------------------------
// HighContrastContext
// ---------------------------------------------------------------------------

HighContrastContext::HighContrastContext()
    : QObject(nullptr)
    , m_impl(std::make_unique<Impl>())
{
    // Establish initial state before the first poll fires.
    m_impl->enabled.store(Impl::QueryHCM(), std::memory_order_release);

    // Wire up the repeating poll.
    m_impl->pollTimer.setInterval(kPollIntervalMs);
    m_impl->pollTimer.setTimerType(Qt::CoarseTimer);

    QObject::connect(&m_impl->pollTimer, &QTimer::timeout, this,
        [this]() noexcept
        {
            const bool current  = Impl::QueryHCM();
            const bool previous = m_impl->enabled.exchange(current, std::memory_order_acq_rel);
            if (previous != current) {
                SS_LOG_INFO(kLogCat,
                    L"High Contrast Mode %ls.",
                    current ? L"enabled" : L"disabled");
                emit enabledChanged();
            }
        });

    m_impl->pollTimer.start();

    SS_LOG_INFO(kLogCat,
        L"HighContrastContext initialised — HCM is currently %ls.",
        m_impl->enabled.load(std::memory_order_relaxed) ? L"ON" : L"OFF");
}

HighContrastContext::~HighContrastContext()
{
    // QTimer::stop() is safe to call from any thread only when the timer
    // lives on the same thread.  The destructor always runs on the GUI
    // thread for a singleton created there.
    m_impl->pollTimer.stop();
}

// static
HighContrastContext& HighContrastContext::Instance()
{
    // Meyers' singleton — thread-safe from C++11 onward.
    static HighContrastContext s_instance;
    return s_instance;
}

bool HighContrastContext::enabled() const noexcept
{
    return m_impl->enabled.load(std::memory_order_relaxed);
}

} // namespace ShadowStrike::PhantomHome::UI
