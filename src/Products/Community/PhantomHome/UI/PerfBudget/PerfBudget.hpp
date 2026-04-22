#pragma once

// Qt headers first — required by the Q_OBJECT macro expansion.
#include <QObject>

#include <chrono>
#include <cstdint>

namespace ShadowStrike::PhantomHome::UI {

// ---------------------------------------------------------------------------
// PerfBudgetContext
//
// Lightweight QObject bridge that exposes the current animation-pause state
// to QML via a registered context property ("perfBudget").  PerfBudget owns
// the singleton lifetime; consumers must never delete the returned reference.
// ---------------------------------------------------------------------------
class PerfBudgetContext final : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool animationsPaused READ animationsPaused NOTIFY animationsPausedChanged)

public:
    [[nodiscard]] bool animationsPaused() const noexcept;

signals:
    void animationsPausedChanged();

private:
    // Only PerfBudget may mutate the paused flag.
    friend class PerfBudget;
    void setPaused(bool paused);
};

// ---------------------------------------------------------------------------
// PerfBudget
//
// Static-only utility that enforces a startup time budget, applies QtQuick
// engine environment tuning, and propagates window-focus changes to QML so
// that animations can be suspended when the window is inactive.
//
// Typical call sequence from main():
//   PerfBudget::ApplyEngineTuning();      // before QGuiApplication
//   PerfBudget::BeginStartup();           // before QQmlApplicationEngine load
//   // ... engine.load(url) ...
//   PerfBudget::EndStartupAndValidate();  // after first frame is composed
// ---------------------------------------------------------------------------
class [[nodiscard]] PerfBudget final {
public:
    // Marks the beginning of the startup measurement window.
    static void BeginStartup() noexcept;

    // Records the end of startup and validates against kStartupBudget.
    // Debug builds: Q_ASSERT_X fires on budget violation.
    // Release builds: SS_LOG_WARN is emitted.
    static void EndStartupAndValidate() noexcept;

    // Sets Qt / QtQuick environment variables for minimal footprint.
    // Must be called before QGuiApplication is constructed.
    static void ApplyEngineTuning() noexcept;

    // Propagates window active state to QML via PerfBudgetContext::animationsPaused.
    // Connect to the main window's onActiveChanged signal.
    static void OnWindowActiveChanged(bool active) noexcept;

    // Returns the Meyers singleton for the QML context property bridge.
    [[nodiscard]] static PerfBudgetContext& Context() noexcept;

    // Duration of the most recently completed startup sequence.
    [[nodiscard]] static std::chrono::milliseconds LastStartupDuration() noexcept;

    static constexpr std::chrono::milliseconds kStartupBudget{650};
    static constexpr std::size_t               kIdleRamBudgetBytes = 80ULL * 1024ULL * 1024ULL;
    static constexpr int                       kMinFrameRate        = 60;
};

} // namespace ShadowStrike::PhantomHome::UI
