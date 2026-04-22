#pragma once
// ShadowStrikePhantomUI — HighContrastContext
// QObject bridge that polls the Windows High Contrast Mode (HCM) flag and
// exposes it to QML via the "hcmCtx" context property.

#include <QObject>
#include <memory>

namespace ShadowStrike::PhantomHome::UI {

// ---------------------------------------------------------------------------
// HighContrastContext
//
// Meyers singleton.  Register the instance as a QML context property:
//
//   engine.rootContext()->setContextProperty(
//       "hcmCtx", &HighContrastContext::Instance());
//
// QML side: the HighContrast.qml singleton reads hcmCtx.enabled.
// ---------------------------------------------------------------------------
class HighContrastContext final : public QObject {
    Q_OBJECT
    Q_PROPERTY(bool enabled READ enabled NOTIFY enabledChanged)

public:
    [[nodiscard]] static HighContrastContext& Instance();

    // Returns true when Windows High Contrast Mode is currently active.
    [[nodiscard]] bool enabled() const noexcept;

    ~HighContrastContext() override;

    // Non-copyable / non-movable singleton.
    HighContrastContext(const HighContrastContext&)            = delete;
    HighContrastContext& operator=(const HighContrastContext&) = delete;
    HighContrastContext(HighContrastContext&&)                 = delete;
    HighContrastContext& operator=(HighContrastContext&&)      = delete;

signals:
    void enabledChanged();

private:
    HighContrastContext();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomHome::UI
