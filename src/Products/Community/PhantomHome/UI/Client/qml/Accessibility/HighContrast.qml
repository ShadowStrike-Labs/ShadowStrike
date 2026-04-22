// ShadowStrike PhantomHome — HighContrast singleton
// Exposes Windows High Contrast Mode state to QML.
// Backed by HighContrastContext (C++ QObject registered as "hcmCtx").

pragma Singleton
import QtQuick

QtObject {
    // True when Windows HCM is active; false otherwise.
    // Pages should guard override colors behind this property.
    readonly property bool enabled: hcmCtx ? hcmCtx.enabled : false
}
