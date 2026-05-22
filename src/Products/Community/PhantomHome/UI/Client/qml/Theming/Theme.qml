pragma Singleton
import QtQuick

QtObject {
    // --- Runtime accessibility/performance context ---
    readonly property bool highContrast:
        (typeof hcmCtx !== "undefined" && hcmCtx !== null) ? hcmCtx.enabled : false
    readonly property bool reducedMotion:
        highContrast || ((typeof perfBudget !== "undefined" && perfBudget !== null)
                         ? perfBudget.animationsPaused : false)

    // --- Palette (locked by brand logo: dark phantom body + cyan-blue eye glow) ---
    readonly property color bgDeep:        highContrast ? "#000000" : "#05080F"
    readonly property color bgCanvas:      highContrast ? "#000000" : "#07101D"
    readonly property color bgSurface:     highContrast ? "#000000" : "#0B1220"
    readonly property color bgSurfaceAlt:  highContrast ? "#101820" : "#111B2E"
    readonly property color bgElevated:    highContrast ? "#050A12" : "#12203A"
    readonly property color strokeSubtle:  highContrast ? "#FFFFFF" : "#1E2A44"
    readonly property color strokeStrong:  highContrast ? "#FFFFFF" : "#2F456A"
    readonly property color textPrimary:   highContrast ? "#FFFFFF" : "#EAF2FF"
    readonly property color textSecondary: highContrast ? "#FFFFFF" : "#B4C7EA"
    readonly property color textMuted:     highContrast ? "#D8E7FF" : "#7185A8"
    readonly property color accentCyan:    highContrast ? "#00FFFF" : "#38BDF8"
    readonly property color accentBlue:    highContrast ? "#4DA3FF" : "#1E6FFF"
    readonly property color accentGlow:    highContrast ? "#00FFFF" : "#3FD8FF"
    readonly property color ok:            highContrast ? "#00FF99" : "#22D39A"
    readonly property color warn:          highContrast ? "#FFD84D" : "#F5B544"
    readonly property color crit:          highContrast ? "#FF5C8A" : "#FF5370"
    readonly property color info:          highContrast ? "#00FFFF" : "#60A5FA"
    readonly property color offline:       highContrast ? "#FFFFFF" : "#8FA3C7"

    readonly property color overlayScrim:  highContrast ? "#000000" : "#020612"
    readonly property color focusRingColor: highContrast ? "#FFFFFF" : accentGlow

    // --- Gradients (usable as stop arrays for ShaderEffect / Rectangle.gradient) ---
    readonly property var heroGradientStops: [
        { position: 0.0, color: bgSurface },
        { position: 1.0, color: highContrast ? "#000000" : "#132642" }
    ]

    // --- Typography ---
    readonly property string fontFamily:      "Segoe UI Variable Display, Segoe UI, Inter, system-ui, sans-serif"
    readonly property int    fontSizeDisplay: 28
    readonly property int    fontSizeTitle:   20
    readonly property int    fontSizeBody:    14
    readonly property int    fontSizeLabel:   12
    readonly property int    fontSizeMicro:   11
    readonly property int    fontWeightRegular: Font.Normal
    readonly property int    fontWeightMedium:  Font.Medium
    readonly property int    fontWeightBold:    Font.DemiBold

    // --- Metrics ---
    readonly property int radiusSmall:  6
    readonly property int radiusMedium: 10
    readonly property int radiusLarge:  14
    readonly property int radiusXL:     20
    readonly property int spacingXS: 4
    readonly property int spacingS:  8
    readonly property int spacingM:  12
    readonly property int spacingL:  20
    readonly property int spacingXL: 32

    readonly property int sidebarWidthExpanded:  220
    readonly property int sidebarWidthCollapsed: 64
    readonly property int topBarHeight:          48
    readonly property int controlHeight:         40
    readonly property int touchTarget:           44
    readonly property int cardMinWidth:          280
    readonly property int contentMaxWidth:       1180
    readonly property int statePanelMaxWidth:    420
    readonly property int compactWidth:          760
    readonly property int mediumWidth:           1040
    readonly property real disabledOpacity:      highContrast ? 0.62 : 0.42
    readonly property int focusRingWidth:        highContrast ? 3 : 2

    // --- Motion ---
    readonly property int motionFast:      reducedMotion ? 0 : 120
    readonly property int motionBase:      reducedMotion ? 0 : 180
    readonly property int motionPage:      reducedMotion ? 0 : 220
    readonly property int motionHeadline:  reducedMotion ? 0 : 260
    readonly property int motionHeroPulse: reducedMotion ? 0 : 2400
    readonly property int easingType:      Easing.OutCubic

    // --- State helpers ---
    function alpha(colorValue, opacity) {
        return Qt.rgba(colorValue.r, colorValue.g, colorValue.b, opacity)
    }

    function duration(ms) {
        return reducedMotion ? 0 : ms
    }

    function surfaceColor(elevated, interactive) {
        if (highContrast)
            return interactive ? bgSurfaceAlt : bgSurface
        return elevated ? bgElevated : (interactive ? bgSurfaceAlt : bgSurface)
    }

    function interactiveBorder(hovered, active, severity) {
        if (active)
            return stateColor(severity || "info")
        if (hovered)
            return highContrast ? strokeStrong : alpha(stateColor(severity || "info"), 0.55)
        return strokeSubtle
    }

    function stateColor(state) {
        switch (state) {
        case "on":
        case "healthy":  return ok;
        case "warning":
        case "atRisk":   return warn;
        case "error":
        case "crit":
        case "critical": return crit;
        case "info":     return info;
        case "loading":  return accentCyan;
        case "offline":  return offline;
        case "paused":
        case "off":      return textMuted;
        default:         return textMuted;
        }
    }

    function stateFill(state) {
        const c = stateColor(state)
        return highContrast ? "#000000" : alpha(c, 0.16)
    }

    function isCompact(width) {
        return width > 0 && width < compactWidth
    }

    // --- Headline strings (state-driven rolling copy) ---
    readonly property var headlineStrings: ({
        healthy: [
            qsTr("We are protecting you."),
            qsTr("No threats on your device."),
            qsTr("PhantomSentry is watching in real time."),
            qsTr("All modules are operational.")
        ],
        atRisk: [
            qsTr("Your protection needs attention."),
            qsTr("Some modules are turned off."),
            qsTr("Review recommendations below.")
        ],
        critical: [
            qsTr("Your device is in danger."),
            qsTr("We blocked a threat. Review it now.")
        ]
    })
}
