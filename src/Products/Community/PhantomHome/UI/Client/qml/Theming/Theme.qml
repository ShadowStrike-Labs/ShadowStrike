pragma Singleton
import QtQuick

QtObject {
    // --- Palette (locked by brand logo: dark phantom body + cyan-blue eye glow) ---
    readonly property color bgDeep:        "#05080F"
    readonly property color bgSurface:     "#0B1220"
    readonly property color bgSurfaceAlt:  "#111B2E"
    readonly property color strokeSubtle:  "#1E2A44"
    readonly property color textPrimary:   "#EAF2FF"
    readonly property color textSecondary: "#9BB0D1"
    readonly property color textMuted:     "#5C6E8F"
    readonly property color accentCyan:    "#38BDF8"
    readonly property color accentBlue:    "#1E6FFF"
    readonly property color accentGlow:    "#3FD8FF"
    readonly property color ok:            "#22D39A"
    readonly property color warn:          "#F5B544"
    readonly property color crit:          "#FF5370"

    // --- Gradients (usable as stop arrays for ShaderEffect / Rectangle.gradient) ---
    readonly property var heroGradientStops: [
        { position: 0.0, color: "#0B1220" },
        { position: 1.0, color: "#132642" }
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

    // --- Motion ---
    readonly property int motionFast:      120
    readonly property int motionBase:      180
    readonly property int motionPage:      220
    readonly property int motionHeadline:  260
    readonly property int motionHeroPulse: 2400
    readonly property int easingType:      Easing.OutCubic

    // --- State helpers ---
    function stateColor(state) {
        switch (state) {
        case "healthy":  return ok;
        case "atRisk":   return warn;
        case "critical": return crit;
        default:         return textMuted;
        }
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
