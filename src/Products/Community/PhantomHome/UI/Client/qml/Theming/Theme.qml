pragma Singleton
import QtQuick

/*
 * ShadowStrike Phantom — design tokens.
 * Dark-first palette; light variant flips via property `dark`.
 * Spacing grid = 4 px.
 */
QtObject {
    id: root

    property bool dark: true

    // --- Colors ------------------------------------------------------------
    readonly property color bg0:       dark ? "#0B1020" : "#F7F8FB"
    readonly property color bg1:       dark ? "#111833" : "#FFFFFF"
    readonly property color bg2:       dark ? "#1A2246" : "#EEF1F8"
    readonly property color stroke:    dark ? "#2C3566" : "#D7DEEB"
    readonly property color text:      dark ? "#E6EAF5" : "#0F172A"
    readonly property color textMuted: dark ? "#9AA5C4" : "#475569"

    readonly property color accent:    "#3B82F6"
    readonly property color accentAlt: "#6EE7F9"
    readonly property color success:   "#22C55E"
    readonly property color warning:   "#F59E0B"
    readonly property color danger:    "#EF4444"

    readonly property color stateGreen: success
    readonly property color stateAmber: warning
    readonly property color stateRed:   danger
    readonly property color statePause: textMuted

    // --- Metrics -----------------------------------------------------------
    readonly property int unit: 4
    readonly property int sp1:  unit
    readonly property int sp2:  unit * 2
    readonly property int sp3:  unit * 3
    readonly property int sp4:  unit * 4
    readonly property int sp6:  unit * 6
    readonly property int sp8:  unit * 8

    readonly property int radiusSm: 6
    readonly property int radiusMd: 10
    readonly property int radiusLg: 16

    // --- Typography --------------------------------------------------------
    readonly property string fontFamily: "Segoe UI Variable, Segoe UI, Inter, Arial"
    readonly property int   fontTitle:   20
    readonly property int   fontHeading: 15
    readonly property int   fontBody:    13
    readonly property int   fontSmall:   11

    // --- Motion ------------------------------------------------------------
    readonly property int   motionFast:   140
    readonly property int   motionNormal: 220
    readonly property int   motionSlow:   420
}
