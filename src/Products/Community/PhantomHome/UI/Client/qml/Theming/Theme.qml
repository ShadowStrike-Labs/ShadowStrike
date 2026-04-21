pragma Singleton
import QtQuick

/*
 * ShadowStrike Phantom - Theme
 * ----------------------------
 * Enterprise-grade dark palette inspired by Kaspersky Premium's visual
 * language but tuned to ShadowStrike's blue/black identity. The goal is
 * a calm, deep surface stack with zero visible borders by default -
 * depth is conveyed by tone alone, never by a stroke.
 *
 * Rules:
 *   - Cards never carry a border. They sit on bg1 using bg2 tone.
 *   - Hover elevates one step (bg2 -> bg3). Selected state uses a very
 *     subtle accent tint, not a hard outline.
 *   - Accent blue is reserved for primary CTAs, active selection, and
 *     the protection shield halo. Status colors (green/amber/red) are
 *     used only for security state - never decoration.
 *   - Typography is quiet: strong titles, muted body, mono only where
 *     numeric alignment matters.
 */
QtObject {
    id: root

    property bool dark: true

    // --- Backgrounds (depth stack) ----------------------------------------
    // Deep charcoal with a faint cool tint. No pure black.
    readonly property color bg0:        dark ? "#0B0F16" : "#F3F6FC"   // window base
    readonly property color bg1:        dark ? "#11161F" : "#FFFFFF"   // sidebar / top panel
    readonly property color bg2:        dark ? "#181E29" : "#F0F4FA"   // card surface
    readonly property color bg3:        dark ? "#202738" : "#E4EAF4"   // card hover / elevated
    readonly property color bgHeader:   dark ? "#0B0F16" : "#E5ECF7"   // title bar tint
    readonly property color bgGradTop:  dark ? "#12182A" : "#F9FBFF"
    readonly property color bgGradBot:  dark ? "#0B0F16" : "#ECF1FA"

    // --- Strokes (used sparingly - only hairlines / separators) -----------
    readonly property color stroke:      dark ? "#1D2434" : "#D1DAEA"
    readonly property color strokeSoft:  dark ? "#151B27" : "#E1E7F3"
    readonly property color strokeHot:   dark ? "#3B82F6" : "#3B82F6"

    // --- Typography colors ------------------------------------------------
    readonly property color text:        dark ? "#E7ECF5" : "#0D1428"
    readonly property color textStrong:  dark ? "#FFFFFF" : "#050A18"
    readonly property color textMuted:   dark ? "#8492AC" : "#526085"
    readonly property color textDim:     dark ? "#5D6B87" : "#7A89A9"

    // --- Primary accent (blue signal) -------------------------------------
    // Tuned against bg1/bg2 for WCAG AA on muted UI chrome.
    readonly property color accent:       "#3B82F6"
    readonly property color accentHover:  "#5B96F8"
    readonly property color accentPress:  "#2563EB"
    readonly property color accentAlt:    "#60A5FA"
    readonly property color accentGlow:   "#93C5FD"
    readonly property color accentDeep:   "#1E3A8A"

    // --- Status colors (protection state only) ----------------------------
    readonly property color success:     "#22C55E"
    readonly property color warning:     "#F59E0B"
    readonly property color danger:      "#EF4444"

    readonly property color stateGreen:  success
    readonly property color stateAmber:  warning
    readonly property color stateRed:    danger
    readonly property color statePause:  textMuted

    // --- AI pill (used as a small purple chip on AI-enhanced modules) ----
    readonly property color aiPillBg:    Qt.rgba(0.66, 0.56, 0.94, 0.22)
    readonly property color aiPillText:  "#CBB6FC"

    // --- Overlays ---------------------------------------------------------
    readonly property color overlayHover:    Qt.rgba(0.23, 0.51, 0.96, 0.08)
    readonly property color overlayPressed:  Qt.rgba(0.23, 0.51, 0.96, 0.16)
    readonly property color overlayDanger:   Qt.rgba(0.94, 0.27, 0.27, 0.14)

    // --- Metrics -----------------------------------------------------------
    readonly property int unit: 4
    readonly property int sp1:  unit          //  4
    readonly property int sp2:  unit * 2      //  8
    readonly property int sp3:  unit * 3      // 12
    readonly property int sp4:  unit * 4      // 16
    readonly property int sp5:  unit * 5      // 20
    readonly property int sp6:  unit * 6      // 24
    readonly property int sp8:  unit * 8      // 32
    readonly property int sp10: unit * 10     // 40
    readonly property int sp12: unit * 12     // 48
    readonly property int sp16: unit * 16     // 64

    readonly property int radiusXs:  4
    readonly property int radiusSm:  8
    readonly property int radiusMd:  14
    readonly property int radiusLg:  18
    readonly property int radiusXl:  26

    readonly property int titleBarHeight: 44
    readonly property int sidebarWidth:   232

    // --- Typography --------------------------------------------------------
    readonly property string fontFamily: "Segoe UI Variable Display, Segoe UI Variable, Segoe UI, Inter, Arial"
    readonly property string fontFamilyMono: "Cascadia Mono, Consolas, Menlo, monospace"

    readonly property int fontDisplay:  30
    readonly property int fontTitle:    22
    readonly property int fontHeading:  16
    readonly property int fontSubhead:  14
    readonly property int fontBody:     13
    readonly property int fontSmall:    11
    readonly property int fontCaption:  10

    // --- Motion tokens -----------------------------------------------------
    readonly property int motionFast:    120
    readonly property int motionNormal:  220
    readonly property int motionSlow:    420
    readonly property int motionBreath: 1600
}
