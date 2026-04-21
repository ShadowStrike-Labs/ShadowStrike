pragma Singleton
import QtQuick

/*
 * ShadowStrike Phantom - Theme
 * ----------------------------
 * Dark-first blue/black enterprise palette. All design tokens live here
 * so every surface across the app is visually consistent. Nothing hard-
 * codes colors or sizes elsewhere.
 *
 * Palette direction:
 *   - Backgrounds are deep navy / near-black with just enough blue cast
 *     to read as "cool steel" rather than flat grey.
 *   - Primary accent is an electric signal-blue used only for the most
 *     important affordances (selected state, primary CTAs, focus).
 *   - Status colors (green/amber/red) are reserved for protection state
 *     and must never be used as decoration.
 */
QtObject {
    id: root

    property bool dark: true

    // --- Backgrounds (depth stack) ----------------------------------------
    readonly property color bg0:        dark ? "#05080F" : "#F3F6FC"   // window base
    readonly property color bg1:        dark ? "#0B1322" : "#FFFFFF"   // sidebar / top panel
    readonly property color bg2:        dark ? "#111C33" : "#E9EFF8"   // card surface
    readonly property color bg3:        dark ? "#18264A" : "#DCE5F3"   // card elevated / hover
    readonly property color bgHeader:   dark ? "#080D1A" : "#E5ECF7"   // title bar tint
    readonly property color bgGradTop:  dark ? "#0C1528" : "#F9FBFF"
    readonly property color bgGradBot:  dark ? "#05080F" : "#ECF1FA"

    // --- Strokes & separators ---------------------------------------------
    readonly property color stroke:      dark ? "#1B2A4E" : "#D1DAEA"
    readonly property color strokeSoft:  dark ? "#13203D" : "#E1E7F3"
    readonly property color strokeHot:   dark ? "#2B7BFF" : "#2B7BFF"

    // --- Typography colors -------------------------------------------------
    readonly property color text:        dark ? "#ECF1FB" : "#0D1428"
    readonly property color textStrong:  dark ? "#FFFFFF" : "#050A18"
    readonly property color textMuted:   dark ? "#8091B4" : "#526085"
    readonly property color textDim:     dark ? "#5D6C8E" : "#7A89A9"

    // --- Primary accent (blue signal) -------------------------------------
    readonly property color accent:       "#2B7BFF"    // primary electric blue
    readonly property color accentHover:  "#4C92FF"
    readonly property color accentPress:  "#1F66E6"
    readonly property color accentAlt:    "#4BA3FF"    // lighter highlight / links
    readonly property color accentGlow:   "#7EBEFF"    // soft halo
    readonly property color accentDeep:   "#0F2A6E"    // deep navy for shaded fills

    // --- Status colors (protection state only) ----------------------------
    readonly property color success:     "#2DE37F"
    readonly property color warning:     "#FFC247"
    readonly property color danger:      "#FF4F6E"

    readonly property color stateGreen:  success
    readonly property color stateAmber:  warning
    readonly property color stateRed:    danger
    readonly property color statePause:  textMuted

    // --- Overlays ---------------------------------------------------------
    readonly property color overlayHover:    Qt.rgba(0.17, 0.48, 1.00, 0.08)
    readonly property color overlayPressed:  Qt.rgba(0.17, 0.48, 1.00, 0.16)
    readonly property color overlayDanger:   Qt.rgba(1.00, 0.31, 0.43, 0.14)

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
    readonly property int radiusMd:  12
    readonly property int radiusLg:  18
    readonly property int radiusXl:  26

    readonly property int titleBarHeight: 40
    readonly property int sidebarWidth:   224

    // --- Typography --------------------------------------------------------
    readonly property string fontFamily: "Segoe UI Variable Display, Segoe UI Variable, Segoe UI, Inter, Arial"
    readonly property string fontFamilyMono: "Cascadia Mono, Consolas, Menlo, monospace"

    readonly property int fontDisplay:  28
    readonly property int fontTitle:    22
    readonly property int fontHeading:  16
    readonly property int fontBody:     13
    readonly property int fontSmall:    11
    readonly property int fontCaption:  10

    // --- Motion tokens -----------------------------------------------------
    readonly property int motionFast:    120
    readonly property int motionNormal:  220
    readonly property int motionSlow:    420
    readonly property int motionBreath: 1600
}
