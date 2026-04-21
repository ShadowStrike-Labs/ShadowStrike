import QtQuick
import QtQuick.Shapes
import "../Theming"

/*
 * Iconed
 * ------
 * Vector-only icon renderer. Emoji glyphs look inconsistent across
 * Windows font stacks and lightens the entire surface; we render a
 * small library of geometric paths via QtQuick.Shapes so every
 * module, page and button stays on-palette under any DPI.
 *
 * Inputs
 *   iconName : string  – logical name ("shield", "lock", "globe", ...)
 *   size     : int     – pixel edge (square)
 *   tint     : color   – stroke/fill tint
 *
 * Unknown names fall back to a safe square-ring glyph so layout
 * never collapses.
 */
Item {
    id: root

    property string iconName: "shield"
    property int    size:     24
    property color  tint:     Theme.accentAlt
    property real   strokeW:  1.7

    implicitWidth:  size
    implicitHeight: size

    Shape {
        anchors.fill: parent
        antialiasing: true
        smooth: true
        layer.enabled: true
        layer.samples: 4

        // Every path is authored in a 24x24 canvas and scaled via
        // the enclosing Item size. Keeps the math readable.
        property real s: Math.min(root.width, root.height) / 24.0

        // ---- shield ------------------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: Qt.rgba(root.tint.r, root.tint.g, root.tint.b, 0.18)
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M12 2 L20 5 V12 C20 17 16.5 20.5 12 22 C7.5 20.5 4 17 4 12 V5 Z" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "shield"
        }

        // ---- lock --------------------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M6 11 H18 V20 H6 Z  M8 11 V8 A4 4 0 0 1 16 8 V11" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "lock"
        }

        // ---- globe -------------------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M12 2 A10 10 0 1 1 11.99 2 Z  M2 12 H22  M12 2 C7 7 7 17 12 22 C17 17 17 7 12 2" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "globe"
        }

        // ---- network (broadcast) ----------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M3 12 Q12 3 21 12  M6 15 Q12 9 18 15  M9 18 Q12 15 15 18  M12 21 L12 21.01" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "network"
        }

        // ---- mail --------------------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M3 6 H21 V18 H3 Z  M3 6 L12 13 L21 6" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "mail"
        }

        // ---- eye (privacy) ----------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M2 12 C5 6 9 4 12 4 C15 4 19 6 22 12 C19 18 15 20 12 20 C9 20 5 18 2 12 Z  M12 9 A3 3 0 1 1 11.99 9 Z" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "eye"
        }

        // ---- bolt (exploit) ---------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: Qt.rgba(root.tint.r, root.tint.g, root.tint.b, 0.15)
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M13 2 L4 14 H11 L10 22 L20 10 H13 Z" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "bolt"
        }

        // ---- code (script) ----------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M8 7 L3 12 L8 17  M16 7 L21 12 L16 17  M14 4 L10 20" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "code"
        }

        // ---- usb ---------------------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M12 22 V10  M12 10 L8 6 H16 Z  M12 16 L7 13 V18 H9  M12 14 L16 12 V16" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "usb"
        }

        // ---- home (iot) -------------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M3 11 L12 3 L21 11  M5 10 V21 H19 V10  M10 21 V14 H14 V21" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "home"
        }

        // ---- card (banking) ---------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M3 6 H21 V18 H3 Z  M3 10 H21  M6 14 H10  M14 14 H18" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "card"
        }

        // ---- key (password) --------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M8 12 A4 4 0 1 1 8.01 12 Z  M11 12 L21 12  M18 12 V15  M15 12 V15" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "key"
        }

        // ---- user (identity) --------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M12 11 A4 4 0 1 1 11.99 11 Z  M4 21 C4 16 8 14 12 14 C16 14 20 16 20 21" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "user"
        }

        // ---- radar (realtime) -------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M12 12 m-9 0 a9 9 0 1 1 18 0 a9 9 0 1 1 -18 0  M12 12 L19 7  M12 12 m-5 0 a5 5 0 1 1 10 0" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "radar"
        }

        // ---- cog (settings / gear) --------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M12 9 A3 3 0 1 1 11.99 9 Z  M12 2 V5  M12 19 V22  M2 12 H5  M19 12 H22  M4.9 4.9 L7 7  M17 17 L19.1 19.1  M4.9 19.1 L7 17  M17 7 L19.1 4.9" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "cog"
        }

        // ---- chevron-left -----------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M15 6 L9 12 L15 18" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "chevron-left"
        }

        // ---- chevron-right ----------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M9 6 L15 12 L9 18" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName === "chevron-right"
        }

        // ---- fallback (ring) --------------------------------------
        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.strokeW
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: "M4 4 H20 V20 H4 Z" }
            scale: Qt.size(root.width / 24.0, root.height / 24.0)
            visible: root.iconName !== "shield" && root.iconName !== "lock" &&
                     root.iconName !== "globe" && root.iconName !== "network" &&
                     root.iconName !== "mail" && root.iconName !== "eye" &&
                     root.iconName !== "bolt" && root.iconName !== "code" &&
                     root.iconName !== "usb" && root.iconName !== "home" &&
                     root.iconName !== "card" && root.iconName !== "key" &&
                     root.iconName !== "user" && root.iconName !== "radar" &&
                     root.iconName !== "cog" && root.iconName !== "chevron-left" &&
                     root.iconName !== "chevron-right"
        }
    }
}
