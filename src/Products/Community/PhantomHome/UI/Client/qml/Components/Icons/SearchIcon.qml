import QtQuick
import QtQuick.Shapes
import ShadowStrike.Theming

Shape {
    id: root
    property color iconColor: Theme.textPrimary
    width: 24; height: 24

    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Magnifier circle
        PathSvg { path: "M 16 10 A 6 6 0 1 1 4 10 A 6 6 0 1 1 16 10" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Handle
        PathSvg { path: "M 14.5 14.5 L 20 20" }
    }
}
