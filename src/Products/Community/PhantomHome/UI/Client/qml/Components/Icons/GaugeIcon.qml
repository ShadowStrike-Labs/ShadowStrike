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
        // Gauge arc
        PathSvg { path: "M 4 16 Q 4 8 12 8 Q 20 8 20 16" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Needle
        PathSvg { path: "M 12 16 L 16 10" }
    }
}
