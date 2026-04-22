import QtQuick
import QtQuick.Shapes
import ShadowStrike.Theming

Shape {
    id: root
    property color iconColor: Theme.accentCyan
    width: 24; height: 24

    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Circle
        PathSvg { path: "M 22 12 A 10 10 0 1 1 2 12 A 10 10 0 1 1 22 12" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   root.iconColor
        capStyle:    ShapePath.RoundCap
        // Dot
        PathSvg { path: "M 12 8 A 0.5 0.5 0 1 1 12.001 8" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Stem
        PathSvg { path: "M 12 11 L 12 16" }
    }
}
