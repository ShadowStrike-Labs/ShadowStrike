import QtQuick
import QtQuick.Shapes
import ShadowStrike.Theming

Shape {
    id: root
    property color iconColor: Theme.warn
    width: 24; height: 24

    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        joinStyle:   ShapePath.RoundJoin
        // Triangle
        PathSvg { path: "M 12 3 L 21 20 L 3 20 Z" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   root.iconColor
        capStyle:    ShapePath.RoundCap
        // Exclamation dot
        PathSvg { path: "M 12 16 A 0.5 0.5 0 1 1 12.001 16" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Exclamation line
        PathSvg { path: "M 12 9 L 12 14" }
    }
}
