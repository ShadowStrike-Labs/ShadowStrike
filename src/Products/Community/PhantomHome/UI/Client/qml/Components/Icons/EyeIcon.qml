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
        joinStyle:   ShapePath.RoundJoin
        // Eye outline
        PathSvg { path: "M 2 12 Q 12 4 22 12 Q 12 20 2 12 Z" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        // Iris
        PathSvg { path: "M 15 12 A 3 3 0 1 1 9 12 A 3 3 0 1 1 15 12" }
    }
}
