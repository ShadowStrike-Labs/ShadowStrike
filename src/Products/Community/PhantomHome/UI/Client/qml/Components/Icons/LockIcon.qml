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
        // Lock body
        PathSvg { path: "M 5 11 L 5 20 Q 5 21 6 21 L 18 21 Q 19 21 19 20 L 19 11 Q 19 10 18 10 L 6 10 Q 5 10 5 11 Z" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        // Shackle
        PathSvg { path: "M 8 10 L 8 7 Q 8 3 12 3 Q 16 3 16 7 L 16 10" }
    }
}
