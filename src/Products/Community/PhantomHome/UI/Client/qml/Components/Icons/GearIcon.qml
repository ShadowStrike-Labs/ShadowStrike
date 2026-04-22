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
        // Gear outer path (simplified 8-tooth gear)
        PathSvg { path: "M 12 2 L 13.5 5 L 16.5 4 L 18 7 L 21 8 L 20 11 L 22 13 L 20 15 L 21 18 L 18 19 L 16.5 22 L 13.5 21 L 12 22 L 10.5 21 L 7.5 22 L 6 19 L 3 18 L 4 15 L 2 13 L 4 11 L 3 8 L 6 7 L 7.5 4 L 10.5 5 Z" }
    }
    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 1.5
        fillColor:   "transparent"
        // Inner circle
        PathSvg { path: "M 15 12 A 3 3 0 1 1 9 12 A 3 3 0 1 1 15 12" }
    }
}
