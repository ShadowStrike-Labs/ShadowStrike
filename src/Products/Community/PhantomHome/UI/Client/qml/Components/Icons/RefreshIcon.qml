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
        PathSvg { path: "M 4 12 A 8 8 0 1 0 12 4 L 12 1 L 8 5 L 12 9 L 12 6 A 6 6 0 1 1 6 12" }
    }
}
