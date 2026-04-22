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
        PathSvg { path: "M 12 2 L 20 5.5 L 20 12 Q 20 18 12 22 Q 4 18 4 12 L 4 5.5 Z" }
    }
}
