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
        PathSvg { path: "M 15 6 L 9 12 L 15 18" }
    }
}
