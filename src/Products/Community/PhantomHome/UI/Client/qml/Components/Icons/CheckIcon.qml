import QtQuick
import QtQuick.Shapes
import ShadowStrike.Theming

Shape {
    id: root
    property color iconColor: Theme.ok
    width: 24; height: 24

    ShapePath {
        strokeColor: root.iconColor
        strokeWidth: 2
        fillColor:   "transparent"
        capStyle:    ShapePath.RoundCap
        joinStyle:   ShapePath.RoundJoin
        PathSvg { path: "M 4 12 L 9 17 L 20 6" }
    }
}
