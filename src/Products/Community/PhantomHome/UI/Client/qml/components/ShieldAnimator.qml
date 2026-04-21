import QtQuick
import QtQuick.Shapes
import "../Theming"

/*
 * ShieldAnimator
 * --------------
 * Animated protection emblem used on the Main page.
 *  - protectionState in {"green","amber","red","paused"} -> driven by the
 *    ProtectionViewModel.
 *  - Idle state breathes softly; transitions smoothly through color on change.
 *  - Pure shape-based; no PNG assets, scales to any DPI.
 */
Item {
    id: root
    implicitWidth:  180
    implicitHeight: 200

    property string protectionState: "green"       // "green"|"amber"|"red"|"paused"
    property real   pulse: 0.0

    // shieldColor avoids the reserved CSS 'currentColor' read-only property.
    property color shieldColor: {
        switch (protectionState) {
        case "green":  return Theme.stateGreen
        case "amber":  return Theme.stateAmber
        case "red":    return Theme.stateRed
        case "paused": return Theme.statePause
        }
        return Theme.stateGreen
    }

    Behavior on shieldColor { ColorAnimation { duration: Theme.motionSlow } }

    SequentialAnimation on pulse {
        loops: Animation.Infinite
        running: true
        NumberAnimation { from: 0.0; to: 1.0; duration: 1600; easing.type: Easing.InOutSine }
        NumberAnimation { from: 1.0; to: 0.0; duration: 1600; easing.type: Easing.InOutSine }
    }

    // Outer breathing halo
    Rectangle {
        anchors.centerIn: parent
        width:  160 + root.pulse * 18
        height: width
        radius: width / 2
        color:  Qt.rgba(root.shieldColor.r, root.shieldColor.g, root.shieldColor.b,
                        0.08 + root.pulse * 0.10)
    }

    // Shield body
    Shape {
        anchors.centerIn: parent
        width:  130
        height: 140
        layer.enabled: true
        layer.samples: 8

        ShapePath {
            strokeColor: root.shieldColor
            strokeWidth: 2
            fillColor:   Qt.rgba(root.shieldColor.r, root.shieldColor.g, root.shieldColor.b, 0.18)

            startX: 65; startY: 2
            PathLine { x: 126; y: 22 }
            PathLine { x: 126; y: 72 }
            PathCubic { control1X: 126; control1Y: 108; control2X: 100; control2Y: 132; x: 65; y: 140 }
            PathCubic { control1X: 30;  control1Y: 132; control2X: 4;   control2Y: 108; x: 4;  y: 72 }
            PathLine { x: 4;   y: 22 }
            PathLine { x: 65;  y: 2 }
        }

        ShapePath {
            strokeColor: root.shieldColor
            strokeWidth: 4
            fillColor:   "transparent"
            capStyle:    ShapePath.RoundCap
            joinStyle:   ShapePath.RoundJoin
            startX: 36; startY: 72
            PathLine { x: 58; y: 94 }
            PathLine { x: 96; y: 50 }
        }
    }
}
