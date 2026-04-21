import QtQuick
import QtQuick.Shapes
import "../Theming"

/*
 * ShieldAnimator
 * --------------
 * The signature protection emblem used on the main page. Pure vector
 * so it scales to any DPI with no assets.
 *
 * Visual composition (back -> front):
 *   1. Soft breathing halo (large, low alpha)
 *   2. Rotating conic accent ring (slow)
 *   3. Shield outline (gradient-filled, stroked)
 *   4. Check mark
 *
 * `protectionState` drives the accent hue through Theme status colors,
 * animated via ColorAnimation on `shieldColor`. Note the property is
 * deliberately *not* called currentColor - that name is reserved by
 * Qt Quick's CSS/SVG inheritance and cannot be written to at runtime.
 */
Item {
    id: root
    implicitWidth:  220
    implicitHeight: 240

    property string protectionState: "green"        // green|amber|red|paused
    property real   pulse: 0.0
    property real   ringAngle: 0.0

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

    // Continuous gentle breathing used by halo + fill alpha.
    SequentialAnimation on pulse {
        loops: Animation.Infinite
        running: true
        NumberAnimation { from: 0.0; to: 1.0; duration: Theme.motionBreath; easing.type: Easing.InOutSine }
        NumberAnimation { from: 1.0; to: 0.0; duration: Theme.motionBreath; easing.type: Easing.InOutSine }
    }

    // Slow rotation for the accent ring.
    NumberAnimation on ringAngle {
        from: 0; to: 360
        duration: 9000
        loops: Animation.Infinite
        running: true
    }

    // --- Outer breathing halo (largest layer) -----------------------------
    Rectangle {
        anchors.centerIn: parent
        width:  200 + root.pulse * 28
        height: width
        radius: width / 2
        color:  Qt.rgba(root.shieldColor.r, root.shieldColor.g, root.shieldColor.b,
                        0.06 + root.pulse * 0.08)
    }

    // --- Middle accent halo (cooler blue, static) -------------------------
    Rectangle {
        anchors.centerIn: parent
        width:  164
        height: width
        radius: width / 2
        color:  "transparent"
        border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.22)
        border.width: 1
    }

    // --- Rotating dashed accent ring --------------------------------------
    Shape {
        anchors.centerIn: parent
        width:  178
        height: 178
        rotation: root.ringAngle
        layer.enabled: true
        layer.samples: 8
        ShapePath {
            strokeColor: Qt.rgba(Theme.accentAlt.r, Theme.accentAlt.g, Theme.accentAlt.b, 0.55)
            strokeWidth: 2
            fillColor:   "transparent"
            strokeStyle: ShapePath.DashLine
            dashPattern: [3, 6]
            capStyle:    ShapePath.FlatCap
            startX: 89; startY: 0
            PathAngleArc { centerX: 89; centerY: 89; radiusX: 89; radiusY: 89
                           startAngle: -90; sweepAngle: 360 }
        }
    }

    // --- Shield body ------------------------------------------------------
    Shape {
        id: shield
        anchors.centerIn: parent
        width:  138
        height: 150
        layer.enabled: true
        layer.samples: 8

        // Soft inner fill (gradient-looking via two stacked paths)
        ShapePath {
            strokeColor: root.shieldColor
            strokeWidth: 2.5
            fillColor:   Qt.rgba(root.shieldColor.r, root.shieldColor.g, root.shieldColor.b,
                                 0.14 + root.pulse * 0.06)
            joinStyle:   ShapePath.RoundJoin
            capStyle:    ShapePath.RoundCap

            startX: 69; startY: 2
            PathLine  { x: 134; y: 24 }
            PathLine  { x: 134; y: 76 }
            PathCubic { control1X: 134; control1Y: 114; control2X: 104; control2Y: 140; x: 69; y: 148 }
            PathCubic { control1X: 34;  control1Y: 140; control2X: 4;   control2Y: 114; x: 4;  y: 76 }
            PathLine  { x: 4;   y: 24 }
            PathLine  { x: 69;  y: 2 }
        }

        // Check mark
        ShapePath {
            strokeColor: root.shieldColor
            strokeWidth: 5
            fillColor:   "transparent"
            capStyle:    ShapePath.RoundCap
            joinStyle:   ShapePath.RoundJoin
            startX: 38; startY: 76
            PathLine { x: 62;  y: 100 }
            PathLine { x: 104; y: 54  }
        }
    }
}
