import QtQuick
import QtQuick.Shapes
import ShadowStrike.Theming

Item {
    id: root

    required property string state  // "healthy"|"atRisk"|"critical"|"paused"

    width:  220
    height: 220

    readonly property color _stateColor: Theme.stateColor(
        root.state === "healthy"  ? "healthy"  :
        root.state === "atRisk"   ? "atRisk"   :
        root.state === "critical" ? "critical"  : "paused")

    // Outer glow rectangle
    Rectangle {
        id: glowOuter
        anchors.centerIn: parent
        width:  parent.width  + 20
        height: parent.height + 20
        radius: (parent.width + 20) / 2
        color:  Qt.rgba(root._stateColor.r, root._stateColor.g, root._stateColor.b, 0.10)
        Behavior on color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
    }

    // Shield shape using Shape+ShapePath with a simplified shield SVG path
    Shape {
        id: shieldShape
        anchors.centerIn: parent
        width:  160
        height: 180

        ShapePath {
            id: shieldPath
            strokeColor: Qt.rgba(root._stateColor.r, root._stateColor.g, root._stateColor.b, 0.85)
            strokeWidth: 2
            fillGradient: LinearGradient {
                x1: 0;   y1: 0
                x2: 0;   y2: 180
                GradientStop { position: 0.0; color: Qt.rgba(root._stateColor.r, root._stateColor.g, root._stateColor.b, 0.75) }
                GradientStop { position: 1.0; color: Qt.rgba(root._stateColor.r, root._stateColor.g, root._stateColor.b, 0.28) }
            }

            // Shield outline path: 160w × 180h viewport
            PathSvg {
                path: "M 80 4 L 156 36 L 156 104 Q 156 158 80 178 Q 4 158 4 104 L 4 36 Z"
            }

            Behavior on strokeColor { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
        }
    }

    // Center emblem — a check when protected, an exclamation otherwise.
    // Drawn inline (no icon-module import) and rendered near-white for strong
    // contrast against the translucent, state-coloured shield fill.
    Shape {
        anchors.centerIn: shieldShape
        anchors.verticalCenterOffset: -6
        width: 76; height: 76
        visible: root.state === "healthy"

        ShapePath {
            strokeColor: Theme.textPrimary
            strokeWidth: 7
            fillColor:   "transparent"
            capStyle:    ShapePath.RoundCap
            joinStyle:   ShapePath.RoundJoin
            PathSvg { path: "M 14 40 L 31 57 L 62 20" }
        }
    }

    Column {
        anchors.centerIn: shieldShape
        anchors.verticalCenterOffset: -6
        spacing: 7
        visible: root.state !== "healthy"

        Rectangle {
            width: 9; height: 34; radius: 4.5
            color: Theme.textPrimary
            anchors.horizontalCenter: parent.horizontalCenter
        }
        Rectangle {
            width: 9; height: 9; radius: 4.5
            color: Theme.textPrimary
            anchors.horizontalCenter: parent.horizontalCenter
        }
    }

    // Pulsing scale animation
    SequentialAnimation {
        id: pulseAnim
        running: {
            if (Theme.reducedMotion)
                return false
            if (typeof perfBudget !== "undefined" && perfBudget !== null && perfBudget.animationsPaused)
                return false
            return true
        }
        loops: Animation.Infinite

        NumberAnimation {
            target:   shieldShape
            property: "scale"
            from:     1.0; to: 1.04
            duration: Theme.motionHeroPulse / 2
            easing.type: Easing.InOutSine
        }
        NumberAnimation {
            target:   shieldShape
            property: "scale"
            from:     1.04; to: 1.0
            duration: Theme.motionHeroPulse / 2
            easing.type: Easing.InOutSine
        }
    }
}
