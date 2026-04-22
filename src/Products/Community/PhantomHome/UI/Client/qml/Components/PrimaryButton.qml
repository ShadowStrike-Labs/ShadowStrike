import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property alias text: label.text
    property bool   busy:    false
    property bool   enabled: true
    signal clicked()

    implicitWidth:  Math.max(120, label.implicitWidth + Theme.spacingXL * 2)
    implicitHeight: 36

    opacity: root.enabled ? 1.0 : 0.4
    Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

    Rectangle {
        id: bg
        anchors.fill: parent
        radius: Theme.radiusMedium

        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: root.enabled && (ma.containsMouse || ma.pressed) ? Qt.lighter(Theme.accentBlue, 1.15) : Theme.accentBlue }
            GradientStop { position: 1.0; color: root.enabled && (ma.containsMouse || ma.pressed) ? Qt.lighter(Theme.accentCyan, 1.1)  : Theme.accentCyan }
        }

        transform: Scale {
            origin.x: bg.width / 2
            origin.y: bg.height / 2
            xScale: root.enabled ? (ma.pressed ? 0.98 : (ma.containsMouse ? 1.02 : 1.0)) : 1.0
            yScale: xScale
            Behavior on xScale { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        }

        BusyIndicator {
            id: busyInd
            visible: root.busy
            anchors.centerIn: parent
            width:  20; height: 20
            running: root.busy
            palette.dark: Theme.textPrimary
        }

        Text {
            id: label
            visible: !root.busy
            anchors.centerIn: parent
            color: Theme.textPrimary
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeBody
            font.weight:    Theme.fontWeightMedium
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: root.enabled
            enabled:      root.enabled && !root.busy
            cursorShape:  root.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked:    root.clicked()
        }

        FocusRing { target: bg }
    }

    Keys.onSpacePressed:  { if (root.enabled && !root.busy) root.clicked() }
    Keys.onReturnPressed: { if (root.enabled && !root.busy) root.clicked() }
    activeFocusOnTab: root.enabled

    Accessible.role:        Accessible.Button
    Accessible.name:        label.text
    Accessible.description: root.busy ? qsTr("Loading") : qsTr("Activate")
}
