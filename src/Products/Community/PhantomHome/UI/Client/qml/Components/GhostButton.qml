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

    implicitWidth:  Math.max(100, label.implicitWidth + Theme.spacingXL * 2)
    implicitHeight: 36

    opacity: root.enabled ? 1.0 : 0.4
    Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

    Rectangle {
        id: bg
        anchors.fill: parent
        radius:       Theme.radiusMedium
        color:        ma.containsMouse && root.enabled ? Theme.bgSurfaceAlt : "transparent"
        border.color: root.enabled ? Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.55) : Theme.strokeSubtle
        border.width: 1

        Behavior on color        { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        transform: Scale {
            origin.x: bg.width / 2
            origin.y: bg.height / 2
            xScale: root.enabled ? (ma.pressed ? 0.98 : 1.0) : 1.0
            yScale: xScale
            Behavior on xScale { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        }

        BusyIndicator {
            id: busyInd
            visible: root.busy
            anchors.centerIn: parent
            width:  20; height: 20
            running: root.busy
            palette.dark: Theme.accentCyan
        }

        Text {
            id: label
            visible: !root.busy
            anchors.centerIn: parent
            color: Theme.accentCyan
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
    Accessible.description: qsTr("Secondary action")
}
