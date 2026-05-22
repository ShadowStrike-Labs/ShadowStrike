import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property alias text: label.text
    property bool   busy:    false
    property bool   enabled: true
    property string accessibleName: label.text
    signal clicked()

    implicitWidth:  Math.max(112, label.implicitWidth + Theme.spacingXL * 2)
    implicitHeight: Theme.controlHeight

    opacity: root.enabled ? 1.0 : Theme.disabledOpacity
    Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

    Rectangle {
        id: bg
        anchors.fill: parent
        radius:       Theme.radiusMedium
        color:        ma.containsMouse && root.enabled ? Theme.surfaceColor(false, true) : "transparent"
        border.color: root.enabled
                      ? (ma.containsMouse ? Theme.accentGlow : Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, Theme.highContrast ? 1.0 : 0.62))
                      : Theme.strokeSubtle
        border.width: Theme.highContrast || bg.activeFocus ? 2 : 1

        Behavior on color        { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        transform: Scale {
            origin.x: bg.width / 2
            origin.y: bg.height / 2
            xScale: root.enabled && !Theme.reducedMotion ? (ma.pressed ? 0.98 : 1.0) : 1.0
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
    Accessible.name:        root.accessibleName.length > 0 ? root.accessibleName : label.text
    Accessible.description: qsTr("Secondary action")
}
