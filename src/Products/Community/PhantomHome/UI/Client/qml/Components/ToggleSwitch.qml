import QtQuick
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property bool   checked:   false
    property string labelText: ""
    signal toggled(bool newValue)

    implicitWidth:  labelText.length > 0 ? track.width + Theme.spacingS + lbl.implicitWidth : track.width
    implicitHeight: Math.max(track.height, 28)
    opacity: root.enabled ? 1.0 : Theme.disabledOpacity
    Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

    Row {
        spacing: Theme.spacingS
        anchors.verticalCenter: parent.verticalCenter

        Rectangle {
            id: track
            width:  44
            height: 24
            radius: 12
            color: root.checked ? Theme.stateFill("on") : Theme.stateFill("off")
            border.color: root.checked ? Theme.accentCyan : Theme.textMuted
            border.width: Theme.highContrast ? 2 : 1.5

            Behavior on color        { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
            Behavior on border.color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

            Rectangle {
                id: thumb
                width:  20; height: 20
                radius: 10
                anchors.verticalCenter: parent.verticalCenter
                x: root.checked ? track.width - width - 2 : 2

                Behavior on x { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

                color: root.checked ? Theme.accentCyan : Theme.textMuted
                Behavior on color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

                // Glow when on
                layer.enabled: root.checked
                layer.effect: null  // DropShadow requires Qt.GraphicsEffects — use border glow via outline rect
            }

            // Soft glow outline when on (replaces DropShadow to avoid GraphicsEffects dependency)
            Rectangle {
                anchors.fill: thumb
                anchors.margins: -3
                radius: thumb.radius + 3
                color: "transparent"
                visible: !Theme.highContrast
                border.color: root.checked ? Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.45) : "transparent"
                border.width: 3
                Behavior on border.color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
            }

            MouseArea {
                id: trackArea
                anchors.fill: parent
                enabled: root.enabled
                hoverEnabled: root.enabled
                cursorShape: root.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: {
                    root.checked = !root.checked
                    root.toggled(root.checked)
                }
            }

            FocusRing { target: track }
        }

        Text {
            id: lbl
            visible: root.labelText.length > 0
            text:    root.labelText
            color:   Theme.textSecondary
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeBody
            font.weight:    Theme.fontWeightRegular
            anchors.verticalCenter: parent.verticalCenter
        }
    }

    Keys.onSpacePressed: {
        if (root.enabled) {
            root.checked = !root.checked
            root.toggled(root.checked)
        }
    }
    Keys.onReturnPressed: {
        if (root.enabled) {
            root.checked = !root.checked
            root.toggled(root.checked)
        }
    }

    activeFocusOnTab: root.enabled

    Accessible.role:        Accessible.CheckBox
    Accessible.name:        root.labelText.length > 0 ? root.labelText : qsTr("Toggle")
    Accessible.description: root.checked ? qsTr("Enabled") : qsTr("Disabled")
    Accessible.checkable:   true
    Accessible.checked:     root.checked
}
