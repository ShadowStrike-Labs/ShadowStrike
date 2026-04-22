import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string state   // "on"|"off"|"paused"|"warning"|"critical"
    required property string label

    // Map component state to Theme palette
    property color _baseColor: {
        switch (root.state) {
        case "on":       return Theme.ok
        case "warning":  return Theme.warn
        case "critical": return Theme.crit
        case "paused":   return Theme.textMuted
        default:         return Theme.textMuted  // "off"
        }
    }

    implicitWidth: row.implicitWidth + Theme.spacingM * 2
    implicitHeight: 24

    Rectangle {
        id: bg
        anchors.fill: parent
        radius: Theme.radiusSmall
        color: Qt.rgba(root._baseColor.r, root._baseColor.g, root._baseColor.b, 0.18)
        border.color: root._baseColor
        border.width: 1

        Behavior on color      { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        Row {
            id: row
            anchors.centerIn: parent
            spacing: Theme.spacingXS

            Rectangle {
                width: 6; height: 6
                radius: 3
                anchors.verticalCenter: parent.verticalCenter
                color: root._baseColor
                Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
            }

            Text {
                text: root.label
                color: root._baseColor
                font.family:    Theme.fontFamily
                font.pixelSize: Theme.fontSizeLabel
                font.weight:    Theme.fontWeightMedium
                Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
            }
        }
    }

    Accessible.role:        Accessible.StaticText
    Accessible.name:        root.label
    Accessible.description: qsTr("Module state: %1").arg(root.state)
}
