import QtQuick
import ShadowStrike.Theming

Item {
    id: root

    required property string state   // "on"|"off"|"paused"|"warning"|"critical"|"info"|"loading"|"offline"
    required property string label

    // Map component state to Theme palette
    property color _baseColor: Theme.stateColor(root.state)

    implicitWidth: row.implicitWidth + Theme.spacingM * 2
    implicitHeight: 26

    Rectangle {
        id: bg
        anchors.fill: parent
        radius: Theme.radiusSmall
        color: Theme.stateFill(root.state)
        border.color: root._baseColor
        border.width: Theme.highContrast ? 2 : 1

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
                border.color: Theme.highContrast ? Theme.textPrimary : "transparent"
                border.width: Theme.highContrast ? 1 : 0
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
    Accessible.description: qsTr("State: %1").arg(root.state)
}
