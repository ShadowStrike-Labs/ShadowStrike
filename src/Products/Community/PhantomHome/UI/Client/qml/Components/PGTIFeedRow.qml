import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string feedName
    required property bool   enabled
    required property string lastSyncDisplay
    required property int    iocCount
    signal toggled(bool v)
    signal refreshClicked()

    implicitWidth:  480
    implicitHeight: 52

    Rectangle {
        anchors.fill: parent
        color: ma.containsMouse ? Theme.bgSurfaceAlt : "transparent"
        Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        Row {
            anchors {
                left:           parent.left
                leftMargin:     Theme.spacingM
                right:          parent.right
                rightMargin:    Theme.spacingM
                verticalCenter: parent.verticalCenter
            }
            spacing: Theme.spacingM

            Column {
                width:   parent.width - iocText.implicitWidth - syncText.implicitWidth
                         - sw.implicitWidth - refreshBtn.implicitWidth - parent.spacing * 4
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

                Text {
                    text:  root.feedName
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    font.weight:    Theme.fontWeightMedium
                    elide: Text.ElideRight
                    width: parent.width
                }

                StatusChip {
                    state: root.enabled ? "on" : "off"
                    label: root.enabled ? qsTr("Active") : qsTr("Disabled")
                }
            }

            Text {
                id: iocText
                text:  qsTr("%1 IOCs").arg(root.iocCount.toLocaleString())
                color: Theme.textSecondary
                font.family:    Theme.fontFamily
                font.pixelSize: Theme.fontSizeLabel
                anchors.verticalCenter: parent.verticalCenter
            }

            Text {
                id: syncText
                text:  root.lastSyncDisplay
                color: Theme.textMuted
                font.family:    Theme.fontFamily
                font.pixelSize: Theme.fontSizeLabel
                anchors.verticalCenter: parent.verticalCenter
                width: 100
                elide: Text.ElideRight
            }

            ToggleSwitch {
                id: sw
                checked: root.enabled
                anchors.verticalCenter: parent.verticalCenter
                onToggled: (v) => root.toggled(v)
            }

            IconButton {
                id: refreshBtn
                iconSource: "qrc:/icons/refresh.svg"
                tooltip:    qsTr("Refresh feed")
                anchors.verticalCenter: parent.verticalCenter
                onClicked:  root.refreshClicked()
            }
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: true
            propagateComposedEvents: true
            onClicked: (mouse) => { mouse.accepted = false }
        }
    }

    Accessible.role:        Accessible.ListItem
    Accessible.name:        root.feedName
    Accessible.description: qsTr("%1 IOCs, last synced %2").arg(root.iocCount).arg(root.lastSyncDisplay)
}
