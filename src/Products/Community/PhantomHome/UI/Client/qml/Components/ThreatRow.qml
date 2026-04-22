import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string threatName
    required property string filePath
    required property string action          // "blocked"|"quarantined"|"deleted"
    required property string timestampDisplay
    signal rowClicked()

    // alternateBackground is set by parent ListView via index
    property bool alternate: false

    implicitWidth:  500
    implicitHeight: 56

    Rectangle {
        anchors.fill: parent
        color: ma.containsMouse
               ? Theme.bgSurfaceAlt
               : (root.alternate ? Qt.rgba(Theme.bgSurfaceAlt.r, Theme.bgSurfaceAlt.g, Theme.bgSurfaceAlt.b, 0.40) : "transparent")
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

            // Action badge
            Rectangle {
                width:  72; height: 20
                radius: Theme.radiusSmall
                anchors.verticalCenter: parent.verticalCenter
                color: {
                    switch (root.action) {
                    case "blocked":     return Qt.rgba(Theme.crit.r, Theme.crit.g, Theme.crit.b, 0.18)
                    case "quarantined": return Qt.rgba(Theme.warn.r, Theme.warn.g, Theme.warn.b, 0.18)
                    default:            return Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 0.18)
                    }
                }
                Text {
                    anchors.centerIn: parent
                    text:  root.action
                    color: {
                        switch (root.action) {
                        case "blocked":     return Theme.crit
                        case "quarantined": return Theme.warn
                        default:            return Theme.textMuted
                        }
                    }
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMicro
                    font.weight:    Theme.fontWeightMedium
                }
            }

            Column {
                width:   parent.width - 72 - 100 - parent.spacing * 2
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

                Text {
                    text:  root.threatName
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    font.weight:    Theme.fontWeightMedium
                    elide: Text.ElideRight
                    width: parent.width
                }
                Text {
                    text:  root.filePath
                    color: Theme.textMuted
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMicro
                    elide: Text.ElideMiddle
                    width: parent.width
                }
            }

            Text {
                width:   100
                text:    root.timestampDisplay
                color:   Theme.textMuted
                font.family:    Theme.fontFamily
                font.pixelSize: Theme.fontSizeLabel
                horizontalAlignment: Text.AlignRight
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: true
            cursorShape:  Qt.PointingHandCursor
            onClicked:    root.rowClicked()
        }
    }

    activeFocusOnTab: true
    Keys.onReturnPressed: root.rowClicked()
    Keys.onSpacePressed:  root.rowClicked()

    FocusRing { target: root }

    Accessible.role:        Accessible.ListItem
    Accessible.name:        root.threatName
    Accessible.description: qsTr("%1 — %2 at %3").arg(root.action).arg(root.filePath).arg(root.timestampDisplay)
}
