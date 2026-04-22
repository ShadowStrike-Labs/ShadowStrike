import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string id
    required property string title
    required property string detail
    required property string severity    // "info"|"warn"|"crit"
    required property string actionLabel
    signal actionClicked()
    signal dismissed()

    implicitWidth:  400
    implicitHeight: 72

    opacity: 0
    x: 20

    Component.onCompleted: {
        entryAnim.start()
    }

    ParallelAnimation {
        id: entryAnim
        NumberAnimation { target: root; property: "opacity"; from: 0; to: 1;   duration: 220; easing.type: Theme.easingType }
        NumberAnimation { target: root; property: "x";       from: 20; to: 0;  duration: 220; easing.type: Theme.easingType }
    }

    ParallelAnimation {
        id: exitAnim
        NumberAnimation { target: root; property: "opacity"; from: 1; to: 0;   duration: 200; easing.type: Theme.easingType }
        NumberAnimation { target: root; property: "x";       from: 0; to: 20;  duration: 200; easing.type: Theme.easingType }
        onFinished: root.dismissed()
    }

    readonly property color _sevColor: {
        switch (root.severity) {
        case "crit": return Theme.crit
        case "warn": return Theme.warn
        default:     return Theme.accentCyan
        }
    }

    Rectangle {
        anchors.fill: parent
        radius:       Theme.radiusMedium
        color:        Theme.bgSurface
        border.color: Theme.strokeSubtle
        border.width: 1

        // Left severity bar
        Rectangle {
            width:  4
            height: parent.height
            radius: 2
            color:  root._sevColor
        }

        Row {
            anchors {
                left:           parent.left
                leftMargin:     Theme.spacingL
                right:          parent.right
                rightMargin:    Theme.spacingM
                verticalCenter: parent.verticalCenter
            }
            spacing: Theme.spacingM

            Column {
                width:   parent.width - actionBtn.implicitWidth - closeBtn.implicitWidth - parent.spacing * 2
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

                Text {
                    text:  root.title
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    font.weight:    Theme.fontWeightMedium
                    elide: Text.ElideRight
                    width: parent.width
                }
                Text {
                    text:  root.detail
                    color: Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLabel
                    elide: Text.ElideRight
                    width: parent.width
                }
            }

            PrimaryButton {
                id: actionBtn
                text: root.actionLabel
                anchors.verticalCenter: parent.verticalCenter
                implicitHeight: 30
                onClicked: root.actionClicked()
            }

            IconButton {
                id: closeBtn
                iconSource: "qrc:/icons/close.svg"
                tooltip:    qsTr("Dismiss")
                anchors.verticalCenter: parent.verticalCenter
                onClicked: exitAnim.start()
            }
        }
    }

    Keys.onDeletePressed: exitAnim.start()
    activeFocusOnTab: true

    Accessible.role:        Accessible.ListItem
    Accessible.name:        root.title
    Accessible.description: root.detail
}
