import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string pageTitle
    property bool showBack: false
    signal backClicked()

    default property alias actions: actionRow.children

    width:          parent ? parent.width : 800
    implicitHeight: Theme.topBarHeight

    Rectangle {
        anchors.fill:  parent
        color:         Theme.bgSurface
        border.color:  Theme.strokeSubtle
        border.width:  0

        // Bottom border
        Rectangle {
            anchors {
                left:   parent.left
                right:  parent.right
                bottom: parent.bottom
            }
            height: 1
            color:  Theme.strokeSubtle
        }

        Row {
            anchors {
                left:           parent.left
                leftMargin:     Theme.spacingM
                verticalCenter: parent.verticalCenter
            }
            spacing: Theme.spacingS

            IconButton {
                visible:    root.showBack
                iconSource: "qrc:/icons/back.svg"
                tooltip:    qsTr("Back")
                anchors.verticalCenter: parent.verticalCenter
                onClicked:  root.backClicked()
            }

            Text {
                text:  root.pageTitle
                color: Theme.textPrimary
                font.family:    Theme.fontFamily
                font.pixelSize: Theme.fontSizeTitle
                font.weight:    Theme.fontWeightBold
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        Row {
            id: actionRow
            anchors {
                right:          parent.right
                rightMargin:    Theme.spacingM
                verticalCenter: parent.verticalCenter
            }
            spacing: Theme.spacingS
        }
    }

    Accessible.role: Accessible.ToolBar
    Accessible.name: root.pageTitle
}
