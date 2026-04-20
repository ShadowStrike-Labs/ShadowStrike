import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * Sidebar
 * -------
 * Left navigation rail. Emits selectedIndex on activation.
 * Order matches the main App page stack.
 */
Rectangle {
    id: root
    color:       Theme.bg1
    border.color:Theme.stroke
    border.width:1
    radius:      0
    implicitWidth: 196

    property int selectedIndex: 0
    signal navigate(int index)

    // ------- Header / brand -------
    Column {
        id: header
        anchors.top:   parent.top
        anchors.left:  parent.left
        anchors.right: parent.right
        anchors.margins: Theme.sp4
        spacing: Theme.sp1

        Row {
            spacing: Theme.sp2
            Image {
                source: "../assets/logo.svg"
                width: 28; height: 28
                sourceSize.width: 56
                sourceSize.height: 56
                fillMode: Image.PreserveAspectFit
            }
            Column {
                spacing: 0
                Text {
                    text: "ShadowStrike Phantom"
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontHeading
                    font.weight: Font.DemiBold
                }
                Text {
                    text: "Home"
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                }
            }
        }
    }

    // ------- Nav list -------
    ListModel {
        id: navModel
        ListElement { label: "Main";        icon: "\u25A0" }
        ListElement { label: "Security";    icon: "\u25C6" }
        ListElement { label: "Performance"; icon: "\u25B2" }
        ListElement { label: "Privacy";     icon: "\u25CF" }
        ListElement { label: "Scan";        icon: "\u25B6" }
        ListElement { label: "Quarantine";  icon: "\u25A3" }
        ListElement { label: "Reports";     icon: "\u25A4" }
        ListElement { label: "Settings";    icon: "\u2699" }
    }

    ListView {
        anchors.top: header.bottom
        anchors.topMargin: Theme.sp6
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: Theme.sp2
        model: navModel
        spacing: 2
        interactive: false

        delegate: Rectangle {
            width: ListView.view.width
            height: 38
            radius: Theme.radiusSm
            color: root.selectedIndex === index ? Theme.bg2 : "transparent"
            border.color: root.selectedIndex === index ? Theme.stroke : "transparent"
            border.width: 1

            Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: Theme.sp3
                spacing: Theme.sp2

                Text {
                    text: icon
                    color: root.selectedIndex === index ? Theme.accentAlt : Theme.textMuted
                    font.pixelSize: 12
                }
                Text {
                    text: label
                    color: root.selectedIndex === index ? Theme.text : Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    font.weight: root.selectedIndex === index ? Font.DemiBold : Font.Normal
                }
            }

            MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    root.selectedIndex = index
                    root.navigate(index)
                }
            }

            Behavior on color { ColorAnimation { duration: Theme.motionFast } }
        }
    }
}
