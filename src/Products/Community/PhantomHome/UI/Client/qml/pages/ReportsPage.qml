import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Reports")
    property var events: []       // [{timeUnix, module, severity, title, detail}]

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp4

        Text { text: "Reports"; color: Theme.text
               font.family: Theme.fontFamily
               font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }

        CardFrame {
            title: "Recent activity"
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
                anchors.fill: parent
                model: page.events
                spacing: Theme.sp2
                clip: true

                delegate: Rectangle {
                    width: ListView.view.width
                    height: 60
                    color: Theme.bg2
                    border.color: Theme.stroke
                    border.width: 1
                    radius: Theme.radiusSm
                    Column {
                        anchors.fill: parent
                        anchors.margins: Theme.sp3
                        spacing: 2
                        Text { text: modelData.title; color: Theme.text
                               font.pixelSize: Theme.fontBody
                               font.weight: Font.DemiBold }
                        Text { text: modelData.module + " · " + modelData.severity
                               color: Theme.textMuted
                               font.pixelSize: Theme.fontSmall }
                    }
                }
            }
        }
    }
}
