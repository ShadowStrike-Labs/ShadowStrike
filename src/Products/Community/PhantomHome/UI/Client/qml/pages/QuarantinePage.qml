import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

Item {
    id: page
    property var items: []     // [{id, path, sha256, detectionName, quarantinedUnix, severity}]

    signal restore(string id)
    signal purge(string id)

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp4

        Text { text: "Quarantine"; color: Theme.text
               font.family: Theme.fontFamily
               font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }

        CardFrame {
            title: "Isolated items"
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
                id: list
                anchors.fill: parent
                model: page.items
                spacing: Theme.sp2
                clip: true

                delegate: Rectangle {
                    width: ListView.view.width
                    height: 56
                    color: Theme.bg2
                    border.color: Theme.stroke
                    border.width: 1
                    radius: Theme.radiusSm

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: Theme.sp3
                        spacing: Theme.sp4

                        Column {
                            Layout.fillWidth: true
                            spacing: 1
                            Text { text: modelData.path; color: Theme.text
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontBody
                                   elide: Text.ElideMiddle }
                            Text { text: modelData.detectionName + " · " + modelData.severity
                                   color: Theme.textMuted
                                   font.pixelSize: Theme.fontSmall }
                        }
                        Button { text: "Restore"; onClicked: page.restore(modelData.id) }
                        Button { text: "Delete";  onClicked: page.purge(modelData.id) }
                    }
                }
            }
        }
    }
}
