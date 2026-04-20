import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

Item {
    id: page

    property int    scanType: 0              // 0=Quick 1=Full 2=Custom 3=Memory
    property bool   scanning: false
    property real   progress: 0.0            // 0..1
    property int    filesScanned: 0
    property int    threatsFound: 0

    signal startScan(int scanType)
    signal cancelScan()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp4

        Text { text: "Scan"; color: Theme.text; font.family: Theme.fontFamily
               font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }

        CardFrame {
            title: "Choose scan type"
            Layout.fillWidth: true

            RowLayout {
                spacing: Theme.sp3
                Button { text: "Quick";   onClicked: { page.scanType = 0; page.startScan(0) } }
                Button { text: "Full";    onClicked: { page.scanType = 1; page.startScan(1) } }
                Button { text: "Custom";  onClicked: { page.scanType = 2; page.startScan(2) } }
                Button { text: "Memory";  onClicked: { page.scanType = 3; page.startScan(3) } }
            }
        }

        CardFrame {
            title: page.scanning ? "Scan in progress" : "Last scan results"
            Layout.fillWidth: true

            ProgressBar {
                Layout.fillWidth: true
                from: 0; to: 1
                value: page.progress
                visible: page.scanning
            }

            Text { text: "Files scanned: " + page.filesScanned; color: Theme.textMuted
                   font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
            Text { text: "Threats found: " + page.threatsFound
                   color: page.threatsFound > 0 ? Theme.danger : Theme.success
                   font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }

            Button {
                text: "Cancel"; visible: page.scanning
                onClicked: page.cancelScan()
            }
        }

        Item { Layout.fillHeight: true }
    }
}
