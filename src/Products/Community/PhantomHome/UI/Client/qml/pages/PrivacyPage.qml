import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

Item {
    id: page

    property bool webcamBlocked: false
    property bool dnsLeakProtection: true
    property bool ipLeakProtection: true
    property bool trackerBlocker: true

    signal setToggle(string id, bool on)

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp4

        Text { text: "Privacy"; color: Theme.text; font.family: Theme.fontFamily
               font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }

        CardFrame {
            title: "Device privacy"
            Layout.fillWidth: true
            RowLayout { Text { text: "Webcam access block"; color: Theme.text; Layout.fillWidth: true
                         font.pixelSize: Theme.fontBody }
                Switch { checked: page.webcamBlocked
                         onToggled: page.setToggle("webcam", checked) } }
            RowLayout { Text { text: "DNS leak protection"; color: Theme.text; Layout.fillWidth: true
                         font.pixelSize: Theme.fontBody }
                Switch { checked: page.dnsLeakProtection
                         onToggled: page.setToggle("dnsLeak", checked) } }
            RowLayout { Text { text: "IP leak protection"; color: Theme.text; Layout.fillWidth: true
                         font.pixelSize: Theme.fontBody }
                Switch { checked: page.ipLeakProtection
                         onToggled: page.setToggle("ipLeak", checked) } }
            RowLayout { Text { text: "Tracker blocker"; color: Theme.text; Layout.fillWidth: true
                         font.pixelSize: Theme.fontBody }
                Switch { checked: page.trackerBlocker
                         onToggled: page.setToggle("tracker", checked) } }
        }

        Item { Layout.fillHeight: true }
    }
}
