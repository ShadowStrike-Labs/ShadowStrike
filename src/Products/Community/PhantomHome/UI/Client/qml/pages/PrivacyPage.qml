import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * PrivacyPage
 * -----------
 * Device and network privacy toggles. Each row shows a short
 * description under the label so the user understands the effect.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Privacy")

    property bool webcamBlocked:     false
    property bool dnsLeakProtection: true
    property bool ipLeakProtection:  true
    property bool trackerBlocker:    true

    signal setToggle(string id, bool on)

    component PrivacyRow: Rectangle {
        id: row
        property string rowLabel: ""
        property string detail: ""
        property bool   rowChecked: false
        property string toggleId: ""

        Layout.fillWidth: true
        implicitHeight: 64
        radius: Theme.radiusSm
        color: Theme.bg1
        border.color: Theme.stroke
        border.width: 1

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.sp4
            anchors.rightMargin: Theme.sp3
            spacing: Theme.sp3
            Column {
                Layout.fillWidth: true
                spacing: 2
                Text { text: row.rowLabel
                       color: Theme.textStrong
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontBody
                       font.weight: Font.DemiBold }
                Text { text: row.detail
                       color: Theme.textMuted
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontSmall
                       wrapMode: Text.WordWrap }
            }
            Switch {
                checked: row.rowChecked
                onToggled: page.setToggle(row.toggleId, checked)
            }
        }
    }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            Column {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: 4
                Text { text: "Privacy"; color: Theme.textStrong
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: "Device hardware and network leak protections."
                       color: Theme.textMuted
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontBody }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                title: "Device privacy"

                PrivacyRow { rowLabel: "Webcam access block"
                             detail: "Prevents untrusted apps from opening the camera."
                             rowChecked: page.webcamBlocked
                             toggleId: "webcam" }

                PrivacyRow { rowLabel: "DNS leak protection"
                             detail: "Stops queries from bypassing your configured resolver."
                             rowChecked: page.dnsLeakProtection
                             toggleId: "dnsLeak" }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: "Network privacy"

                PrivacyRow { rowLabel: "IP leak protection"
                             detail: "Blocks WebRTC and raw-socket IP disclosure channels."
                             rowChecked: page.ipLeakProtection
                             toggleId: "ipLeak" }

                PrivacyRow { rowLabel: "Tracker blocker"
                             detail: "Filters known analytics and fingerprint trackers."
                             rowChecked: page.trackerBlocker
                             toggleId: "tracker" }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
