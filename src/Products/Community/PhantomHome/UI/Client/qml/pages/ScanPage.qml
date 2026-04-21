import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * ScanPage
 * --------
 * Dispatches scan requests and shows progress. Four scan types are
 * presented as selectable cards; the active card gets an accent border.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Scan")

    property int    scanType: 0          // 0=Quick 1=Full 2=Custom 3=Memory
    property bool   scanning: false
    property real   progress: 0.0        // 0..1
    property int    filesScanned: 0
    property int    threatsFound: 0

    signal startScan(int scanType)
    signal cancelScan()

    readonly property var scanTypes: [
        { label: "Quick scan",       desc: "Frequently targeted locations.",          icon: "\u25B6" },
        { label: "Full system scan", desc: "Every drive, every file.",                 icon: "\u25A0" },
        { label: "Custom scan",      desc: "Pick a folder or drive.",                  icon: "\u25C6" },
        { label: "Memory scan",      desc: "Running processes and loaded modules.",    icon: "\u2316" }
    ]

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
                Text { text: "Scan"; color: Theme.textStrong
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: "On-demand malware inspection across the device."
                       color: Theme.textMuted
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontBody }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                title: "Choose scan type"

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.sp3
                    rowSpacing: Theme.sp3

                    Repeater {
                        model: page.scanTypes
                        delegate: Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 72
                            radius: Theme.radiusSm
                            color: page.scanType === index ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.14) : Theme.bg1
                            border.color: page.scanType === index ? Theme.accent : Theme.stroke
                            border.width: 1
                            Behavior on color        { ColorAnimation { duration: Theme.motionFast } }
                            Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: Theme.sp3
                                spacing: Theme.sp3

                                Rectangle {
                                    width: 38; height: 38
                                    radius: Theme.radiusSm
                                    color: page.scanType === index ? Theme.accent : Theme.bg2
                                    Text { anchors.centerIn: parent
                                           text: modelData.icon
                                           color: page.scanType === index ? "#FFFFFF" : Theme.accentAlt
                                           font.pixelSize: 18 }
                                }
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 2
                                    Text { text: modelData.label; color: Theme.textStrong
                                           font.family: Theme.fontFamily
                                           font.pixelSize: Theme.fontBody
                                           font.weight: Font.DemiBold }
                                    Text { text: modelData.desc; color: Theme.textMuted
                                           font.family: Theme.fontFamily
                                           font.pixelSize: Theme.fontSmall
                                           wrapMode: Text.WordWrap }
                                }
                            }

                            TapHandler { onTapped: page.scanType = index }
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.sp3
                    spacing: Theme.sp3
                    Item { Layout.fillWidth: true }
                    PrimaryButton {
                        text: page.scanning ? "Scanning\u2026" : "Start " + page.scanTypes[page.scanType].label.toLowerCase()
                        enabled: !page.scanning
                        onClicked: page.startScan(page.scanType)
                    }
                    SecondaryButton {
                        text: "Cancel"
                        visible: page.scanning
                        danger: true
                        onClicked: page.cancelScan()
                    }
                }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: page.scanning ? "Scan in progress" : "Last scan results"
                subtitle: page.scanning
                          ? ""
                          : (page.filesScanned > 0
                              ? (page.threatsFound > 0 ? "Threats found in the last scan." : "No threats found.")
                              : "No scans have been run in this session yet.")

                Rectangle {
                    Layout.fillWidth: true
                    height: 8
                    radius: 4
                    color: Theme.bg1
                    visible: page.scanning
                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        width: parent.width * Math.max(0, Math.min(1, page.progress))
                        radius: parent.radius
                        color: Theme.accent
                        Behavior on width { NumberAnimation { duration: Theme.motionFast } }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp6
                    Column {
                        spacing: 2
                        Text { text: "Files scanned"; color: Theme.textMuted
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontSmall }
                        Text { text: page.filesScanned.toString()
                               color: Theme.textStrong
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontHeading
                               font.weight: Font.DemiBold }
                    }
                    Column {
                        spacing: 2
                        Text { text: "Threats found"; color: Theme.textMuted
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontSmall }
                        Text { text: page.threatsFound.toString()
                               color: page.threatsFound > 0 ? Theme.danger : Theme.success
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontHeading
                               font.weight: Font.DemiBold }
                    }
                    Item { Layout.fillWidth: true }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
