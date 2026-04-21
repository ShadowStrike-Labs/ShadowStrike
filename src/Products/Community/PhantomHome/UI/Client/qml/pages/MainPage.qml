import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * MainPage
 * --------
 * The "at-a-glance" protection hub the user sees first. Layout:
 *
 *   [ Shield emblem ][ State copy + primary CTA          ]
 *   [ Stat card ][ Stat card ][ Stat card                ]
 *   [ Quick actions rail (scan shortcuts + updates)      ]
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Protection status")

    // Wired from App.qml -> ProtectionViewModel.
    property string protectionState: "green"
    property string stateCopy:       "You are protected"
    property string stateSubCopy:    "Real-time protection is active."
    property string lastScan:        "—"
    property int    threatsBlocked7d: 0
    property string updateStatus:    "Up to date"

    signal startFastScan()
    signal openScanTab()
    signal openUpdateTab()

    function severityFromState(s) {
        switch (s) {
        case "green":  return "ok"
        case "amber":  return "warn"
        case "red":    return "bad"
        case "paused": return "muted"
        }
        return "info"
    }
    function labelFromState(s) {
        switch (s) {
        case "green":  return "Protected"
        case "amber":  return "Attention needed"
        case "red":    return "At risk"
        case "paused": return "Paused"
        }
        return "Checking"
    }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            anchors.margins: 0
            spacing: Theme.sp6

            // ----- Hero row --------------------------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                padded: true

                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 240

                    RowLayout {
                        anchors.fill: parent
                        spacing: Theme.sp8

                        ShieldAnimator {
                            id: shield
                            protectionState: page.protectionState
                            Layout.preferredWidth: 220
                            Layout.preferredHeight: 240
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            spacing: Theme.sp3

                            StatePill {
                                label: page.labelFromState(page.protectionState)
                                severity: page.severityFromState(page.protectionState)
                            }

                            Text {
                                text: page.stateCopy
                                color: Theme.textStrong
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontDisplay
                                font.weight: Font.DemiBold
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                            Text {
                                text: page.stateSubCopy
                                color: Theme.textMuted
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                                Layout.maximumWidth: 640
                            }

                            RowLayout {
                                spacing: Theme.sp3
                                Layout.topMargin: Theme.sp3

                                PrimaryButton {
                                    text: "Fast scan"
                                    onClicked: page.startFastScan()
                                    Accessible.name: qsTr("Fast scan")
                                    Accessible.description: qsTr("Run a fast scan of frequently targeted system locations")
                                }
                                SecondaryButton {
                                    text: "Full scan"
                                    onClicked: page.openScanTab()
                                }
                                SecondaryButton {
                                    text: "Check for updates"
                                    onClicked: page.openUpdateTab()
                                }
                            }
                            Item { Layout.fillHeight: true }
                        }
                    }
                }
            }

            // ----- Stat cards row -----------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp4

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 118
                    title: "Last scan"
                    subtitle: "Most recent detection sweep"

                    Text {
                        text: page.lastScan
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontHeading
                        font.weight: Font.Medium
                    }
                }
                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 118
                    title: "Threats blocked"
                    subtitle: "Last 7 days"

                    RowLayout {
                        spacing: Theme.sp2
                        Text {
                            text: page.threatsBlocked7d
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontDisplay
                            font.weight: Font.DemiBold
                        }
                        Text {
                            text: "blocked"
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontBody
                            Layout.alignment: Qt.AlignBottom
                            bottomPadding: 6
                        }
                    }
                }
                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 118
                    title: "Updates"
                    subtitle: "Signatures and engine"

                    RowLayout {
                        spacing: Theme.sp2
                        Rectangle {
                            width: 10; height: 10; radius: 5
                            color: Theme.success
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        Text {
                            text: page.updateStatus
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontHeading
                            font.weight: Font.Medium
                        }
                    }
                }
            }

            // ----- Quick actions rail -------------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: "Quick actions"
                subtitle: "Common tasks you can run right now"

                GridLayout {
                    Layout.fillWidth: true
                    columns: 4
                    columnSpacing: Theme.sp3
                    rowSpacing: Theme.sp3

                    Repeater {
                        model: [
                            { title: "Quick scan",       desc: "Common locations", target: 0 },
                            { title: "Full system scan", desc: "All drives",       target: 1 },
                            { title: "Custom scan",      desc: "Pick a path",      target: 2 },
                            { title: "Memory scan",      desc: "Running processes",target: 3 }
                        ]
                        delegate: Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 72
                            radius: Theme.radiusSm
                            color: hover.hovered ? Theme.bg3 : Theme.bg2
                            border.color: hover.hovered ? Theme.accentAlt : Theme.stroke
                            border.width: 1
                            Behavior on color        { ColorAnimation { duration: Theme.motionFast } }
                            Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }

                            Column {
                                anchors.fill: parent
                                anchors.margins: Theme.sp3
                                spacing: 2
                                Text {
                                    text: modelData.title
                                    color: Theme.textStrong
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontBody
                                    font.weight: Font.DemiBold
                                }
                                Text {
                                    text: modelData.desc
                                    color: Theme.textMuted
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSmall
                                }
                            }

                            HoverHandler { id: hover }
                            TapHandler { onTapped: page.openScanTab() }
                        }
                    }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
