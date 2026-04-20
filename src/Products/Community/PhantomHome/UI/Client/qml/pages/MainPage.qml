import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * MainPage
 * --------
 * Top-level status view: animated shield, big protection copy, Fast Scan
 * CTA, and a short summary row (last scan / threats blocked / update status).
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Protection status")

    // Wired from App.qml -> ProtectionViewModel
    property string protectionState: "green"
    property string stateCopy: "We are protecting you"
    property string stateSubCopy: "Real-time protection is active."
    property string lastScan: "—"
    property int    threatsBlocked7d: 0
    property string updateStatus: "Up to date"

    signal startFastScan()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp6

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.sp6

            ShieldAnimator {
                protectionState: page.protectionState
                Layout.preferredWidth: 180
                Layout.preferredHeight: 200
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.sp2

                Text {
                    text: page.stateCopy
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontTitle + 8
                    font.weight: Font.DemiBold
                }
                Text {
                    text: page.stateSubCopy
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    wrapMode: Text.WordWrap
                    Layout.maximumWidth: 480
                }

                Button {
                    text: "Fast scan"
                    Layout.topMargin: Theme.sp3
                    onClicked: page.startFastScan()
                    focusPolicy: Qt.StrongFocus
                    Accessible.role: Accessible.Button
                    Accessible.name: qsTr("Fast scan")
                    Accessible.description: qsTr("Run a fast scan of frequently targeted system locations")
                    background: Rectangle {
                        color: Theme.accent
                        radius: Theme.radiusSm
                        border.color: Qt.darker(Theme.accent, 1.15)
                        border.width: 1
                    }
                    contentItem: Text {
                        text: parent.text
                        color: "#FFFFFF"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                        font.weight: Font.DemiBold
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment:   Text.AlignVCenter
                        leftPadding: Theme.sp4
                        rightPadding: Theme.sp4
                        topPadding: Theme.sp2
                        bottomPadding: Theme.sp2
                    }
                }
            }
        }

        // Summary row
        GridLayout {
            Layout.fillWidth: true
            columns: 3
            columnSpacing: Theme.sp4
            rowSpacing:    Theme.sp4

            CardFrame {
                title: "Last scan"
                Layout.fillWidth: true
                Layout.preferredHeight: 92
                Text {
                    text: page.lastScan
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                }
            }
            CardFrame {
                title: "Threats blocked (7d)"
                Layout.fillWidth: true
                Layout.preferredHeight: 92
                Text {
                    text: page.threatsBlocked7d
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontTitle
                    font.weight: Font.DemiBold
                }
            }
            CardFrame {
                title: "Updates"
                Layout.fillWidth: true
                Layout.preferredHeight: 92
                Text {
                    text: page.updateStatus
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
