import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * IdentityPage
 * ------------
 * Credential monitoring and password-strength audit surface. The live
 * data is not wired yet; the page provides an authentic shell with
 * demo entries until the service exposes the feeds.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Identity")

    signal runPasswordAudit()

    readonly property var _demoEmails: [
        { address: "user@example.com",   status: "clean"  },
        { address: "work@company.org",   status: "leaked" },
        { address: "backup@private.net", status: "clean"  }
    ]

    function _dotColor(s) {
        if (s === "clean")  return Theme.success
        if (s === "leaked") return Theme.warning
        return Theme.textDim
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
                Text { text: qsTr("Identity"); color: Theme.textStrong
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: qsTr("Credential monitoring, breach alerts and password hygiene.")
                       color: Theme.textMuted
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody }
            }

            // ---- Status strip --------------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                padded: true

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    Rectangle {
                        Layout.preferredWidth: 36
                        Layout.preferredHeight: 36
                        radius: Theme.radiusSm
                        color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
                        Iconed { anchors.centerIn: parent; iconName: "user"; size: 18; tint: Theme.accentAlt }
                    }
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("%1 credentials monitored \u00b7 last check 12 min ago").arg(page._demoEmails.length)
                        color: Theme.text
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                    }
                }
            }

            // ---- Two cards side by side ---------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp4

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 260
                    title: qsTr("Monitored emails")

                    Repeater {
                        model: page._demoEmails
                        delegate: RowLayout {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 32
                            spacing: Theme.sp3

                            Rectangle {
                                width: 8; height: 8; radius: 4
                                color: page._dotColor(modelData.status)
                                Layout.alignment: Qt.AlignVCenter
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData.address
                                color: Theme.text
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                                elide: Text.ElideRight
                            }
                            Text {
                                text: modelData.status === "leaked" ? qsTr("Leaked") : qsTr("Clean")
                                color: modelData.status === "leaked" ? Theme.warning : Theme.success
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                                font.weight: Font.DemiBold
                            }
                        }
                    }

                    Item { Layout.fillHeight: true; implicitHeight: Theme.sp2 }

                    RowLayout {
                        Layout.fillWidth: true
                        Item { Layout.fillWidth: true }
                        PrimaryButton {
                            text: qsTr("Add email")
                            onClicked: { /* wired when breach-monitoring service lands */ }
                        }
                    }
                }

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 260
                    title: qsTr("Breach alerts")

                    Item {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        ColumnLayout {
                            anchors.centerIn: parent
                            spacing: Theme.sp2
                            Iconed {
                                Layout.alignment: Qt.AlignHCenter
                                iconName: "shield"; size: 28; tint: Theme.textDim
                            }
                            Text {
                                Layout.alignment: Qt.AlignHCenter
                                text: qsTr("No breaches detected")
                                color: Theme.textDim
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                            }
                        }
                    }
                }
            }

            // ---- Password strength --------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: qsTr("Password strength")
                subtitle: qsTr("Run an audit to find weak and reused passwords.")

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp8
                    Layout.topMargin: Theme.sp3

                    Column {
                        spacing: 2
                        Text { text: "0"; color: Theme.danger
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontDisplay
                               font.weight: Font.Bold }
                        Text { text: qsTr("Weak")
                               color: Theme.textMuted
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontSmall }
                    }
                    Column {
                        spacing: 2
                        Text { text: "1"; color: Theme.warning
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontDisplay
                               font.weight: Font.Bold }
                        Text { text: qsTr("Reused")
                               color: Theme.textMuted
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontSmall }
                    }
                    Column {
                        spacing: 2
                        Text { text: "12"; color: Theme.success
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontDisplay
                               font.weight: Font.Bold }
                        Text { text: qsTr("Strong")
                               color: Theme.textMuted
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontSmall }
                    }
                    Item { Layout.fillWidth: true }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.sp3
                    Item { Layout.fillWidth: true }
                    PrimaryButton {
                        text: qsTr("Run password audit")
                        onClicked: page.runPasswordAudit()
                    }
                }
            }

            Item { Layout.fillHeight: true; implicitHeight: 1 }
        }
    }
}
