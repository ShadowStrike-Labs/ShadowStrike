import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * SettingsPage
 * ------------
 * General application settings and update preferences.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Settings")

    property bool  launchOnStartup:    true
    property bool  showNotifications:  true
    property int   logLevelIndex:      1   // 0=Error 1=Info 2=Debug
    property bool  automaticUpdates:   true
    property string lastUpdateCheck:   "Never"

    signal setLaunchOnStartup(bool on)
    signal setShowNotifications(bool on)
    signal setLogLevel(int index)
    signal setAutomaticUpdates(bool on)
    signal checkForUpdates()

    readonly property var logLevelModel: ["Error", "Info", "Debug"]

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
                Text { text: "Settings"; color: Theme.textStrong
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: "Application behaviour and update policy."
                       color: Theme.textMuted
                       font.family: Theme.fontFamily
                       font.pixelSize: Theme.fontBody }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                title: "General"

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: Theme.radiusSm
                    color: Theme.bg1
                    border.color: Theme.stroke
                    border.width: 1
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3
                        Text { Layout.fillWidth: true
                               text: "Launch at startup"
                               color: Theme.textStrong
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontBody }
                        Switch { checked: page.launchOnStartup
                                 onToggled: page.setLaunchOnStartup(checked) }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: Theme.radiusSm
                    color: Theme.bg1
                    border.color: Theme.stroke
                    border.width: 1
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3
                        Text { Layout.fillWidth: true
                               text: "Show notifications"
                               color: Theme.textStrong
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontBody }
                        Switch { checked: page.showNotifications
                                 onToggled: page.setShowNotifications(checked) }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: Theme.radiusSm
                    color: Theme.bg1
                    border.color: Theme.stroke
                    border.width: 1
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3
                        Text { Layout.fillWidth: true
                               text: "Log verbosity"
                               color: Theme.textStrong
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontBody }
                        ComboBox {
                            implicitWidth: 160
                            model: page.logLevelModel
                            currentIndex: page.logLevelIndex
                            onActivated: page.setLogLevel(currentIndex)
                        }
                    }
                }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: "Updates"
                subtitle: "Last check: " + page.lastUpdateCheck

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: Theme.radiusSm
                    color: Theme.bg1
                    border.color: Theme.stroke
                    border.width: 1
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3
                        Text { Layout.fillWidth: true
                               text: "Install signature updates automatically"
                               color: Theme.textStrong
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontBody }
                        Switch { checked: page.automaticUpdates
                                 onToggled: page.setAutomaticUpdates(checked) }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.sp3
                    spacing: Theme.sp3
                    Item { Layout.fillWidth: true }
                    PrimaryButton {
                        text: "Check for updates now"
                        onClicked: page.checkForUpdates()
                    }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
