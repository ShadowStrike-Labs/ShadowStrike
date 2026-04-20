import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Settings")

    property bool autoStart: true
    property bool telemetryEnabled: false
    property bool notifications: true
    property string updateChannel: "stable"

    signal setAutoStart(bool on)
    signal setTelemetry(bool on)
    signal setNotifications(bool on)
    signal setUpdateChannel(string channel)
    signal checkForUpdates()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp4

        Text { text: "Settings"; color: Theme.text
               font.family: Theme.fontFamily
               font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }

        CardFrame {
            title: "General"
            Layout.fillWidth: true
            RowLayout { Text { text: "Start at login"; color: Theme.text; Layout.fillWidth: true }
                        Switch { checked: page.autoStart
                                 onToggled: page.setAutoStart(checked) } }
            RowLayout { Text { text: "Show desktop notifications"; color: Theme.text; Layout.fillWidth: true }
                        Switch { checked: page.notifications
                                 onToggled: page.setNotifications(checked) } }
            RowLayout { Text { text: "Share anonymous telemetry"; color: Theme.text; Layout.fillWidth: true }
                        Switch { checked: page.telemetryEnabled
                                 onToggled: page.setTelemetry(checked) } }
        }

        CardFrame {
            title: "Updates"
            Layout.fillWidth: true
            RowLayout {
                ComboBox {
                    model: ["stable","beta","insider"]
                    currentIndex: model.indexOf(page.updateChannel)
                    onActivated: page.setUpdateChannel(currentText)
                }
                Button { text: "Check for updates"; onClicked: page.checkForUpdates() }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
