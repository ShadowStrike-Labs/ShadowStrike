import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Performance")

    property real cpuPct: 0.0
    property real memPct: 0.0
    property bool gameModeActive: false
    property bool batterySaverActive: false

    signal setGameMode(bool on)
    signal setBatterySaver(bool on)

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp4

        Text { text: "Performance"; color: Theme.text; font.family: Theme.fontFamily
               font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }

        CardFrame {
            title: "Runtime"
            Layout.fillWidth: true
            RowLayout {
                spacing: Theme.sp6
                ColumnLayout {
                    Text { text: "CPU"; color: Theme.textMuted; font.pixelSize: Theme.fontSmall }
                    Text { text: (page.cpuPct * 100).toFixed(0) + " %"; color: Theme.text
                           font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }
                }
                ColumnLayout {
                    Text { text: "Memory"; color: Theme.textMuted; font.pixelSize: Theme.fontSmall }
                    Text { text: (page.memPct * 100).toFixed(0) + " %"; color: Theme.text
                           font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }
                }
            }
        }

        CardFrame {
            title: "Modes"
            Layout.fillWidth: true
            RowLayout {
                spacing: Theme.sp6
                RowLayout {
                    Text { text: "Game mode"; color: Theme.text; font.pixelSize: Theme.fontBody }
                    Switch { checked: page.gameModeActive
                             onToggled: page.setGameMode(checked) }
                }
                RowLayout {
                    Text { text: "Battery saver"; color: Theme.text; font.pixelSize: Theme.fontBody }
                    Switch { checked: page.batterySaverActive
                             onToggled: page.setBatterySaver(checked) }
                }
            }
        }

        Item { Layout.fillHeight: true }
    }
}
