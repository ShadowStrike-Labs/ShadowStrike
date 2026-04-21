import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * PerformancePage
 * ---------------
 * Runtime budget snapshot plus the two modes (Game / Battery saver)
 * that throttle scanning activity.
 */
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

    function budgetColor(pct) {
        if (pct < 0.40) return Theme.success
        if (pct < 0.75) return Theme.warning
        return Theme.danger
    }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            // Header
            Column {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: 4
                Text {
                    text: "Performance"
                    color: Theme.textStrong
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontTitle
                    font.weight: Font.DemiBold
                }
                Text {
                    text: "Runtime utilisation of the protection engine."
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp4

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 168
                    title: "CPU"
                    subtitle: "Average over the last minute"

                    RowLayout {
                        spacing: Theme.sp4
                        Layout.fillWidth: true
                        Text {
                            text: (page.cpuPct * 100).toFixed(0) + "%"
                            color: page.budgetColor(page.cpuPct)
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontDisplay + 6
                            font.weight: Font.DemiBold
                        }
                        Item { Layout.fillWidth: true }
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        height: 6
                        radius: 3
                        color: Theme.bg1
                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: parent.width * Math.max(0, Math.min(1, page.cpuPct))
                            radius: parent.radius
                            color: page.budgetColor(page.cpuPct)
                            Behavior on width { NumberAnimation { duration: Theme.motionNormal } }
                        }
                    }
                }

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 168
                    title: "Memory"
                    subtitle: "Working set of the protection engine"

                    RowLayout {
                        spacing: Theme.sp4
                        Layout.fillWidth: true
                        Text {
                            text: (page.memPct * 100).toFixed(0) + "%"
                            color: page.budgetColor(page.memPct)
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontDisplay + 6
                            font.weight: Font.DemiBold
                        }
                        Item { Layout.fillWidth: true }
                    }
                    Rectangle {
                        Layout.fillWidth: true
                        height: 6
                        radius: 3
                        color: Theme.bg1
                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: parent.width * Math.max(0, Math.min(1, page.memPct))
                            radius: parent.radius
                            color: page.budgetColor(page.memPct)
                            Behavior on width { NumberAnimation { duration: Theme.motionNormal } }
                        }
                    }
                }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: "Modes"
                subtitle: "Reduce background work during games or on battery."

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp4

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 68
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
                                Text { text: "Game mode"; color: Theme.textStrong
                                       font.family: Theme.fontFamily
                                       font.pixelSize: Theme.fontBody
                                       font.weight: Font.DemiBold }
                                Text { text: "Pauses notifications and scheduled scans."
                                       color: Theme.textMuted
                                       font.family: Theme.fontFamily
                                       font.pixelSize: Theme.fontSmall }
                            }
                            Switch { checked: page.gameModeActive
                                     onToggled: page.setGameMode(checked) }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 68
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
                                Text { text: "Battery saver"; color: Theme.textStrong
                                       font.family: Theme.fontFamily
                                       font.pixelSize: Theme.fontBody
                                       font.weight: Font.DemiBold }
                                Text { text: "Defers heavy scans until plugged in."
                                       color: Theme.textMuted
                                       font.family: Theme.fontFamily
                                       font.pixelSize: Theme.fontSmall }
                            }
                            Switch { checked: page.batterySaverActive
                                     onToggled: page.setBatterySaver(checked) }
                        }
                    }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
