import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * ReportsPage
 * -----------
 * Event log of security decisions: each row shows a severity-coloured
 * bar on the left plus a short description, path, and timestamp.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Reports")

    // [{timestamp, severity, event, detail}]
    property var events: []

    function barColor(s) {
        if (s === "critical" || s === "high") return Theme.danger
        if (s === "medium")                   return Theme.warning
        if (s === "info")                     return Theme.accentAlt
        return Theme.success
    }

    function pillFor(s) {
        if (s === "critical" || s === "high") return "bad"
        if (s === "medium")                   return "warn"
        if (s === "info")                     return "info"
        return "ok"
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.sp5

        Column {
            Layout.fillWidth: true
            Layout.topMargin: Theme.sp6
            Layout.leftMargin: Theme.sp8
            Layout.rightMargin: Theme.sp8
            spacing: 4
            Text { text: "Reports"; color: Theme.textStrong
                   font.family: Theme.fontFamily
                   font.pixelSize: Theme.fontTitle
                   font.weight: Font.DemiBold }
            Text { text: "Recent events recorded by the protection engine."
                   color: Theme.textMuted
                   font.family: Theme.fontFamily
                   font.pixelSize: Theme.fontBody }
        }

        CardFrame {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: Theme.sp8
            Layout.rightMargin: Theme.sp8
            Layout.bottomMargin: Theme.sp6
            title: "Activity log"
            subtitle: page.events.length === 0
                      ? "No recent activity."
                      : page.events.length + " event(s)."

            ListView {
                id: list
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredHeight: 420
                model: page.events
                spacing: Theme.sp2
                clip: true

                delegate: Rectangle {
                    width: ListView.view.width
                    height: 64
                    color: Theme.bg1
                    border.color: Theme.stroke
                    border.width: 1
                    radius: Theme.radiusSm

                    // Severity bar
                    Rectangle {
                        width: 4
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.left: parent.left
                        anchors.margins: 1
                        radius: 2
                        color: page.barColor(modelData.severity)
                    }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4 + 4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3

                        Column {
                            Layout.fillWidth: true
                            spacing: 2
                            Text { text: modelData.event
                                   color: Theme.textStrong
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontBody
                                   font.weight: Font.DemiBold }
                            Text { text: modelData.detail !== undefined ? modelData.detail : ""
                                   color: Theme.textMuted
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontSmall
                                   elide: Text.ElideMiddle
                                   width: list.width - 260 }
                        }
                        StatePill { label: modelData.severity
                                    severity: page.pillFor(modelData.severity) }
                        Text { text: modelData.timestamp !== undefined ? modelData.timestamp : ""
                               color: Theme.textMuted
                               font.family: Theme.fontFamily
                               font.pixelSize: Theme.fontSmall }
                    }
                }
            }
        }
    }
}
