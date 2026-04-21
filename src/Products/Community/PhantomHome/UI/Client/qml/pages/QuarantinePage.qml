import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * QuarantinePage
 * --------------
 * List of isolated items, each with restore / delete affordances.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Quarantine")

    // [{id, path, sha256, detectionName, quarantinedUnix, severity}]
    property var items: []

    signal restore(string id)
    signal purge(string id)

    function severityPillFor(s) {
        if (s === "high" || s === "critical") return "bad"
        if (s === "medium")                   return "warn"
        if (s === "low")                      return "info"
        return "muted"
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
            Text { text: "Quarantine"; color: Theme.textStrong
                   font.family: Theme.fontFamily
                   font.pixelSize: Theme.fontTitle
                   font.weight: Font.DemiBold }
            Text { text: "Items that have been isolated from the file system."
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
            title: "Isolated items"
            subtitle: page.items.length === 0
                      ? "Nothing is currently quarantined."
                      : page.items.length + " item(s) in quarantine."

            ListView {
                id: list
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredHeight: 400
                model: page.items
                spacing: Theme.sp2
                clip: true

                delegate: Rectangle {
                    width: ListView.view.width
                    height: 66
                    color: Theme.bg1
                    border.color: Theme.stroke
                    border.width: 1
                    radius: Theme.radiusSm

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3

                        StatePill { label: modelData.severity
                                    severity: page.severityPillFor(modelData.severity) }

                        Column {
                            Layout.fillWidth: true
                            spacing: 2
                            Text { text: modelData.path
                                   color: Theme.textStrong
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontBody
                                   elide: Text.ElideMiddle
                                   width: list.width - 240 }
                            Text { text: modelData.detectionName
                                   color: Theme.textMuted
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontSmall }
                        }
                        SecondaryButton { text: "Restore"
                                          onClicked: page.restore(modelData.id) }
                        SecondaryButton { text: "Delete"; danger: true
                                          onClicked: page.purge(modelData.id) }
                    }
                }
            }
        }
    }
}
