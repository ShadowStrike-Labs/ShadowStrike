import QtQuick
import QtQuick.Layouts
import "../Theming"

/*
 * ActivityTimeline
 * ----------------
 * Vertical event list with a severity-coloured dot spine. Model is a
 * plain JS array of objects: { title|event, module, severity, timeUnix }.
 */
Item {
    id: root

    property var model:    []
    property int maxItems: 8

    implicitHeight: content.implicitHeight
    Layout.fillWidth: true

    function _severityColor(sev) {
        if (!sev) return Theme.textDim
        var s = String(sev).toLowerCase()
        if (s === "critical" || s === "high") return Theme.danger
        if (s === "medium" || s === "warn")   return Theme.warning
        if (s === "info")                     return Theme.accentAlt
        return Theme.success
    }

    function _relativeTime(unixSecs) {
        if (!unixSecs) return ""
        var delta = Math.floor(Date.now() / 1000) - unixSecs
        if (delta < 60)    return qsTr("Just now")
        if (delta < 3600)  return qsTr("%1 min ago").arg(Math.floor(delta / 60))
        if (delta < 86400) return qsTr("%1 h ago").arg(Math.floor(delta / 3600))
        return qsTr("%1 d ago").arg(Math.floor(delta / 86400))
    }

    ColumnLayout {
        id: content
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: 0

        Item {
            visible: root.model.length === 0
            Layout.fillWidth: true
            implicitHeight: 80
            ColumnLayout {
                anchors.centerIn: parent
                spacing: Theme.sp2
                Iconed {
                    Layout.alignment: Qt.AlignHCenter
                    iconName: "radar"; size: 28; tint: Theme.textDim
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: qsTr("No recent activity")
                    color: Theme.textDim
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                }
            }
        }

        Repeater {
            model: Math.min(root.model.length, root.maxItems)
            delegate: RowLayout {
                id: rowDel
                property var ev: root.model[index]
                property bool isLast: index >= Math.min(root.model.length, root.maxItems) - 1

                Layout.fillWidth: true
                Layout.preferredHeight: 44
                spacing: Theme.sp3

                ColumnLayout {
                    spacing: 0
                    Layout.preferredWidth: 16
                    Layout.alignment: Qt.AlignTop
                    Layout.topMargin: 10
                    Rectangle {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: 8
                        Layout.preferredHeight: 8
                        radius: 4
                        color: root._severityColor(rowDel.ev ? rowDel.ev.severity : "")
                    }
                    Rectangle {
                        visible: !rowDel.isLast
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: 1
                        Layout.preferredHeight: 24
                        color: Qt.rgba(1, 1, 1, 0.06)
                    }
                }

                Text {
                    Layout.fillWidth: true
                    text: rowDel.ev ? (rowDel.ev.title || rowDel.ev.event || "") : ""
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    elide: Text.ElideRight
                }
                Text {
                    text: rowDel.ev ? (rowDel.ev.module || "") : ""
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    elide: Text.ElideRight
                    Layout.preferredWidth: 100
                }
                Text {
                    text: rowDel.ev ? root._relativeTime(rowDel.ev.timeUnix) : ""
                    color: Theme.textDim
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    Layout.preferredWidth: 70
                }
            }
        }
    }
}
