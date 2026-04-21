import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * QuarantinePage
 * --------------
 * Quarantined-files list with per-row hover actions and an
 * empty-quarantine confirmation dialog.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Quarantine")

    // Legacy property kept for backward compatibility.
    property var items:            []
    property var quarantineItems:  []

    signal restore(string id)
    signal purge(string id)

    function _effectiveItems() {
        return quarantineItems.length > 0 ? quarantineItems : items;
    }

    function _severityColor(s) {
        if (s === "critical" || s === "high") return Theme.danger
        if (s === "medium")                   return Theme.warning
        if (s === "info" || s === "low")      return Theme.accentAlt
        return Theme.textMuted
    }

    function _formatQuarantinedTime(unixSecs) {
        if (!unixSecs) return "";
        var now = Math.floor(Date.now() / 1000);
        var delta = now - unixSecs;
        if (delta < 60)    return qsTr("Just now");
        if (delta < 3600)  return qsTr("%1 min ago").arg(Math.floor(delta / 60));
        if (delta < 86400) return qsTr("%1 h ago").arg(Math.floor(delta / 3600));
        if (delta < 7 * 86400) return qsTr("%1 d ago").arg(Math.floor(delta / 86400));
        return Qt.formatDateTime(new Date(unixSecs * 1000), Qt.DefaultLocaleShortDate);
    }

    Dialog {
        id: confirmDlg
        modal: true
        title: qsTr("Empty quarantine?")
        standardButtons: Dialog.Ok | Dialog.Cancel
        anchors.centerIn: parent
        width: 420

        Text {
            anchors.fill: parent
            text: qsTr("All isolated files will be permanently deleted. This cannot be undone.")
            color: Theme.text
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontBody
            wrapMode: Text.WordWrap
        }

        onAccepted: {
            var list = page._effectiveItems();
            for (var i = 0; i < list.length; ++i) {
                if (list[i] && list[i].id) page.purge(list[i].id);
            }
        }
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
                Text { text: qsTr("Quarantine"); color: Theme.textStrong
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: qsTr("Files isolated from the system until you review them.")
                       color: Theme.textMuted
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody }
            }

            // ---- Top row: count tile + empty quarantine button ----
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp3

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 100

                    Text {
                        text: page._effectiveItems().length.toString()
                        color: page._effectiveItems().length > 0 ? Theme.warning : Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontDisplay
                        font.weight: Font.Bold
                    }
                    Text {
                        text: qsTr("Items in quarantine")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSmall
                    }
                }

                Item { Layout.preferredWidth: Theme.sp4 }

                SecondaryButton {
                    text: qsTr("Empty quarantine")
                    danger: true
                    enabled: page._effectiveItems().length > 0
                    onClicked: confirmDlg.open()
                }
            }

            // ---- Isolated files list ------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: qsTr("Isolated files")

                // Empty state
                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 140
                    visible: page._effectiveItems().length === 0

                    ColumnLayout {
                        anchors.centerIn: parent
                        spacing: Theme.sp2
                        Iconed {
                            Layout.alignment: Qt.AlignHCenter
                            iconName: "shield"; size: 32; tint: Theme.success
                        }
                        Text {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr("Your device is clean \u2014 nothing in quarantine")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                    }
                }

                ListView {
                    id: qlist
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(560, Math.max(1, page._effectiveItems().length) * 64)
                    visible: page._effectiveItems().length > 0
                    model: page._effectiveItems()
                    spacing: 0
                    clip: true
                    interactive: true

                    delegate: Rectangle {
                        id: row
                        width: ListView.view.width
                        height: 64
                        radius: Theme.radiusSm
                        color: rowMouse.hovered ? Theme.bg3 : "transparent"
                        Behavior on color { ColorAnimation { duration: Theme.motionFast } }

                        HoverHandler { id: rowMouse }

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.sp3
                            anchors.rightMargin: Theme.sp3
                            spacing: Theme.sp3

                            Rectangle {
                                width: 8; height: 8; radius: 4
                                color: page._severityColor(modelData ? modelData.severity : "")
                                Layout.alignment: Qt.AlignVCenter
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2
                                Text {
                                    text: modelData ? (modelData.path || "") : ""
                                    color: Theme.textStrong
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontBody
                                    elide: Text.ElideMiddle
                                    Layout.fillWidth: true
                                }
                                Text {
                                    text: modelData ? (modelData.detectionName || "") : ""
                                    color: Theme.textMuted
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSmall
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }

                            Text {
                                text: modelData ? page._formatQuarantinedTime(modelData.quarantinedUnix) : ""
                                color: Theme.textDim
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                                Layout.preferredWidth: 90
                            }

                            SecondaryButton {
                                text: qsTr("Restore")
                                visible: rowMouse.hovered
                                onClicked: if (modelData && modelData.id) page.restore(modelData.id)
                            }
                            SecondaryButton {
                                text: qsTr("Delete")
                                danger: true
                                visible: rowMouse.hovered
                                onClicked: if (modelData && modelData.id) page.purge(modelData.id)
                            }
                        }
                    }
                }
            }

            Item { Layout.fillHeight: true; implicitHeight: 1 }
        }
    }
}
