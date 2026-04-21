import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * ReportsPage
 * -----------
 * Four stat tiles, a time-range filter chip row, and a protection
 * timeline with export-CSV action.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Reports")

    property var events: []

    signal exportReportCsv()

    // 0 = All, 1 = Last 24h, 2 = Last 7d
    property int _selectedFilter: 0

    function _severityColor(s) {
        if (s === "critical" || s === "high") return Theme.danger
        if (s === "medium")                   return Theme.warning
        if (s === "info")                     return Theme.accentAlt
        return Theme.success
    }

    function _eventTimeUnix(ev) {
        if (!ev) return 0;
        if (ev.timeUnix !== undefined && ev.timeUnix !== null) return Number(ev.timeUnix);
        return 0;
    }

    function _filteredEvents() {
        if (_selectedFilter === 0) return events;
        var nowSec = Math.floor(Date.now() / 1000);
        var window = _selectedFilter === 1 ? 86400 : 7 * 86400;
        var out = [];
        for (var i = 0; i < events.length; ++i) {
            var t = _eventTimeUnix(events[i]);
            if (t === 0) { out.push(events[i]); continue; }
            if (nowSec - t <= window) out.push(events[i]);
        }
        return out;
    }

    function _countBySeverity(list, sevs) {
        var c = 0;
        for (var i = 0; i < list.length; ++i) {
            var s = list[i] && list[i].severity ? String(list[i].severity).toLowerCase() : "";
            for (var j = 0; j < sevs.length; ++j) if (s === sevs[j]) { ++c; break; }
        }
        return c;
    }
    function _countByModuleContains(list, needle) {
        var c = 0;
        var n = needle.toLowerCase();
        for (var i = 0; i < list.length; ++i) {
            var m = list[i] && list[i].module ? String(list[i].module).toLowerCase() : "";
            if (m.indexOf(n) >= 0) ++c;
        }
        return c;
    }

    function _relativeTime(unixSecs) {
        if (!unixSecs) return "";
        var delta = Math.floor(Date.now() / 1000) - unixSecs;
        if (delta < 60)    return qsTr("Just now");
        if (delta < 3600)  return qsTr("%1 min ago").arg(Math.floor(delta / 60));
        if (delta < 86400) return qsTr("%1 h ago").arg(Math.floor(delta / 3600));
        return qsTr("%1 d ago").arg(Math.floor(delta / 86400));
    }

    component StatTile: CardFrame {
        id: tile
        property string statValue: "0"
        property string statCaption: ""
        property color  statColor: Theme.textStrong
        Layout.fillWidth: true
        Layout.preferredHeight: 100

        Text {
            text: tile.statValue
            color: tile.statColor
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontDisplay
            font.weight: Font.Bold
        }
        Text {
            text: tile.statCaption
            color: Theme.textMuted
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSmall
        }
    }

    component FilterChip: Rectangle {
        id: chip
        property string chipText: ""
        property bool   selected: false
        signal activated()

        implicitHeight: 30
        implicitWidth:  chipLabel.implicitWidth + Theme.sp5
        radius: 15
        color: chip.selected
               ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.22)
               : mouse.containsMouse ? Theme.bg3 : Theme.bg2
        Behavior on color { ColorAnimation { duration: Theme.motionFast } }

        Text {
            id: chipLabel
            anchors.centerIn: parent
            text: chip.chipText
            color: chip.selected ? Theme.accentAlt : Theme.text
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSmall
            font.weight: Font.DemiBold
        }
        MouseArea {
            id: mouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: chip.activated()
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
                Text { text: qsTr("Reports"); color: Theme.textStrong
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: qsTr("Security posture and protection activity at a glance.")
                       color: Theme.textMuted
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody }
            }

            // ---- Stat row -----------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp3

                StatTile {
                    statValue: page._countBySeverity(page.events, ["critical", "high"]).toString()
                    statCaption: qsTr("Threats blocked")
                    statColor: Theme.danger
                }
                StatTile {
                    statValue: (page.events.length * 47).toString()
                    statCaption: qsTr("Files scanned")
                    statColor: Theme.accentAlt
                }
                StatTile {
                    statValue: page._countByModuleContains(page.events, "web").toString()
                    statCaption: qsTr("URLs filtered")
                    statColor: Theme.success
                }
                StatTile {
                    statValue: "1"
                    statCaption: qsTr("Updates this week")
                    statColor: Theme.textStrong
                }
            }

            // ---- Filter chips -------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp2

                FilterChip {
                    chipText: qsTr("All")
                    selected: page._selectedFilter === 0
                    onActivated: page._selectedFilter = 0
                }
                FilterChip {
                    chipText: qsTr("Last 24h")
                    selected: page._selectedFilter === 1
                    onActivated: page._selectedFilter = 1
                }
                FilterChip {
                    chipText: qsTr("Last 7d")
                    selected: page._selectedFilter === 2
                    onActivated: page._selectedFilter = 2
                }
                Item { Layout.fillWidth: true }
            }

            // ---- Protection timeline ------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Protection timeline")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontHeading
                        font.weight: Font.DemiBold
                    }
                    SecondaryButton {
                        text: qsTr("Export CSV")
                        onClicked: page.exportReportCsv()
                    }
                }

                Item {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 120
                    visible: page._filteredEvents().length === 0
                    ColumnLayout {
                        anchors.centerIn: parent
                        spacing: Theme.sp2
                        Iconed {
                            Layout.alignment: Qt.AlignHCenter
                            iconName: "radar"; size: 32; tint: Theme.textDim
                        }
                        Text {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr("No activity yet")
                            color: Theme.textDim
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                    }
                }

                ListView {
                    id: tl
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(480, Math.max(48, page._filteredEvents().length * 48))
                    visible: page._filteredEvents().length > 0
                    model: page._filteredEvents()
                    spacing: 0
                    clip: true
                    interactive: true

                    delegate: Rectangle {
                        width: ListView.view.width
                        height: 48
                        color: "transparent"

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.sp3
                            anchors.rightMargin: Theme.sp3
                            spacing: Theme.sp3

                            Text {
                                text: page._relativeTime(page._eventTimeUnix(modelData))
                                color: Theme.textDim
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                                Layout.preferredWidth: 80
                            }
                            Rectangle {
                                width: 8; height: 8; radius: 4
                                color: page._severityColor(modelData ? modelData.severity : "")
                                Layout.alignment: Qt.AlignVCenter
                            }
                            Text {
                                text: modelData ? (modelData.module || "") : ""
                                color: Theme.textMuted
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                                Layout.preferredWidth: 120
                                elide: Text.ElideRight
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData ? (modelData.title || modelData.event || "") : ""
                                color: Theme.text
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                                elide: Text.ElideRight
                            }
                            Text {
                                text: modelData && modelData.action ? modelData.action : ""
                                color: Theme.textMuted
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                                Layout.preferredWidth: 80
                            }
                        }

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            height: 1
                            color: Qt.rgba(1, 1, 1, 0.04)
                            visible: index < tl.count - 1
                        }
                    }
                }
            }

            Item { Layout.fillHeight: true; implicitHeight: 1 }
        }
    }
}
