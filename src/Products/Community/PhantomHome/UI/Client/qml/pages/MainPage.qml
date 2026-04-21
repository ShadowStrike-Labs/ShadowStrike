import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * MainPage
 * --------
 * "At-a-glance" protection hub. Layout, Kaspersky-class:
 *
 *   +-------------------------------------------------------------+
 *   | [shield]  State copy                  [N modules protecting]|
 *   |           subcopy                                           |
 *   |           [ Fast scan ] [ Full scan ] [ Check updates ]     |
 *   +-------------------------------------------------------------+
 *   | Recommendations strip (compact, dismissible)                |
 *   +-------------------------------------------------------------+
 *   | Quick actions (4 icon tiles) | Activity timeline (compact)  |
 *   +-------------------------------------------------------------+
 *
 * Module count + "all enabled" logic are computed from the VM's
 * modules list so we don't need extra IPC.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Protection status")

    // Wired from App.qml -> ProtectionViewModel.
    property string protectionState:  "green"
    property string stateCopy:        "You are protected"
    property string stateSubCopy:     "Real-time protection is active."
    property string lastScan:         "\u2014"
    property int    threatsBlocked7d: 0
    property string updateStatus:     "Up to date"

    // Optional: when App.qml wires these, banners light up honestly.
    property var    modules:          []
    property var    recentEvents:     []

    signal startFastScan()
    signal openScanTab()
    signal openUpdateTab()
    signal openSecurityTab()
    signal openReportsTab()

    function severityFromState(s) {
        switch (s) {
        case "green":  return "ok"
        case "amber":  return "warn"
        case "red":    return "bad"
        case "paused": return "muted"
        }
        return "info"
    }
    function labelFromState(s) {
        switch (s) {
        case "green":  return qsTr("Protected")
        case "amber":  return qsTr("Attention needed")
        case "red":    return qsTr("At risk")
        case "paused": return qsTr("Paused")
        }
        return qsTr("Checking")
    }

    // -- Module summaries (derived from VM, no extra IPC) -------------
    function _moduleCounts() {
        var total    = modules.length;
        var running  = 0;
        var degraded = 0;
        var disabled = 0;
        for (var i = 0; i < total; ++i) {
            var m = modules[i];
            if (m.state === "running")  ++running;
            else if (m.state === "degraded") ++degraded;
            else if (m.state === "disabled") ++disabled;
        }
        return { total: total, running: running, degraded: degraded, disabled: disabled };
    }

    readonly property var counts: _moduleCounts()

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            // ================================================================
            //  HERO
            // ================================================================
            Rectangle {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.preferredHeight: heroRow.implicitHeight + Theme.sp8 * 2
                radius: Theme.radiusLg
                color: Theme.bg2
                border.color: Theme.stroke
                border.width: 1

                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.14) }
                    GradientStop { position: 1.0; color: Theme.bg2 }
                }

                // Soft accent halo top-right — pure decoration.
                Rectangle {
                    anchors.top: parent.top
                    anchors.right: parent.right
                    anchors.margins: -60
                    width: 240; height: 240
                    radius: 120
                    color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.10)
                    z: 0
                }

                RowLayout {
                    id: heroRow
                    anchors.fill: parent
                    anchors.margins: Theme.sp8
                    spacing: Theme.sp8
                    z: 1

                    ShieldAnimator {
                        id: shield
                        protectionState: page.protectionState
                        Layout.preferredWidth: 200
                        Layout.preferredHeight: 220
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp3

                        StatePill {
                            label: page.labelFromState(page.protectionState)
                            severity: page.severityFromState(page.protectionState)
                        }

                        Text {
                            text: page.stateCopy
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontDisplay
                            font.weight: Font.DemiBold
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                        Text {
                            text: page.stateSubCopy
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontBody
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                            Layout.maximumWidth: 640
                        }

                        // Module summary line.
                        RowLayout {
                            Layout.topMargin: Theme.sp2
                            spacing: Theme.sp3

                            Rectangle {
                                width: 28; height: 28; radius: 6
                                color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
                                Iconed { anchors.centerIn: parent; iconName: "shield"; size: 16; tint: Theme.accentAlt }
                            }
                            Text {
                                text: page.counts.total > 0
                                      ? qsTr("%1 of %2 protection modules are running")
                                            .arg(page.counts.running).arg(page.counts.total)
                                      : qsTr("Waiting for protection modules\u2026")
                                color: Theme.text
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                                Layout.alignment: Qt.AlignVCenter
                            }
                            Rectangle {
                                visible: page.counts.degraded + page.counts.disabled > 0
                                color: Qt.rgba(1.0, 0.76, 0.28, 0.18)
                                radius: 10
                                implicitHeight: issueText.implicitHeight + 6
                                implicitWidth:  issueText.implicitWidth  + 20
                                Text {
                                    id: issueText
                                    anchors.centerIn: parent
                                    text: qsTr("%1 need attention").arg(page.counts.degraded + page.counts.disabled)
                                    color: Theme.warning
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSmall
                                    font.weight: Font.DemiBold
                                }
                                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: page.openSecurityTab() }
                            }
                        }

                        RowLayout {
                            spacing: Theme.sp3
                            Layout.topMargin: Theme.sp3

                            PrimaryButton {
                                text: qsTr("Fast scan")
                                onClicked: page.startFastScan()
                                Accessible.name: qsTr("Fast scan")
                                Accessible.description: qsTr("Run a fast scan of frequently targeted system locations")
                            }
                            SecondaryButton {
                                text: qsTr("Full scan")
                                onClicked: page.openScanTab()
                            }
                            SecondaryButton {
                                text: qsTr("Check for updates")
                                onClicked: page.openUpdateTab()
                            }
                        }
                    }
                }
            }

            // ================================================================
            //  RECOMMENDATIONS STRIP (shown only when actionable)
            // ================================================================
            Item {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                visible: page.counts.degraded + page.counts.disabled > 0 || page.updateStatus.indexOf("fail") >= 0

                implicitHeight: recRow.implicitHeight

                RowLayout {
                    id: recRow
                    width: parent.width
                    spacing: Theme.sp3

                    Rectangle {
                        visible: page.counts.disabled > 0
                        Layout.fillWidth: true
                        Layout.preferredHeight: 82
                        radius: Theme.radiusMd
                        color: Theme.bg2
                        border.color: Qt.rgba(1.0, 0.76, 0.28, 0.35)
                        border.width: 1

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: Theme.sp4
                            spacing: Theme.sp4

                            Rectangle {
                                Layout.preferredWidth: 40; Layout.preferredHeight: 40
                                radius: Theme.radiusSm
                                color: Qt.rgba(1.0, 0.76, 0.28, 0.14)
                                Iconed { anchors.centerIn: parent; iconName: "bolt"; size: 22; tint: Theme.warning }
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2
                                Text {
                                    text: qsTr("%1 protection modules are disabled").arg(page.counts.disabled)
                                    color: Theme.textStrong
                                    font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                                    font.weight: Font.DemiBold
                                }
                                Text {
                                    text: qsTr("Defence-in-depth drops with every layer you turn off. Review what's off.")
                                    color: Theme.textMuted
                                    font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall
                                    wrapMode: Text.WordWrap
                                    Layout.fillWidth: true
                                }
                            }
                            PrimaryButton {
                                text: qsTr("Review")
                                onClicked: page.openSecurityTab()
                            }
                        }
                    }

                    Rectangle {
                        visible: page.counts.degraded > 0
                        Layout.fillWidth: true
                        Layout.preferredHeight: 82
                        radius: Theme.radiusMd
                        color: Theme.bg2
                        border.color: Qt.rgba(1.0, 0.31, 0.43, 0.35)
                        border.width: 1

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: Theme.sp4
                            spacing: Theme.sp4

                            Rectangle {
                                Layout.preferredWidth: 40; Layout.preferredHeight: 40
                                radius: Theme.radiusSm
                                color: Qt.rgba(1.0, 0.31, 0.43, 0.14)
                                Iconed { anchors.centerIn: parent; iconName: "shield"; size: 22; tint: Theme.danger }
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2
                                Text {
                                    text: qsTr("%1 module(s) reporting degraded state").arg(page.counts.degraded)
                                    color: Theme.textStrong
                                    font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                                    font.weight: Font.DemiBold
                                }
                                Text {
                                    text: qsTr("These layers are running but have reported a fault. Check the module detail for remediation.")
                                    color: Theme.textMuted
                                    font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall
                                    wrapMode: Text.WordWrap
                                    Layout.fillWidth: true
                                }
                            }
                            PrimaryButton {
                                text: qsTr("Inspect")
                                onClicked: page.openSecurityTab()
                            }
                        }
                    }
                }
            }

            // ================================================================
            //  STATS ROW
            // ================================================================
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp4

                // Last scan -------------------------------------------------
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 110
                    radius: Theme.radiusMd
                    color: Theme.bg2
                    border.color: Theme.stroke
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: Theme.sp4
                        spacing: Theme.sp3

                        Rectangle {
                            Layout.preferredWidth: 42; Layout.preferredHeight: 42
                            radius: Theme.radiusSm
                            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.16)
                            Iconed { anchors.centerIn: parent; iconName: "radar"; size: 22; tint: Theme.accentAlt }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2
                            Text { text: qsTr("Last scan"); color: Theme.textMuted;
                                   font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                            Text { text: page.lastScan; color: Theme.textStrong;
                                   font.family: Theme.fontFamily; font.pixelSize: Theme.fontHeading; font.weight: Font.Medium }
                        }
                    }
                }

                // Threats blocked ------------------------------------------
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 110
                    radius: Theme.radiusMd
                    color: Theme.bg2
                    border.color: Theme.stroke
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: Theme.sp4
                        spacing: Theme.sp3

                        Rectangle {
                            Layout.preferredWidth: 42; Layout.preferredHeight: 42
                            radius: Theme.radiusSm
                            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.16)
                            Iconed { anchors.centerIn: parent; iconName: "shield"; size: 22; tint: Theme.accentAlt }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2
                            Text { text: qsTr("Threats blocked (7d)"); color: Theme.textMuted;
                                   font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                            RowLayout {
                                spacing: Theme.sp2
                                Text { text: page.threatsBlocked7d; color: Theme.textStrong;
                                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle; font.weight: Font.DemiBold }
                                Text { text: qsTr("blocked"); color: Theme.textMuted;
                                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                                       Layout.alignment: Qt.AlignBottom; bottomPadding: 4 }
                            }
                        }
                    }
                }

                // Updates --------------------------------------------------
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 110
                    radius: Theme.radiusMd
                    color: Theme.bg2
                    border.color: Theme.stroke
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.margins: Theme.sp4
                        spacing: Theme.sp3

                        Rectangle {
                            Layout.preferredWidth: 42; Layout.preferredHeight: 42
                            radius: Theme.radiusSm
                            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.16)
                            Iconed { anchors.centerIn: parent; iconName: "cog"; size: 22; tint: Theme.accentAlt }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2
                            Text { text: qsTr("Updates"); color: Theme.textMuted;
                                   font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                            RowLayout {
                                spacing: Theme.sp2
                                Rectangle { width: 8; height: 8; radius: 4
                                    color: page.updateStatus.toLowerCase().indexOf("fail") >= 0 ? Theme.danger
                                         : page.updateStatus.toLowerCase().indexOf("check") >= 0 ? Theme.warning
                                         : Theme.success }
                                Text { text: page.updateStatus; color: Theme.textStrong;
                                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody; font.weight: Font.Medium }
                            }
                        }
                    }
                }
            }

            // ================================================================
            //  QUICK ACTIONS + ACTIVITY
            // ================================================================
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp8
                spacing: Theme.sp4

                // Quick actions (2/3 width) -------------------------------
                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 600
                    title: qsTr("Quick actions")
                    subtitle: qsTr("Common tasks you can run right now")

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        columnSpacing: Theme.sp3
                        rowSpacing: Theme.sp3

                        Repeater {
                            model: [
                                { title: qsTr("Quick scan"),       desc: qsTr("Common locations"),    icon: "radar",   target: "scan"   },
                                { title: qsTr("Full system scan"), desc: qsTr("All drives"),          icon: "shield",  target: "scan"   },
                                { title: qsTr("Module settings"),  desc: qsTr("Fine-tune protection"),icon: "cog",     target: "sec"    },
                                { title: qsTr("Activity reports"), desc: qsTr("Recent events"),       icon: "radar",   target: "rep"    }
                            ]
                            delegate: Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 84
                                radius: Theme.radiusMd
                                color: hover.hovered ? Theme.bg3 : Theme.bg1
                                border.color: hover.hovered ? Theme.accentAlt : Theme.stroke
                                border.width: 1
                                Behavior on color        { ColorAnimation { duration: Theme.motionFast } }
                                Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: Theme.sp3
                                    spacing: Theme.sp3

                                    Rectangle {
                                        Layout.preferredWidth: 42; Layout.preferredHeight: 42
                                        radius: Theme.radiusSm
                                        color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.16)
                                        Iconed { anchors.centerIn: parent; iconName: modelData.icon; size: 22; tint: Theme.accentAlt }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 2
                                        Text {
                                            text: modelData.title
                                            color: Theme.textStrong
                                            font.family: Theme.fontFamily
                                            font.pixelSize: Theme.fontBody
                                            font.weight: Font.DemiBold
                                        }
                                        Text {
                                            text: modelData.desc
                                            color: Theme.textMuted
                                            font.family: Theme.fontFamily
                                            font.pixelSize: Theme.fontSmall
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }
                                    Iconed {
                                        iconName: "chevron-right"
                                        size: 16
                                        tint: Theme.textMuted
                                    }
                                }

                                HoverHandler { id: hover }
                                TapHandler {
                                    onTapped: {
                                        if (modelData.target === "sec")  page.openSecurityTab()
                                        else if (modelData.target === "rep") page.openReportsTab()
                                        else page.openScanTab()
                                    }
                                }
                            }
                        }
                    }
                }

                // Activity timeline (1/3 width) ---------------------------
                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 340
                    Layout.minimumWidth: 280
                    title: qsTr("Recent activity")
                    subtitle: qsTr("Latest detections and actions")

                    Column {
                        Layout.fillWidth: true
                        spacing: Theme.sp2

                        Repeater {
                            model: (page.recentEvents && page.recentEvents.length > 0) ? page.recentEvents.slice(0, 4) : []
                            delegate: RowLayout {
                                width: parent ? parent.width : 0
                                spacing: Theme.sp3

                                Rectangle {
                                    width: 8; height: 8; radius: 4
                                    color: (modelData && modelData.severity === "high")   ? Theme.danger
                                         : (modelData && modelData.severity === "medium") ? Theme.warning
                                         : Theme.accentAlt
                                    Layout.alignment: Qt.AlignTop
                                    Layout.topMargin: 6
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 1
                                    Text {
                                        text: (modelData && modelData.title) ? modelData.title : qsTr("Event")
                                        color: Theme.text
                                        font.family: Theme.fontFamily
                                        font.pixelSize: Theme.fontSmall
                                        font.weight: Font.DemiBold
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                    Text {
                                        text: (modelData && modelData.detail) ? modelData.detail : ""
                                        color: Theme.textMuted
                                        font.family: Theme.fontFamily
                                        font.pixelSize: Theme.fontCaption
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }
                                }
                                Text {
                                    text: (modelData && modelData.when) ? modelData.when : ""
                                    color: Theme.textDim
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontCaption
                                }
                            }
                        }

                        Text {
                            visible: !page.recentEvents || page.recentEvents.length === 0
                            text: qsTr("No recent events. You'll see detections and actions here as they happen.")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            wrapMode: Text.WordWrap
                            width: parent.width
                        }

                        SecondaryButton {
                            visible: page.recentEvents && page.recentEvents.length > 0
                            text: qsTr("Open full report")
                            onClicked: page.openReportsTab()
                        }
                    }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
