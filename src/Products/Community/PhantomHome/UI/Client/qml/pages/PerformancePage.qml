import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * PerformancePage
 * ---------------
 * Runtime device-health snapshot: CPU/RAM arc gauges, mode status dots,
 * three tune-up shortcut tiles and an advanced toggle checklist.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Performance")

    property real cpuPct:             0.0
    property real memPct:             0.0
    property bool gameModeActive:     false
    property bool batterySaverActive: false

    signal setGameMode(bool on)
    signal setBatterySaver(bool on)
    signal runTuneUp(string name)

    // Local-only advanced toggles — these would be persisted through
    // configureModule() once service-side wiring lands.
    property bool _scheduledDeepScan: false
    property bool _throttleUnderLoad: true

    function _statusColor(pct) {
        if (pct < 0.40) return Theme.success
        if (pct < 0.75) return Theme.warning
        return Theme.danger
    }

    component ArcGauge: Item {
        id: gauge
        property real value: 0.0
        property string label: ""
        implicitWidth: 180
        implicitHeight: 180

        Canvas {
            id: cv
            anchors.fill: parent
            antialiasing: true

            function drawArc(ctx, cx, cy, r, start, end, color, lw) {
                ctx.beginPath();
                ctx.lineWidth = lw;
                ctx.strokeStyle = color;
                ctx.lineCap = "round";
                ctx.arc(cx, cy, r, start, end, false);
                ctx.stroke();
            }

            onPaint: {
                var ctx = getContext("2d");
                ctx.reset();
                var cx = width / 2;
                var cy = height / 2;
                var r  = Math.min(width, height) / 2 - 14;
                var startAng = Math.PI * 0.75;
                var endAng   = Math.PI * 0.25 + Math.PI * 2;
                drawArc(ctx, cx, cy, r, startAng, endAng, Theme.bg3, 10);
                var v = Math.max(0, Math.min(1, gauge.value));
                var endFill = startAng + (endAng - startAng) * v;
                drawArc(ctx, cx, cy, r, startAng, endFill, page._statusColor(v), 10);
            }

            Connections {
                target: gauge
                function onValueChanged() { cv.requestPaint() }
            }
            Component.onCompleted: requestPaint()
        }

        ColumnLayout {
            anchors.centerIn: parent
            spacing: 2
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: gauge.label
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontCaption
                font.weight: Font.DemiBold
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: Math.round(gauge.value * 100) + "%"
                color: Theme.textStrong
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontDisplay
                font.weight: Font.Bold
            }
        }
    }

    component ToggleRow: Rectangle {
        id: rrow
        property string rowLabel: ""
        property string detail: ""
        property bool   rowChecked: false
        signal toggled(bool on)

        Layout.fillWidth: true
        implicitHeight: 64
        radius: Theme.radiusSm
        color: Theme.bg1
        border.width: 0

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.sp4
            anchors.rightMargin: Theme.sp3
            spacing: Theme.sp3
            Column {
                Layout.fillWidth: true
                spacing: 2
                Text { text: rrow.rowLabel; color: Theme.textStrong
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                       font.weight: Font.DemiBold }
                Text { text: rrow.detail; color: Theme.textMuted
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall
                       wrapMode: Text.WordWrap }
            }
            Switch {
                checked: rrow.rowChecked
                onToggled: rrow.toggled(checked)
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
                Text { text: qsTr("Performance"); color: Theme.textStrong
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: qsTr("Runtime budget and optimization.")
                       color: Theme.textMuted
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                title: qsTr("Device health")
                subtitle: qsTr("Protection engine utilisation over the last minute.")

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.sp3
                    spacing: Theme.sp8

                    ArcGauge { value: page.cpuPct; label: qsTr("CPU") }
                    ArcGauge { value: page.memPct; label: qsTr("RAM") }
                    Item { Layout.fillWidth: true }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.sp3
                    spacing: Theme.sp5

                    RowLayout {
                        spacing: Theme.sp2
                        Rectangle {
                            width: 8; height: 8; radius: 4
                            color: page.gameModeActive ? Theme.success : Theme.textDim
                        }
                        Text {
                            text: page.gameModeActive ? qsTr("Game mode: active")
                                                      : qsTr("Game mode: standby")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                    }
                    RowLayout {
                        spacing: Theme.sp2
                        Rectangle {
                            width: 8; height: 8; radius: 4
                            color: page.batterySaverActive ? Theme.success : Theme.textDim
                        }
                        Text {
                            text: page.batterySaverActive ? qsTr("Battery saver: active")
                                                          : qsTr("Battery saver: standby")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                    }
                    Item { Layout.fillWidth: true }
                }
            }

            SectionHeader {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                sectionTitle: qsTr("Quick tune-up")
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp3

                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 112
                    hoverable: true
                    clickable: true
                    title: qsTr("Free up disk space")
                    subtitle: qsTr("Clear caches, temp files and crash dumps.")
                    onClicked: page.runTuneUp("disk")
                }
                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 112
                    hoverable: true
                    clickable: true
                    title: qsTr("Disable unused startup items")
                    subtitle: qsTr("Shorten boot time by skipping dormant auto-starts.")
                    onClicked: page.runTuneUp("startup")
                }
                CardFrame {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 112
                    hoverable: true
                    clickable: true
                    title: qsTr("Clean browser traces")
                    subtitle: qsTr("Remove cookies, cache and saved form data.")
                    onClicked: page.runTuneUp("browser")
                }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: qsTr("Advanced")
                subtitle: qsTr("Fine-tune how the engine reacts under load.")

                ToggleRow {
                    rowLabel: qsTr("Game mode when fullscreen app detected")
                    detail: qsTr("Pauses notifications and scheduled scans while a game is in focus.")
                    rowChecked: page.gameModeActive
                    onToggled: (on) => page.setGameMode(on)
                }
                ToggleRow {
                    rowLabel: qsTr("Battery saver on battery")
                    detail: qsTr("Defers heavy scans until the device is plugged in.")
                    rowChecked: page.batterySaverActive
                    onToggled: (on) => page.setBatterySaver(on)
                }
                ToggleRow {
                    rowLabel: qsTr("Scheduled deep scan")
                    detail: qsTr("Runs a full-disk scan once per week, during idle hours.")
                    rowChecked: page._scheduledDeepScan
                    onToggled: (on) => page._scheduledDeepScan = on
                }
                ToggleRow {
                    rowLabel: qsTr("Throttle scans under load")
                    detail: qsTr("Reduces scanner priority when foreground apps need CPU.")
                    rowChecked: page._throttleUnderLoad
                    onToggled: (on) => page._throttleUnderLoad = on
                }
            }

            Item { Layout.fillHeight: true; implicitHeight: 1 }
        }
    }
}
