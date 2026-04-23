/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PerformancePage.qml — Calm-surface performance impact dashboard.
 * Displays TPM/CPU/Memory impact, recent optimizations, power plan,
 * scheduled scan impact, and binds to perfBudget.animationsPaused.
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    // Power plan: 0=Quiet, 1=Balanced, 2=Performance
    property int currentPowerPlan: 1

    // Upcoming scans model — caller may replace with a live model.
    property var upcomingScansModel: [
        { name: qsTr("Full system scan"),   scheduled: qsTr("Today, 11:00 PM") },
        { name: qsTr("Quick scan"),         scheduled: qsTr("Tomorrow, 6:00 AM") },
        { name: qsTr("Definitions update"), scheduled: qsTr("Tomorrow, 3:00 AM") },
    ]

    // Recent optimizations — positive-tone rows.
    readonly property var recentOptimizations: [
        { text: qsTr("Paused definitions update during gameplay"), time: qsTr("2 min ago"),   ok: true  },
        { text: qsTr("Throttled background scanner"),              time: qsTr("14 min ago"),  ok: true  },
        { text: qsTr("Deferred full scan during high CPU load"),   time: qsTr("1 hr ago"),    ok: true  },
        { text: qsTr("Suspended telemetry sync during video call"),time: qsTr("3 hrs ago"),   ok: true  },
    ]

    // Power plan labels — 3-mode subset: Quiet/Balanced/Performance.
    // ModePillRow uses a 4-mode bitmask (Off/Passive/Balanced/Aggressive),
    // so we map our 3 modes onto bits 0,1,2 and hide bit 3.
    readonly property int powerPlanMask: 0b0111   // Quiet=0, Balanced=1, Performance=2

    // -------------------------------------------------------------------------
    // Scroll container
    // -------------------------------------------------------------------------

    ScrollView {
        id: scroll
        anchors.fill:           parent
        contentWidth:           parent.width
        clip:                   true

        Column {
            id:      pageColumn
            width:   scroll.width
            spacing: Theme.spacingL
            padding: Theme.spacingL

            // -----------------------------------------------------------------
            // Page header
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Performance")
                width: parent.width - Theme.spacingL * 2
            }

            // -----------------------------------------------------------------
            // 1. Hero card: TPM / CPU / Memory impact summary
            // -----------------------------------------------------------------
            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    Text {
                        text:           qsTr("System impact")
                        color:          Theme.textPrimary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeTitle
                        font.weight:    Theme.fontWeightBold
                    }

                    Text {
                        text:           qsTr("Protection is running efficiently with minimal resource use.")
                        color:          Theme.textSecondary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }

                    // Gauge row — static when animationsPaused, animated otherwise.
                    Row {
                        spacing: Theme.spacingM
                        width:   parent.width

                        Repeater {
                            model: [
                                { label: qsTr("TPM"),    pct: 2,  state: "on"  },
                                { label: qsTr("CPU"),    pct: 4,  state: "on"  },
                                { label: qsTr("Memory"), pct: 38, state: "warning" },
                            ]
                            delegate: Column {
                                spacing:       Theme.spacingXS
                                width:         (parent.width - Theme.spacingM * 2) / 3
                                leftPadding:   0

                                Text {
                                    text:           modelData.label
                                    color:          Theme.textSecondary
                                    font.family:    Theme.fontFamily
                                    font.pixelSize: Theme.fontSizeLabel
                                    font.weight:    Theme.fontWeightMedium
                                }

                                // Gauge bar
                                Rectangle {
                                    width:  parent.width
                                    height: 6
                                    radius: 3
                                    color:  Theme.strokeSubtle

                                    Rectangle {
                                        id:     fillBar
                                        height: parent.height
                                        radius: parent.radius
                                        color:  modelData.state === "warning" ? Theme.warn : Theme.ok

                                        // Width driven by animated or static percentage.
                                        width: animTarget.running
                                               ? animTarget.currentPct / 100 * parent.width
                                               : modelData.pct / 100 * parent.width

                                        NumberAnimation {
                                            id:       animTarget
                                            target:   fillBar
                                            property: "width"
                                            // Pulse animation only when not paused.
                                            running:  !(typeof perfBudget !== 'undefined' && perfBudget.animationsPaused)
                                            from:     modelData.pct / 100 * parent.parent.width * 0.85
                                            to:       modelData.pct / 100 * parent.parent.width
                                            duration: Theme.motionHeroPulse
                                            loops:    Animation.Infinite
                                            easing.type: Easing.InOutSine

                                            // Expose current value for width binding.
                                            property real currentPct: modelData.pct
                                        }
                                    }
                                }

                                Text {
                                    text:           qsTr("%1%").arg(modelData.pct)
                                    color:          modelData.state === "warning" ? Theme.warn : Theme.ok
                                    font.family:    Theme.fontFamily
                                    font.pixelSize: Theme.fontSizeLabel
                                    font.weight:    Theme.fontWeightMedium
                                }

                                StatusChip {
                                    state: modelData.state
                                    label: modelData.state === "warning"
                                           ? qsTr("Moderate")
                                           : qsTr("Low")
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 2. Recent optimizations
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Recent optimizations")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: 0

                    Repeater {
                        model: root.recentOptimizations
                        delegate: Item {
                            width:  parent.width
                            height: 44

                            Rectangle {
                                anchors.bottom: parent.bottom
                                width:          parent.width
                                height:         1
                                color:          Theme.strokeSubtle
                                visible:        index < root.recentOptimizations.length - 1
                            }

                            Row {
                                anchors {
                                    verticalCenter: parent.verticalCenter
                                    left:           parent.left
                                    right:          parent.right
                                }
                                spacing: Theme.spacingS

                                // Positive indicator dot
                                Rectangle {
                                    width:              8
                                    height:             8
                                    radius:             4
                                    color:              Theme.ok
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Text {
                                    text:               modelData.text
                                    color:              Theme.textPrimary
                                    font.family:        Theme.fontFamily
                                    font.pixelSize:     Theme.fontSizeBody
                                    elide:              Text.ElideRight
                                    width:              parent.width - 8 - 72 - Theme.spacingS * 2
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                Text {
                                    text:               modelData.time
                                    color:              Theme.textMuted
                                    font.family:        Theme.fontFamily
                                    font.pixelSize:     Theme.fontSizeMicro
                                    anchors.verticalCenter: parent.verticalCenter
                                    width:              72
                                    horizontalAlignment: Text.AlignRight
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 3. Power plan
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Power plan")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    Text {
                        text:           qsTr("Control how aggressively the scanner uses system resources.")
                        color:          Theme.textSecondary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }

                    // ModePillRow: Off=Quiet(0), Passive=Balanced(1), Balanced=Performance(2)
                    // We hide Aggressive(3) via supportedModesMask = 0b0111.
                    ModePillRow {
                        id:               powerPillRow
                        currentMode:      root.currentPowerPlan
                        supportedModesMask: root.powerPlanMask
                        onModeChosen: function(mode) {
                            root.currentPowerPlan = mode;
                            // Write-back via PerformanceViewModel if available.
                            if (typeof performanceViewModel !== 'undefined') {
                                performanceViewModel.setPowerPlan(mode);
                            } else {
                                // TODO: wire to performanceViewModel.setPowerPlan once the VM is authored.
                                console.log("[PerformancePage] powerPlan changed to", mode,
                                            "— PerformanceViewModel not yet registered.");
                            }
                            // Write-back via perfBudget context property.
                            if (typeof perfBudget !== 'undefined') {
                                // perfBudget exposes animationsPaused; power-plan is a separate concern.
                                // No direct setter on PerfBudgetContext; VM integration handles it.
                            }
                        }

                        FocusRing { target: powerPillRow }
                        activeFocusOnTab: true
                        Accessible.role: Accessible.ComboBox
                        Accessible.name: qsTr("Power plan selector")
                    }

                    // Mode description text
                    Text {
                        text: {
                            switch (root.currentPowerPlan) {
                            case 0: return qsTr("Quiet — Minimal background activity. Scans run only when idle.")
                            case 1: return qsTr("Balanced — Smart throttling. Recommended for most users.")
                            case 2: return qsTr("Performance — Full scanning power. May briefly increase CPU use.")
                            default: return ""
                            }
                        }
                        color:          Theme.textMuted
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeLabel
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }
                }
            }

            // -----------------------------------------------------------------
            // 4. Scheduled scans impact
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Scheduled scans")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: 0

                    Repeater {
                        model: root.upcomingScansModel
                        delegate: Item {
                            width:  parent.width
                            height: 52

                            Rectangle {
                                anchors.bottom: parent.bottom
                                width:          parent.width
                                height:         1
                                color:          Theme.strokeSubtle
                                visible:        index < root.upcomingScansModel.length - 1
                            }

                            Row {
                                anchors {
                                    verticalCenter: parent.verticalCenter
                                    left:           parent.left
                                    right:          parent.right
                                    rightMargin:    4
                                }
                                spacing: Theme.spacingS

                                Column {
                                    spacing:            2
                                    width:              parent.width - rescheduleBtn.width - Theme.spacingS
                                    anchors.verticalCenter: parent.verticalCenter

                                    Text {
                                        text:           modelData.name
                                        color:          Theme.textPrimary
                                        font.family:    Theme.fontFamily
                                        font.pixelSize: Theme.fontSizeBody
                                        elide:          Text.ElideRight
                                        width:          parent.width
                                    }

                                    Text {
                                        text:           modelData.scheduled
                                        color:          Theme.textMuted
                                        font.family:    Theme.fontFamily
                                        font.pixelSize: Theme.fontSizeMicro
                                    }
                                }

                                PrimaryButton {
                                    id:     rescheduleBtn
                                    text:   qsTr("Reschedule")
                                    height: 28
                                    anchors.verticalCenter: parent.verticalCenter
                                    onClicked: {
                                        if (typeof performanceViewModel !== 'undefined') {
                                            performanceViewModel.rescheduleScan(modelData.name);
                                        } else {
                                            // TODO: wire to performanceViewModel.rescheduleScan once the VM is authored.
                                            console.log("[PerformancePage] rescheduleScan requested for:", modelData.name,
                                                        "— PerformanceViewModel not yet registered.");
                                        }
                                    }

                                    FocusRing { target: rescheduleBtn }
                                    activeFocusOnTab: true
                                    Accessible.role: Accessible.Button
                                    Accessible.name: qsTr("Reschedule %1").arg(modelData.name)
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 5. Footer — EmptyState when no recent events
            // -----------------------------------------------------------------
            Loader {
                width: parent.width - Theme.spacingL * 2
                active: root.recentOptimizations.length === 0
                sourceComponent: EmptyState {
                    title:   qsTr("No recent optimizations")
                    message: qsTr("ShadowStrike has not made any performance adjustments yet.")
                }
            }

            // Bottom spacer
            Item { width: 1; height: Theme.spacingXL }
        }
    }
}
