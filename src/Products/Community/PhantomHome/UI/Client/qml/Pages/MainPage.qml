/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * MainPage.qml — Primary dashboard page.
 *
 * Sections (top → bottom):
 *   1. Hero card     — HeroShield + HeadlineTicker + 3 status chips
 *   2. Fast Scan     — FastScanTile wired to scanViewModel + scan progress bar
 *   3. Recommendations — RecommendationCard list (gates on VM availability)
 *   4. Latest threats  — ThreatRow list (top 8 from reportsModel)
 *
 * Context properties consumed (all gated with typeof guards):
 *   protectionViewModel       — ProtectionViewModel*
 *   scanViewModel             — ScanViewModel*
 *   reportsModel              — ReportsModel*
 *   recommendationsViewModel  — optional (not guaranteed to be present)
 *
 * ReportsModel role int constants (Qt.UserRole = 256):
 *   +1 Id | +2 Type | +3 Severity | +4 Title | +5 Summary |
 *   +6 Timestamp | +7 Actor | +8 DetailsJson
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Format a Unix timestamp (seconds) as a relative time string.
    function relativeTime(ts) {
        if (!ts || ts <= 0) return qsTr("unknown")
        var diff = (Date.now() / 1000) - ts
        if (diff < 60)    return qsTr("just now")
        if (diff < 3600)  return qsTr("%1m ago").arg(Math.floor(diff / 60))
        if (diff < 86400) return qsTr("%1h ago").arg(Math.floor(diff / 3600))
        return qsTr("%1d ago").arg(Math.floor(diff / 86400))
    }

    /// ProtectionViewModel.globalMode (0=Off, 1=Balanced, 2=Aggressive) → label.
    function modeName(mode) {
        switch (mode) {
        case 0:  return qsTr("Off")
        case 1:  return qsTr("Balanced")
        case 2:  return qsTr("Aggressive")
        default: return qsTr("Unknown")
        }
    }

    /// ScanViewModel.ScanState int → FastScanTile scanState string.
    /// ScanState: Idle=0 Preparing=1 Running=2 Paused=3 Completed=4 Failed=5
    function scanStateStr(st) {
        if (st === 1 || st === 2 || st === 3) return "running"
        if (st === 4 || st === 5)             return "complete"
        return "idle"
    }

    /// ScanViewModel.ScanState → StatusChip state string.
    function scanChipState(st) {
        if (st === 1 || st === 2) return "on"
        if (st === 3)             return "paused"
        if (st === 5)             return "critical"
        if (st === 4)             return "on"
        return "off"
    }

    /// ProtectionViewModel.globalMode → StatusChip state.
    function modeChipState(mode) {
        if (mode === 0) return "off"
        if (mode === 2) return "warning"
        return "on"
    }

    /// ReportsModel TypeRole string → ThreatRow action string.
    function typeToAction(t) {
        var s = (t || "").toLowerCase()
        if (s === "block")      return "blocked"
        if (s === "quarantine") return "quarantined"
        return "deleted"
    }

    // -------------------------------------------------------------------------
    // Scroll container
    // -------------------------------------------------------------------------

    ScrollView {
        id:           scroll
        anchors.fill: parent
        contentWidth: parent.width
        clip:         true

        Column {
            id:      pageColumn
            width:   scroll.width
            spacing: Theme.spacingL
            padding: Theme.spacingL

            // -----------------------------------------------------------------
            // 1. Hero card
            // -----------------------------------------------------------------
            Card {
                id:     heroCard
                width:  parent.width - Theme.spacingL * 2
                glow:   (typeof protectionViewModel !== "undefined") &&
                         protectionViewModel.headlineState === "critical"
                accent: (typeof protectionViewModel !== "undefined") &&
                         protectionViewModel.headlineState === "critical"
                         ? Theme.crit : Theme.accentCyan

                Row {
                    width:   parent.width
                    spacing: Theme.spacingL

                    HeroShield {
                        id:    heroShield
                        state: (typeof protectionViewModel !== "undefined")
                               ? protectionViewModel.headlineState : "unknown"
                        width:  148; height: 148
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Column {
                        width:   parent.width - heroShield.width - parent.spacing
                        spacing: Theme.spacingM
                        anchors.verticalCenter: parent.verticalCenter

                        HeadlineTicker {
                            width: parent.width
                            state: (typeof protectionViewModel !== "undefined")
                                   ? protectionViewModel.headlineState : "unknown"

                            primaryText: {
                                if (typeof protectionViewModel === "undefined") return ""
                                var crit = protectionViewModel.criticalCount
                                var risk = protectionViewModel.atRiskCount
                                if (crit > 0) return qsTr("%1 critical issue(s) require action.").arg(crit)
                                if (risk > 0) return qsTr("%1 module(s) need your attention.").arg(risk)
                                return ""
                            }
                            secondaryText: {
                                if (typeof protectionViewModel === "undefined") return ""
                                var crit = protectionViewModel.criticalCount
                                var risk = protectionViewModel.atRiskCount
                                if (crit > 0 && risk > 0)
                                    return qsTr("%1 module(s) at risk.").arg(risk)
                                return ""
                            }
                        }

                        // Status chip row
                        Flow {
                            width:   parent.width
                            spacing: Theme.spacingS

                            StatusChip {
                                state: (typeof protectionViewModel !== "undefined")
                                       ? root.modeChipState(protectionViewModel.globalMode) : "off"
                                label: qsTr("Protection: %1").arg(
                                           (typeof protectionViewModel !== "undefined")
                                           ? root.modeName(protectionViewModel.globalMode)
                                           : qsTr("Unknown"))
                            }

                            StatusChip {
                                state: (typeof scanViewModel !== "undefined")
                                       ? root.scanChipState(scanViewModel.state) : "off"
                                label: {
                                    if (typeof scanViewModel === "undefined")
                                        return qsTr("Scan: Unknown")
                                    var st = scanViewModel.state
                                    if (st === 1 || st === 2)
                                        return qsTr("Scanning: %1%").arg(scanViewModel.percent)
                                    if (st === 4)
                                        return qsTr("Last scan: clean")
                                    if (st === 5)
                                        return qsTr("Last scan: %1 threat(s)").arg(scanViewModel.threatsFound)
                                    return qsTr("Last scan: pending")
                                }
                            }

                            StatusChip {
                                state: {
                                    if (typeof protectionViewModel === "undefined") return "off"
                                    return protectionViewModel.criticalCount > 0 ? "critical" : "on"
                                }
                                label: {
                                    if (typeof protectionViewModel === "undefined")
                                        return qsTr("Threats blocked: —")
                                    return qsTr("Threats blocked today: %1").arg(
                                               protectionViewModel.criticalCount +
                                               protectionViewModel.atRiskCount)
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 2. Fast Scan card
            // -----------------------------------------------------------------
            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    FastScanTile {
                        id:              scanTile
                        width:           parent.width
                        scanState:       (typeof scanViewModel !== "undefined")
                                         ? root.scanStateStr(scanViewModel.state) : "idle"
                        progressPercent: (typeof scanViewModel !== "undefined")
                                         ? scanViewModel.percent : 0
                        threatsFound:    (typeof scanViewModel !== "undefined")
                                         ? scanViewModel.threatsFound : 0

                        onStartRequested: {
                            if (typeof scanViewModel !== "undefined")
                                scanViewModel.startFastScan()
                        }
                        onStopRequested: {
                            if (typeof scanViewModel !== "undefined")
                                scanViewModel.cancel()
                        }
                        onOpenResults: {
                            if (typeof stack !== "undefined")
                                Qt.callLater(stack.push, "qrc:/qml/Pages/ReportsSubroute.qml")
                        }
                    }

                    // Linear progress bar — visible while scanning (supplemental indicator)
                    Rectangle {
                        width:   parent.width
                        height:  4
                        radius:  2
                        visible: (typeof scanViewModel !== "undefined") &&
                                 (scanViewModel.state === 1 || scanViewModel.state === 2)
                        color:   Theme.strokeSubtle

                        Rectangle {
                            width: parent.width *
                                   ((typeof scanViewModel !== "undefined")
                                    ? Math.max(0, Math.min(1, scanViewModel.percent / 100.0))
                                    : 0)
                            height:  parent.height
                            radius:  parent.radius
                            gradient: Gradient {
                                orientation: Gradient.Horizontal
                                GradientStop { position: 0.0; color: Theme.accentBlue }
                                GradientStop { position: 1.0; color: Theme.accentCyan  }
                            }
                            Behavior on width {
                                enabled: !(typeof perfBudget !== "undefined" &&
                                           perfBudget !== null && perfBudget.animationsPaused)
                                NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 3. Recommendations
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Recommendations")
                width: parent.width - Theme.spacingL * 2
            }

            Loader {
                width: parent.width - Theme.spacingL * 2
                sourceComponent: (typeof recommendationsViewModel !== "undefined" &&
                                  recommendationsViewModel !== null)
                                 ? recListComponent : recEmptyComponent
            }

            Component {
                id: recListComponent
                ListView {
                    id:             recList
                    width:          parent ? parent.width : 400
                    height:         contentHeight
                    spacing:        Theme.spacingS
                    clip:           true
                    model:          (typeof recommendationsViewModel !== "undefined")
                                    ? recommendationsViewModel : null
                    boundsBehavior: Flickable.StopAtBounds
                    interactive:    false

                    // Show empty state inside the list when model has no items
                    footer: Loader {
                        width: recList.width
                        sourceComponent: (recList.count === 0) ? recInlineEmpty : null

                        Component {
                            id: recInlineEmpty
                            EmptyState {
                                width:   parent ? parent.width : 400
                                height:  80
                                title:   qsTr("All clear")
                                message: qsTr("No recommendations at this time.")
                            }
                        }
                    }

                    delegate: Item {
                        id:    recDelegateHost
                        width: recList.width
                        height: recCard.implicitHeight

                        // Cache the model id for use in signal handlers
                        // (avoids referencing 'model.id' inside the card's closures)
                        required property string displayName
                        required property string detail
                        required property string severity
                        required property string actionLabel

                        // The model may expose an 'id' role — capture via a
                        // context-local property to avoid the QML keyword clash.
                        readonly property string _recId: {
                            if (typeof model !== "undefined" && model !== null &&
                                typeof model.id !== "undefined") {
                                return model.id
                            }
                            return ""
                        }

                        RecommendationCard {
                            id:          recCard
                            width:       recDelegateHost.width
                            title:       recDelegateHost.displayName.length > 0
                                         ? recDelegateHost.displayName : qsTr("Recommendation")
                            detail:      recDelegateHost.detail
                            severity:    recDelegateHost.severity.length > 0
                                         ? recDelegateHost.severity : "info"
                            actionLabel: recDelegateHost.actionLabel.length > 0
                                         ? recDelegateHost.actionLabel : qsTr("Fix")

                            onActionClicked: {
                                if (typeof recommendationsViewModel !== "undefined" &&
                                    recDelegateHost._recId.length > 0) {
                                    recommendationsViewModel.executeAction(recDelegateHost._recId)
                                }
                            }
                            onDismissed: {
                                if (typeof recommendationsViewModel !== "undefined" &&
                                    recDelegateHost._recId.length > 0) {
                                    recommendationsViewModel.dismiss(recDelegateHost._recId)
                                }
                            }
                        }
                    }
                }
            }

            Component {
                id: recEmptyComponent
                EmptyState {
                    width:   parent ? parent.width : 400
                    height:  80
                    title:   qsTr("All clear")
                    message: qsTr("No recommendations at this time. Your device is well protected.")
                }
            }

            // -----------------------------------------------------------------
            // 4. Latest activity — top 8 from reportsModel
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Latest activity")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width: parent.width
                    spacing: 0

                    ListView {
                        id:             latestList
                        width:          parent.width
                        height:         contentHeight
                        spacing:        0
                        clip:           true
                        interactive:    false
                        boundsBehavior: Flickable.StopAtBounds
                        model:          (typeof reportsModel !== "undefined" &&
                                         reportsModel !== null)
                                         ? reportsModel : null

                        delegate: Loader {
                            id:    latestRowLoader
                            width: latestList.width

                            // Limit to 8 rows
                            required property int    index
                            required property string title
                            required property string summary
                            required property var    timestamp
                            required property string type

                            visible:         index < 8
                            height:          visible ? (item ? item.implicitHeight : 56) : 0
                            sourceComponent: index < 8 ? latestRowComp : null

                            Component {
                                id: latestRowComp
                                ThreatRow {
                                    width:            latestRowLoader.width
                                    alternate:        latestRowLoader.index % 2 === 1
                                    threatName:       latestRowLoader.title   ?? qsTr("Unknown threat")
                                    filePath:         latestRowLoader.summary ?? ""
                                    action:           root.typeToAction(latestRowLoader.type)
                                    timestampDisplay: root.relativeTime(latestRowLoader.timestamp)
                                    onRowClicked: {
                                        if (typeof stack !== "undefined")
                                            Qt.callLater(stack.push, "qrc:/qml/Pages/ReportsSubroute.qml")
                                    }
                                }
                            }
                        }

                        footer: Loader {
                            width: latestList.width
                            sourceComponent: latestList.count === 0 ? latestEmptyComp : null
                            Component {
                                id: latestEmptyComp
                                EmptyState {
                                    width:   parent ? parent.width : 400
                                    height:  80
                                    title:   qsTr("No recent activity")
                                    message: qsTr("No threats have been detected recently.")
                                }
                            }
                        }
                    }
                }
            }

            // "View all" footer row
            Row {
                width:           parent.width - Theme.spacingL * 2
                layoutDirection: Qt.RightToLeft

                GhostButton {
                    text: qsTr("View all")
                    onClicked: {
                        if (typeof stack !== "undefined")
                            Qt.callLater(stack.push, "qrc:/qml/Pages/ReportsSubroute.qml")
                    }
                }
            }

            Item { width: 1; height: Theme.spacingL }
        }
    }
}
