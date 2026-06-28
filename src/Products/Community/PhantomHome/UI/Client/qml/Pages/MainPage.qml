/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * MainPage.qml — Primary dashboard page.
 *
 * Sections (top → bottom):
 *   1. Hero card     — HeroShield + HeadlineTicker + 3 status chips
 *   2. Scans         — FastScanTile + full/custom scan actions wired to scanViewModel
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

    property string _customScanPath: ""

    readonly property bool _serviceConnected:
        (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.connected : false
    readonly property int _serviceState:
        (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.state : 0
    readonly property var _modulesModel: {
        if (typeof modulesListModel !== "undefined" && modulesListModel !== null)
            return modulesListModel
        if (typeof protectionViewModel !== "undefined" && protectionViewModel !== null &&
            typeof protectionViewModel.modules !== "undefined")
            return protectionViewModel.modules
        return null
    }
    readonly property var _moduleGroups: [
        { category: 0, title: qsTr("Realtime"), detail: qsTr("File, process, and memory shields") },
        { category: 1, title: qsTr("Behavioral"), detail: qsTr("Zero Trust and runtime behavior") },
        { category: 2, title: qsTr("Network"), detail: qsTr("Web, firewall, and lateral-movement sensors") },
        { category: 3, title: qsTr("Privacy"), detail: qsTr("Camera, microphone, location, and browser privacy") },
        { category: 4, title: qsTr("Performance"), detail: qsTr("Scan scheduling and endpoint impact controls") },
        { category: 5, title: qsTr("Threat intel"), detail: qsTr("PGTI feeds and reputation sources") },
        { category: 6, title: qsTr("Other"), detail: qsTr("Additional protection modules") }
    ]

    Connections {
        target: (typeof recommendationsViewModel !== "undefined" &&
                 recommendationsViewModel !== null)
                ? recommendationsViewModel : null
        function onNavigateToUrl(url) {
            if (typeof stack !== "undefined" && url && url.length > 0) {
                Qt.callLater(stack.push, url)
            }
        }
    }

    Connections {
        target: (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient : null
        function onStateChanged() {
            if (!root._serviceConnected)
                return
            if (typeof protectionViewModel !== "undefined" && protectionViewModel !== null)
                protectionViewModel.refresh()
            if (root._modulesModel !== null)
                root._modulesModel.refresh()
            if (typeof recommendationsViewModel !== "undefined" && recommendationsViewModel !== null)
                recommendationsViewModel.refresh()
            if (typeof pgtiViewModel !== "undefined" && pgtiViewModel !== null)
                pgtiViewModel.refreshAll()
            if (typeof privacyViewModel !== "undefined" && privacyViewModel !== null)
                privacyViewModel.refresh()
            if (typeof performanceViewModel !== "undefined" && performanceViewModel !== null)
                performanceViewModel.refresh()
        }
    }

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

    function serviceStateLabel(state) {
        switch (state) {
        case 1:  return qsTr("Connecting")
        case 2:  return qsTr("Authenticating")
        case 3:  return qsTr("Connected")
        case 4:  return qsTr("Reconnecting")
        case 5:  return qsTr("Authentication failed")
        default: return qsTr("Offline")
        }
    }

    /// ProtectionViewModel.globalMode (0=Off, 1=Passive, 2=Balanced, 3=Aggressive) -> label.
    function modeName(mode) {
        switch (mode) {
        case 0:  return qsTr("Off")
        case 1:  return qsTr("Passive")
        case 2:  return qsTr("Balanced")
        case 3:  return qsTr("Aggressive")
        default: return qsTr("Unknown")
        }
    }

    function dashboardState() {
        if (!root._serviceConnected)
            return "unknown"
        if (typeof protectionViewModel !== "undefined" && protectionViewModel !== null &&
            protectionViewModel.protectionPaused)
            return "paused"
        if (typeof protectionViewModel !== "undefined" && protectionViewModel !== null)
            return protectionViewModel.headlineState
        return "unknown"
    }

    function dashboardPrimaryHeadline() {
        if (!root._serviceConnected)
            return qsTr("ShadowStrike service is offline")
        if (typeof protectionViewModel === "undefined" || protectionViewModel === null)
            return qsTr("Protection telemetry is loading")
        if (protectionViewModel.protectionPaused)
            return qsTr("Protection is paused")
        var crit = protectionViewModel.criticalCount
        var risk = protectionViewModel.atRiskCount
        if (crit > 0) return qsTr("%1 critical issue(s) require action.").arg(crit)
        if (risk > 0) return qsTr("%1 module(s) need your attention.").arg(risk)
        return qsTr("Your device is protected")
    }

    function dashboardSecondaryHeadline() {
        if (!root._serviceConnected)
            return qsTr("Live protection state will refresh when the service reconnects.")
        var modules = root._moduleCount()
        var unhealthy = root._moduleCountByHealth(1) + root._moduleCountByHealth(2)
        if (modules === 0)
            return qsTr("Waiting for protection modules to report sensor health.")
        if (unhealthy > 0)
            return qsTr("%1 of %2 sensor(s) require review.").arg(unhealthy).arg(modules)
        return qsTr("%1 protection sensor(s) are reporting healthy state.").arg(modules)
    }

    function moduleRole(row, offset) {
        if (root._modulesModel === null) return undefined
        return root._modulesModel.data(root._modulesModel.index(row, 0), Qt.UserRole + offset)
    }

    function _moduleCount() {
        return root._modulesModel === null ? 0 : root._modulesModel.rowCount()
    }

    function _moduleCountByHealth(health) {
        if (root._modulesModel === null) return 0
        var total = 0
        for (var i = 0; i < root._modulesModel.rowCount(); ++i) {
            if ((root.moduleRole(i, 8) ?? -1) === health)
                total++
        }
        return total
    }

    function _moduleCountByMode(mode) {
        if (root._modulesModel === null) return 0
        var total = 0
        for (var i = 0; i < root._modulesModel.rowCount(); ++i) {
            if ((root.moduleRole(i, 5) ?? 0) === mode)
                total++
        }
        return total
    }

    function _categoryMatches(moduleCategory, groupCategory) {
        if (groupCategory === 6)
            return moduleCategory < 0 || moduleCategory > 5
        return moduleCategory === groupCategory
    }

    function _moduleCountByCategory(groupCategory) {
        if (root._modulesModel === null) return 0
        var total = 0
        for (var i = 0; i < root._modulesModel.rowCount(); ++i) {
            var category = root.moduleRole(i, 4) ?? -1
            if (root._categoryMatches(category, groupCategory))
                total++
        }
        return total
    }

    function _moduleIssuesByCategory(groupCategory) {
        if (root._modulesModel === null) return 0
        var total = 0
        for (var i = 0; i < root._modulesModel.rowCount(); ++i) {
            var category = root.moduleRole(i, 4) ?? -1
            var health = root.moduleRole(i, 8) ?? -1
            if (root._categoryMatches(category, groupCategory) && (health === 1 || health === 2))
                total++
        }
        return total
    }

    function _categoryState(groupCategory) {
        if (!root._serviceConnected) return "offline"
        var count = root._moduleCountByCategory(groupCategory)
        if (count === 0) return "loading"
        var issues = root._moduleIssuesByCategory(groupCategory)
        if (issues > 0) return "warning"
        return "on"
    }

    function _feedCount() {
        if (typeof pgtiViewModel === "undefined" || pgtiViewModel === null || typeof pgtiViewModel.feeds === "undefined" || pgtiViewModel.feeds === null)
            return 0
        return pgtiViewModel.feeds.rowCount()
    }

    function _feedIssueCount() {
        if (typeof pgtiViewModel === "undefined" || pgtiViewModel === null || typeof pgtiViewModel.feeds === "undefined" || pgtiViewModel.feeds === null)
            return 0
        var issues = 0
        for (var i = 0; i < pgtiViewModel.feeds.rowCount(); ++i) {
            var health = (pgtiViewModel.feeds.data(pgtiViewModel.feeds.index(i, 0), Qt.UserRole + 3) || "").toLowerCase()
            var enabled = pgtiViewModel.feeds.data(pgtiViewModel.feeds.index(i, 0), Qt.UserRole + 7)
            if (enabled && health !== "healthy")
                issues++
        }
        return issues
    }

    function _privacyBlockedTotal() {
        if (typeof privacyViewModel === "undefined" || privacyViewModel === null)
            return 0
        return privacyViewModel.webcamAccessBlocked + privacyViewModel.micAccessBlocked +
               privacyViewModel.locationAccessBlocked + privacyViewModel.cookiesBlocked
    }

    function _performancePlanName(plan) {
        switch (plan) {
        case 0:  return qsTr("Balanced")
        case 1:  return qsTr("Performance")
        case 2:  return qsTr("Battery saver")
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

    function scanIsActive(st) {
        return st === 1 || st === 2 || st === 3
    }

    /// ProtectionViewModel.globalMode → StatusChip state.
    function modeChipState(mode) {
        if (mode === 0) return "off"
        if (mode === 1 || mode === 3) return "warning"
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
                glow:   root.dashboardState() === "critical"
                accent: root.dashboardState() === "critical" ? Theme.crit : Theme.accentCyan

                Row {
                    width:   parent.width
                    spacing: Theme.spacingL

                    HeroShield {
                        id:    heroShield
                        state: root.dashboardState()
                        width:  148; height: 148
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Column {
                        width:   parent.width - heroShield.width - parent.spacing
                        spacing: Theme.spacingM
                        anchors.verticalCenter: parent.verticalCenter

                        HeadlineTicker {
                            width: parent.width
                            state: root.dashboardState()
                            primaryText: root.dashboardPrimaryHeadline()
                            secondaryText: root.dashboardSecondaryHeadline()
                        }

                        // Status chip row
                        Flow {
                            width:   parent.width
                            spacing: Theme.spacingS

                            StatusChip {
                                state: root._serviceConnected
                                       ? ((typeof protectionViewModel !== "undefined" && protectionViewModel !== null &&
                                           protectionViewModel.protectionPaused) ? "paused" :
                                          ((typeof protectionViewModel !== "undefined" && protectionViewModel !== null)
                                           ? root.modeChipState(protectionViewModel.globalMode) : "loading"))
                                       : "offline"
                                label: qsTr("Protection: %1").arg(
                                           root._serviceConnected && typeof protectionViewModel !== "undefined" &&
                                           protectionViewModel !== null
                                           ? root.modeName(protectionViewModel.globalMode)
                                           : root.serviceStateLabel(root._serviceState))
                            }

                            StatusChip {
                                state: root._serviceConnected
                                       ? ((root._moduleCountByHealth(2) > 0) ? "critical" :
                                          ((root._moduleCountByHealth(1) > 0) ? "warning" :
                                           (root._moduleCount() > 0 ? "on" : "loading")))
                                       : "offline"
                                label: qsTr("Sensors: %1 healthy / %2 total").arg(root._moduleCountByHealth(0)).arg(root._moduleCount())
                            }

                            StatusChip {
                                state: {
                                    if (!root._serviceConnected) return "offline"
                                    if (typeof reportsModel !== "undefined" && reportsModel !== null && reportsModel.loading)
                                        return "loading"
                                    if (typeof protectionViewModel === "undefined" || protectionViewModel === null)
                                        return "loading"
                                    return protectionViewModel.criticalCount > 0 ? "critical" :
                                           (protectionViewModel.atRiskCount > 0 ? "warning" : "on")
                                }
                                label: {
                                    if (typeof protectionViewModel === "undefined" || protectionViewModel === null)
                                        return qsTr("Alerts: loading")
                                    return qsTr("Open alerts: %1").arg(protectionViewModel.criticalCount +
                                                                      protectionViewModel.atRiskCount)
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 2. Service and sensor health
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Service & sensor health")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2

                Flow {
                    width:   parent.width
                    spacing: Theme.spacingS

                    StatusChip {
                        state: root._serviceConnected ? "on" : "offline"
                        label: qsTr("Service: %1").arg(root.serviceStateLabel(root._serviceState))
                    }

                    StatusChip {
                        state: root._moduleCount() > 0 ? "on" : (root._serviceConnected ? "loading" : "offline")
                        label: qsTr("Modules: %1 loaded").arg(root._moduleCount())
                    }

                    StatusChip {
                        // Disabled/off sensors = those reporting health "off" (-1):
                        // Disabled or Stopped module states (e.g. modules turned off
                        // by config such as the IoT and Backup groups). The previous
                        // _moduleCountByMode(0) counted protection-mode==0, which every
                        // module reports, so it always showed the full module total.
                        state: root._moduleCount() > 0 ? "on" : (root._serviceConnected ? "loading" : "offline")
                        label: qsTr("Disabled: %1").arg(root._moduleCountByHealth(-1))
                    }

                    StatusChip {
                        state: root._privacyBlockedTotal() > 0 ? "warning" : "on"
                        label: qsTr("Privacy blocks: %1").arg(root._privacyBlockedTotal())
                    }

                    StatusChip {
                        state: root._feedIssueCount() > 0 ? "warning" : (root._feedCount() > 0 ? "on" : "loading")
                        label: qsTr("PGTI feeds: %1").arg(root._feedCount())
                    }

                    StatusChip {
                        state: (typeof performanceViewModel !== "undefined" && performanceViewModel !== null &&
                                performanceViewModel.loading) ? "loading" : "info"
                        label: qsTr("Performance: %1").arg(
                                   (typeof performanceViewModel !== "undefined" && performanceViewModel !== null)
                                   ? root._performancePlanName(performanceViewModel.currentPowerPlan)
                                   : qsTr("Unknown"))
                    }
                }
            }

            // -----------------------------------------------------------------
            // 3. Protection groups
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Protection groups")
                width: parent.width - Theme.spacingL * 2
            }

            Flow {
                id:      groupFlow
                width:   parent.width - Theme.spacingL * 2
                spacing: Theme.spacingM

                Repeater {
                    model: root._moduleGroups
                    delegate: Card {
                        required property var modelData

                        readonly property int groupCount: root._moduleCountByCategory(modelData.category)
                        readonly property int groupIssues: root._moduleIssuesByCategory(modelData.category)

                        width: Math.max(260, groupFlow.width >= 860
                                   ? Math.floor((groupFlow.width - Theme.spacingM * 2) / 3)
                                   : Math.floor((groupFlow.width - Theme.spacingM) / 2))
                        visible: groupCount > 0 || !root._serviceConnected
                        height: visible ? implicitHeight : 0
                        interactive: true
                        accessibleName: modelData.title

                        Column {
                            width:   parent.width
                            spacing: Theme.spacingS

                            Row {
                                width: parent.width
                                spacing: Theme.spacingS

                                Text {
                                    width: parent.width - groupChip.width - parent.spacing
                                    text:  modelData.title
                                    color: Theme.textPrimary
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSizeBody
                                    font.weight: Theme.fontWeightBold
                                    elide: Text.ElideRight
                                    anchors.verticalCenter: parent.verticalCenter
                                }

                                StatusChip {
                                    id: groupChip
                                    state: root._categoryState(modelData.category)
                                    label: groupIssues > 0 ? qsTr("%1 issue(s)").arg(groupIssues)
                                                           : qsTr("%1 sensor(s)").arg(groupCount)
                                    anchors.verticalCenter: parent.verticalCenter
                                }
                            }

                            Text {
                                width: parent.width
                                text:  modelData.detail
                                color: Theme.textSecondary
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSizeLabel
                                wrapMode: Text.WordWrap
                                maximumLineCount: 2
                                elide: Text.ElideRight
                            }
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                if (typeof stack !== "undefined")
                                    Qt.callLater(stack.push, "qrc:/qml/Pages/SecurityPage.qml")
                            }
                        }
                    }
                }

                Loader {
                    width: groupFlow.width
                    sourceComponent: (!root._serviceConnected || root._moduleCount() === 0) ? groupStateComp : null

                    Component {
                        id: groupStateComp
                        EmptyState {
                            width:   parent ? parent.width : 400
                            height:  96
                            variant: root._serviceConnected ? "loading" : "offline"
                            title:   root._serviceConnected ? qsTr("Loading protection modules")
                                                            : qsTr("Service offline")
                            message: root._serviceConnected ? qsTr("Waiting for live sensor state from the service.")
                                                            : qsTr("Module health will refresh when ShadowStrike service reconnects.")
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 4. Fast Scan card
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
                                 root.scanIsActive(scanViewModel.state)
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

                    Column {
                        width:   parent.width
                        spacing: Theme.spacingXS
                        visible: (typeof scanViewModel !== "undefined") &&
                                 root.scanIsActive(scanViewModel.state)

                        Text {
                            text:           qsTr("%1 item(s) scanned, %2 threat(s) found")
                                            .arg(scanViewModel.itemsScanned)
                                            .arg(scanViewModel.threatsFound)
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                        }

                        Text {
                            visible:        scanViewModel.currentPath.length > 0
                            text:           qsTr("Current: %1").arg(scanViewModel.currentPath)
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeMicro
                            elide:          Text.ElideMiddle
                            width:          parent.width
                        }
                    }

                    Row {
                        spacing: Theme.spacingS

                        GhostButton {
                            id:      fullScanButton
                            text:    qsTr("Full Scan")
                            enabled: typeof scanViewModel !== "undefined" &&
                                     !root.scanIsActive(scanViewModel.state)
                            onClicked: {
                                if (typeof scanViewModel !== "undefined")
                                    scanViewModel.startFullScan()
                            }
                        }

                        TextField {
                            id:              customScanPathField
                            width:           Math.max(220, scanTile.width - fullScanButton.implicitWidth -
                                                      customScanButton.implicitWidth - Theme.spacingS * 3)
                            height:          32
                            placeholderText: qsTr("Custom scan path")
                            text:            root._customScanPath
                            enabled:         typeof scanViewModel !== "undefined" &&
                                             !root.scanIsActive(scanViewModel.state)
                            selectByMouse:   true
                            onTextChanged:   root._customScanPath = text

                            background: Rectangle {
                                radius:       Theme.radiusMedium
                                color:        Theme.bgSurface
                                border.color: customScanPathField.activeFocus
                                              ? Theme.accentCyan : Theme.strokeSubtle
                                border.width: customScanPathField.activeFocus ? 2 : 1
                            }
                        }

                        GhostButton {
                            id:      customScanButton
                            text:    qsTr("Custom Scan")
                            enabled: typeof scanViewModel !== "undefined" &&
                                     !root.scanIsActive(scanViewModel.state) &&
                                     root._customScanPath.trim().length > 0
                            onClicked: {
                                if (typeof scanViewModel !== "undefined") {
                                    var path = root._customScanPath.trim()
                                    if (path.length > 0)
                                        scanViewModel.startCustomScan([path])
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 5. Recommendations
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Recommendations")
                width: parent.width - Theme.spacingL * 2
            }

            Loader {
                width: parent.width - Theme.spacingL * 2
                sourceComponent: {
                    if (!root._serviceConnected)
                        return recUnavailableComponent
                    if (typeof recommendationsViewModel === "undefined" || recommendationsViewModel === null)
                        return recUnavailableComponent
                    if (recommendationsViewModel.loading && recommendationsViewModel.rowCount() === 0)
                        return recLoadingComponent
                    return recListComponent
                }
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
                        sourceComponent: (recList.count === 0 &&
                                          typeof recommendationsViewModel !== "undefined" &&
                                          recommendationsViewModel !== null &&
                                          !recommendationsViewModel.loading) ? recInlineEmpty : null

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
                        required property bool   dismissible

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
                            dismissible: recDelegateHost.dismissible

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
                id: recLoadingComponent
                EmptyState {
                    width:   parent ? parent.width : 400
                    height:  96
                    variant: "loading"
                    title:   qsTr("Loading recommendations")
                    message: qsTr("Retrieving live hardening guidance from the service.")
                }
            }

            Component {
                id: recUnavailableComponent
                EmptyState {
                    width:   parent ? parent.width : 400
                    height:  96
                    variant: "offline"
                    title:   qsTr("Recommendations unavailable")
                    message: qsTr("Hardening recommendations will refresh when ShadowStrike service reconnects.")
                }
            }

            // -----------------------------------------------------------------
            // 6. Latest activity — top 8 from reportsModel
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
                            height:          visible ? (implicitHeight > 0 ? implicitHeight : 56) : 0
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
                            sourceComponent: {
                                if (!root._serviceConnected)
                                    return latestUnavailableComp
                                if (typeof reportsModel !== "undefined" && reportsModel !== null &&
                                    reportsModel.loading && latestList.count === 0)
                                    return latestLoadingComp
                                return latestList.count === 0 ? latestEmptyComp : null
                            }
                            Component {
                                id: latestEmptyComp
                                EmptyState {
                                    width:   parent ? parent.width : 400
                                    height:  80
                                    title:   qsTr("No recent activity")
                                    message: qsTr("No threats have been detected recently.")
                                }
                            }

                            Component {
                                id: latestLoadingComp
                                EmptyState {
                                    width:   parent ? parent.width : 400
                                    height:  80
                                    variant: "loading"
                                    title:   qsTr("Loading activity")
                                    message: qsTr("Retrieving the latest protection events.")
                                }
                            }

                            Component {
                                id: latestUnavailableComp
                                EmptyState {
                                    width:   parent ? parent.width : 400
                                    height:  80
                                    variant: "offline"
                                    title:   qsTr("Activity unavailable")
                                    message: qsTr("Live alerts require a connection to the ShadowStrike service.")
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
