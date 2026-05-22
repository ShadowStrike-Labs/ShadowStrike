/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SecurityPage.qml — Main protection configuration page.
 *
 * Layout:
 *   TopBar with Quarantine + PGTI navigation buttons
 *   Basic section:
 *     ModePillRow — global protection mode (Off/Passive/Balanced/Aggressive)
 *     Pause controls — duration selector popup
 *     Up to 5 priority ModuleCards (categories 0–2: Realtime, Behavioral, Network)
 *   Advanced section (collapsible, default collapsed):
 *     SearchBar filtering by displayName (client-side)
 *     Responsive Flow (1/2/3 col) of ModuleCards for all modules
 *
 * ModulesListModel role integers (Qt.UserRole = 256):
 *   +1  Id          | +2 DisplayName   | +3 IconId
 *   +4  Category    | +5 CurrentMode   | +6 SupportedModesMask
 *   +7  DetailPage  | +8 StatusHealth  | +9 StatusDetail  | +10 Binary
 *
 * ProtectionViewModel.globalMode: 0=Off, 1=Passive, 2=Balanced, 3=Aggressive
 * ModePillRow index:              0=Off, 1=Passive,  2=Balanced, 3=Aggressive
 *
 * Context properties consumed (gated):
 *   protectionViewModel — ProtectionViewModel*
 *   modulesListModel    — ModulesListModel* (also accessible via protectionViewModel.modules)
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

    property string _searchText:       ""
    property bool   _advancedExpanded: false
    property bool   _pauseMenuOpen:    false

    readonly property bool _serviceConnected:
        (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.connected : false
    readonly property int _serviceState:
        (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.state : 0
    readonly property var _moduleGroups: [
        { category: 0, title: qsTr("Realtime protection"), detail: qsTr("File, process, and memory shields") },
        { category: 1, title: qsTr("Behavioral protection"), detail: qsTr("Zero Trust and runtime behavior sensors") },
        { category: 2, title: qsTr("Network protection"), detail: qsTr("Web, firewall, and lateral-movement controls") },
        { category: 3, title: qsTr("Privacy protection"), detail: qsTr("Camera, microphone, location, and browser privacy sensors") },
        { category: 4, title: qsTr("Performance guardrails"), detail: qsTr("Endpoint impact, scan cadence, and battery-aware controls") },
        { category: 5, title: qsTr("Threat intelligence"), detail: qsTr("PGTI feeds, reputation, and IOC enrichment") },
        { category: 6, title: qsTr("Additional modules"), detail: qsTr("Other service-reported protection modules") }
    ]

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Resolve modulesListModel from either direct context property or VM.
    readonly property var _modulesModel: {
        if (typeof modulesListModel !== "undefined" && modulesListModel !== null)
            return modulesListModel
        if (typeof protectionViewModel !== "undefined" &&
            protectionViewModel !== null &&
            typeof protectionViewModel.modules !== "undefined")
            return protectionViewModel.modules
        return null
    }

    /// StatusHealthRole int → ModuleCard state string.
    /// Conventional health values: 0=OK, 1=Warning, 2=Critical, -1=Off/Unknown
    function _healthToState(h) {
        switch (h) {
        case 0:  return "on"
        case 1:  return "warning"
        case 2:  return "critical"
        default: return "off"
        }
    }

    /// ProtectionViewModel globalMode and ModePillRow both use ProtectionMode:
    /// 0=Off, 1=Passive, 2=Balanced, 3=Aggressive.
    function _vmModeToUiMode(mode) {
        return (mode >= 0 && mode <= 3) ? mode : 0
    }
    /// Reverse mapping: ModePillRow index → ProtectionViewModel globalMode.
    function _uiModeToVmMode(uiMode) {
        return (uiMode >= 0 && uiMode <= 3) ? uiMode : 0
    }

    function _serviceStateLabel(state) {
        switch (state) {
        case 1:  return qsTr("Connecting")
        case 2:  return qsTr("Authenticating")
        case 3:  return qsTr("Connected")
        case 4:  return qsTr("Reconnecting")
        case 5:  return qsTr("Authentication failed")
        default: return qsTr("Offline")
        }
    }

    /// Read-only model role accessor (convenience wrapper).
    function _role(row, offset) {
        if (root._modulesModel === null) return undefined
        return root._modulesModel.data(root._modulesModel.index(row, 0), Qt.UserRole + offset)
    }

    function _moduleCount() {
        return root._modulesModel === null ? 0 : root._modulesModel.rowCount()
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
            var category = root._role(i, 4) ?? -1
            if (root._categoryMatches(category, groupCategory))
                total++
        }
        return total
    }

    function _moduleIssuesByCategory(groupCategory) {
        if (root._modulesModel === null) return 0
        var total = 0
        for (var i = 0; i < root._modulesModel.rowCount(); ++i) {
            var category = root._role(i, 4) ?? -1
            var health = root._role(i, 8) ?? -1
            if (root._categoryMatches(category, groupCategory) && (health === 1 || health === 2))
                total++
        }
        return total
    }

    function _groupState(groupCategory) {
        if (!root._serviceConnected) return "offline"
        var issues = root._moduleIssuesByCategory(groupCategory)
        if (issues > 0) return "warning"
        return root._moduleCountByCategory(groupCategory) > 0 ? "on" : "loading"
    }

    function _safeDetailPage(moduleId, detailPage) {
        if (moduleId === "ZeroTrustGuard")
            return "ZeroTrustDetailPage.qml"

        var allowed = {
            "ModuleDetailPage.qml": true,
            "ZeroTrustDetailPage.qml": true,
            "PgtiDetailPage.qml": true,
            "PrivacyPage.qml": true,
            "PerformancePage.qml": true
        }
        if (detailPage && allowed[detailPage])
            return detailPage
        return "ModuleDetailPage.qml"
    }

    function _openModuleDetail(moduleId, detailPage) {
        if (typeof stack === "undefined" || stack === null || moduleId.length === 0)
            return

        var page = root._safeDetailPage(moduleId, detailPage)
        if (typeof stack.openModuleDetail === "function") {
            Qt.callLater(function() { stack.openModuleDetail(moduleId, page) })
        } else {
            Qt.callLater(stack.push, "qrc:/qml/Pages/" + page)
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
        }
    }

    // -------------------------------------------------------------------------
    // Pause duration options
    // -------------------------------------------------------------------------

    readonly property var _pauseOptions: [
        { label: qsTr("15 minutes"),    minutes: 15 },
        { label: qsTr("30 minutes"),    minutes: 30 },
        { label: qsTr("1 hour"),        minutes: 60 },
        { label: qsTr("Until restart"), minutes: 0  },
    ]

    // -------------------------------------------------------------------------
    // Layout
    // -------------------------------------------------------------------------

    Column {
        id:      pageColumn
        anchors.fill: parent
        spacing: 0

        // TopBar — Quarantine + PGTI quick-nav buttons injected as actions
        TopBar {
            id:        topBar
            pageTitle: qsTr("Security")
            showBack:  false
            width:     parent.width

            GhostButton {
                text: qsTr("Quarantine")
                onClicked: {
                    if (typeof stack !== "undefined")
                        Qt.callLater(stack.push, "qrc:/qml/Pages/QuarantineSubroute.qml")
                }
            }

            GhostButton {
                text: qsTr("PGTI Feeds")
                onClicked: {
                    if (typeof stack !== "undefined")
                        Qt.callLater(stack.push, "qrc:/qml/Pages/PgtiDetailPage.qml")
                }
            }
        }

        // Scrollable body
        ScrollView {
            id:           scroll
            width:        parent.width
            height:       parent.height - topBar.implicitHeight
            contentWidth: parent.width
            clip:         true

            Column {
                id:      bodyColumn
                width:   scroll.width
                spacing: Theme.spacingL
                padding: Theme.spacingL

                // -------------------------------------------------------------
                // Global mode + pause controls card
                // -------------------------------------------------------------
                SectionTitle {
                    text:  qsTr("Protection mode")
                    width: parent.width - Theme.spacingL * 2
                }

                Card {
                    width: parent.width - Theme.spacingL * 2

                    Column {
                        width:   parent.width
                        spacing: Theme.spacingM

                        Text {
                            text:           qsTr("Global protection level")
                            color:          Theme.textPrimary
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeBody
                            font.weight:    Theme.fontWeightMedium
                        }

                        Flow {
                            width:   parent.width
                            spacing: Theme.spacingS

                            StatusChip {
                                state: root._serviceConnected ? "on" : "offline"
                                label: qsTr("Service: %1").arg(root._serviceStateLabel(root._serviceState))
                            }

                            StatusChip {
                                state: {
                                    if (!root._serviceConnected) return "offline"
                                    if (typeof protectionViewModel === "undefined" || protectionViewModel === null)
                                        return "loading"
                                    if (protectionViewModel.protectionPaused)
                                        return "paused"
                                    return protectionViewModel.globalMode === 0 ? "off" : "on"
                                }
                                label: qsTr("Global mode: %1").arg(
                                           (root._serviceConnected && typeof protectionViewModel !== "undefined" &&
                                            protectionViewModel !== null)
                                           ? root._vmModeToUiMode(protectionViewModel.globalMode) === 0 ? qsTr("Off") :
                                             root._vmModeToUiMode(protectionViewModel.globalMode) === 1 ? qsTr("Passive") :
                                             root._vmModeToUiMode(protectionViewModel.globalMode) === 2 ? qsTr("Balanced") : qsTr("Aggressive")
                                           : qsTr("Unavailable"))
                            }

                            StatusChip {
                                state: {
                                    if (!root._serviceConnected) return "offline"
                                    if (typeof protectionViewModel === "undefined" || protectionViewModel === null)
                                        return "loading"
                                    return protectionViewModel.criticalCount > 0 ? "critical" :
                                           (protectionViewModel.atRiskCount > 0 ? "warning" : "on")
                                }
                                label: qsTr("Open alerts: %1").arg(
                                           (typeof protectionViewModel !== "undefined" && protectionViewModel !== null)
                                           ? protectionViewModel.criticalCount + protectionViewModel.atRiskCount : 0)
                            }
                        }

                        // Global mode pill row
                        // Off=bit0, Passive=bit1, Balanced=bit2, Aggressive=bit3.
                        ModePillRow {
                            id:                 globalModePills
                            supportedModesMask: 0b1111
                            currentMode:        (root._serviceConnected && typeof protectionViewModel !== "undefined" &&
                                                protectionViewModel !== null)
                                                ? root._vmModeToUiMode(protectionViewModel.globalMode) : 0
                            enabled:            root._serviceConnected && typeof protectionViewModel !== "undefined" &&
                                                protectionViewModel !== null
                            opacity:            enabled ? 1.0 : 0.55
                            onModeChosen: (m) => {
                                if (root._serviceConnected && typeof protectionViewModel !== "undefined" &&
                                    protectionViewModel !== null)
                                    protectionViewModel.setGlobalMode(root._uiModeToVmMode(m))
                            }
                        }

                        // Pause / resume row (visible only when protection is on)
                        Item {
                            width:  parent.width
                            height: pauseRow.implicitHeight
                            visible: root._serviceConnected && typeof protectionViewModel !== "undefined" &&
                                     protectionViewModel !== null && protectionViewModel.globalMode > 0

                            Row {
                                id:      pauseRow
                                spacing: Theme.spacingS

                                PrimaryButton {
                                    text: (typeof protectionViewModel !== "undefined" &&
                                           protectionViewModel.protectionPaused)
                                          ? qsTr("Resume protection")
                                          : qsTr("Pause protection ▾")
                                    onClicked: {
                                        if (typeof protectionViewModel === "undefined") return
                                        if (protectionViewModel.protectionPaused) {
                                            protectionViewModel.resumeProtection()
                                        } else {
                                            root._pauseMenuOpen = !root._pauseMenuOpen
                                        }
                                    }
                                }
                            }

                            // Pause duration popup panel
                            Rectangle {
                                visible:      root._pauseMenuOpen
                                anchors.top:  pauseRow.bottom
                                anchors.topMargin: Theme.spacingXS
                                width:        180
                                height:       pauseOptCol.implicitHeight + Theme.spacingM * 2
                                radius:       Theme.radiusMedium
                                color:        Theme.bgSurfaceAlt
                                border.color: Theme.strokeSubtle
                                border.width: 1
                                z:            10

                                Column {
                                    id:      pauseOptCol
                                    anchors.margins: Theme.spacingM
                                    anchors.fill:    parent
                                    spacing: Theme.spacingXS

                                    Repeater {
                                        model: root._pauseOptions
                                        delegate: Item {
                                            required property var modelData
                                            width:  pauseOptCol.width
                                            height: 32

                                            Rectangle {
                                                anchors.fill: parent
                                                radius:       Theme.radiusSmall
                                                color:        optMa.containsMouse
                                                              ? Theme.bgSurface : "transparent"
                                                Behavior on color {
                                                    ColorAnimation { duration: Theme.motionFast }
                                                }
                                            }

                                            Text {
                                                anchors.left:       parent.left
                                                anchors.leftMargin: Theme.spacingS
                                                anchors.verticalCenter: parent.verticalCenter
                                                text:           modelData.label
                                                color:          Theme.textPrimary
                                                font.family:    Theme.fontFamily
                                                font.pixelSize: Theme.fontSizeBody
                                            }

                                            MouseArea {
                                                id:           optMa
                                                anchors.fill: parent
                                                hoverEnabled: true
                                                onClicked: {
                                                    root._pauseMenuOpen = false
                                                    if (typeof protectionViewModel !== "undefined")
                                                        protectionViewModel.pauseProtection(modelData.minutes)
                                                }
                                            }

                                            Accessible.role:        Accessible.MenuItem
                                            Accessible.name:        modelData.label
                                            Accessible.description: qsTr("Pause protection for %1").arg(modelData.label)
                                        }
                                    }
                                }
                            }

                            // Backdrop to close the popup on outside click
                            MouseArea {
                                anchors.fill: parent
                                visible:      root._pauseMenuOpen
                                z:            9
                                onClicked:    root._pauseMenuOpen = false
                            }
                        }
                    }
                }

                // -------------------------------------------------------------
                // Grouped module cards — live service-reported protection state
                // -------------------------------------------------------------
                SectionTitle {
                    text:  qsTr("Protection modules")
                    width: parent.width - Theme.spacingL * 2
                    subtitle: root._serviceConnected
                              ? qsTr("%1 module(s) reporting live state").arg(root._moduleCount())
                              : qsTr("Waiting for the ShadowStrike service connection")
                }

                Loader {
                    width: parent.width - Theme.spacingL * 2
                    sourceComponent: {
                        if (!root._serviceConnected || root._modulesModel === null)
                            return modulesOfflineComp
                        if (root._moduleCount() === 0)
                            return modulesLoadingComp
                        return groupedModulesComp
                    }
                }

                Component {
                    id: modulesOfflineComp
                    EmptyState {
                        width:   parent ? parent.width : 400
                        height:  112
                        variant: "offline"
                        title:   qsTr("Protection service unavailable")
                        message: qsTr("Global and per-module controls will become active when ShadowStrike service reconnects.")
                    }
                }

                Component {
                    id: modulesLoadingComp
                    EmptyState {
                        width:   parent ? parent.width : 400
                        height:  112
                        variant: "loading"
                        title:   qsTr("Loading protection modules")
                        message: qsTr("Waiting for sensor health and module mode state from the service.")
                    }
                }

                Component {
                    id: groupedModulesComp
                    Column {
                        width:   parent ? parent.width : 400
                        spacing: Theme.spacingM

                        Repeater {
                            model: root._moduleGroups
                            delegate: Column {
                                id: groupDelegate
                                required property var modelData

                                readonly property int groupCount: root._moduleCountByCategory(modelData.category)
                                readonly property int issueCount: root._moduleIssuesByCategory(modelData.category)

                                width:   parent.width
                                spacing: Theme.spacingS
                                visible: groupCount > 0
                                height:  visible ? implicitHeight : 0

                                Row {
                                    width: parent.width
                                    spacing: Theme.spacingS

                                    Column {
                                        width: parent.width - groupStatus.width - parent.spacing
                                        spacing: Theme.spacingXS

                                        Text {
                                            width: parent.width
                                            text:  groupDelegate.modelData.title
                                            color: Theme.textPrimary
                                            font.family: Theme.fontFamily
                                            font.pixelSize: Theme.fontSizeTitle
                                            font.weight: Theme.fontWeightBold
                                            elide: Text.ElideRight
                                        }

                                        Text {
                                            width: parent.width
                                            text:  groupDelegate.modelData.detail
                                            color: Theme.textSecondary
                                            font.family: Theme.fontFamily
                                            font.pixelSize: Theme.fontSizeLabel
                                            wrapMode: Text.WordWrap
                                            maximumLineCount: 2
                                            elide: Text.ElideRight
                                        }
                                    }

                                    StatusChip {
                                        id: groupStatus
                                        state: root._groupState(groupDelegate.modelData.category)
                                        label: groupDelegate.issueCount > 0
                                               ? qsTr("%1 issue(s)").arg(groupDelegate.issueCount)
                                               : qsTr("%1 module(s)").arg(groupDelegate.groupCount)
                                        anchors.verticalCenter: parent.verticalCenter
                                    }
                                }

                                Flow {
                                    width:   parent.width
                                    spacing: Theme.spacingM

                                    Repeater {
                                        model: root._modulesModel
                                        delegate: Item {
                                            id: moduleSlot
                                            required property int    index
                                            required property string displayName
                                            required property int    category
                                            required property int    currentMode
                                            required property int    supportedModesMask
                                            required property int    statusHealth
                                            required property string statusDetail
                                            required property string detailPage
                                            required property string iconId

                                            readonly property bool _matchesGroup:
                                                root._categoryMatches(category, groupDelegate.modelData.category)
                                            readonly property string _moduleId: root._role(index, 1) ?? ""
                                            readonly property int _colWidth: {
                                                if (parent.width >= 900)
                                                    return Math.floor((parent.width - Theme.spacingM * 2) / 3)
                                                if (parent.width >= 580)
                                                    return Math.floor((parent.width - Theme.spacingM) / 2)
                                                return parent.width
                                            }

                                            width:   _matchesGroup ? _colWidth : 0
                                            height:  _matchesGroup ? moduleCard.implicitHeight : 0
                                            visible: _matchesGroup

                                            ModuleCard {
                                                id:                 moduleCard
                                                width:              parent.width
                                                moduleName:         moduleSlot._moduleId
                                                displayName:        moduleSlot.displayName
                                                iconSource:         "qrc:/icons/" + moduleSlot.iconId + ".svg"
                                                state:              root._healthToState(moduleSlot.statusHealth)
                                                enabled:            moduleSlot.currentMode > 0
                                                currentMode:        moduleSlot.currentMode
                                                supportedModesMask: moduleSlot.supportedModesMask
                                                description:        moduleSlot.statusDetail

                                                onToggled: (v) => {
                                                    if (root._serviceConnected && root._modulesModel !== null &&
                                                        moduleSlot._moduleId.length > 0)
                                                        root._modulesModel.toggleBinaryModule(moduleSlot._moduleId, v)
                                                }
                                                onModeChosen: (m) => {
                                                    if (root._serviceConnected && root._modulesModel !== null &&
                                                        moduleSlot._moduleId.length > 0)
                                                        root._modulesModel.setModuleMode(moduleSlot._moduleId, m)
                                                }
                                                onOpenDetail: root._openModuleDetail(moduleSlot._moduleId,
                                                                                    moduleSlot.detailPage)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // -------------------------------------------------------------
                // Advanced — collapsible section
                // -------------------------------------------------------------
                Item {
                    width:  parent.width - Theme.spacingL * 2
                    height: advHeader.implicitHeight + Theme.spacingS

                    Row {
                        id:      advHeader
                        spacing: Theme.spacingS

                        Text {
                            text:           qsTr("Search all modules")
                            color:          Theme.textPrimary
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeTitle
                            font.weight:    Theme.fontWeightBold
                            anchors.verticalCenter: parent.verticalCenter
                        }

                        Text {
                            text:           root._advancedExpanded ? "▲" : "▼"
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape:  Qt.PointingHandCursor
                        onClicked:    root._advancedExpanded = !root._advancedExpanded
                    }

                    Accessible.role:        Accessible.Button
                    Accessible.name:        qsTr("Advanced modules")
                    Accessible.description: root._advancedExpanded ? qsTr("Collapse") : qsTr("Expand")
                }

                // Advanced body
                Column {
                    visible: root._advancedExpanded
                    width:   parent.width - Theme.spacingL * 2
                    spacing: Theme.spacingM

                    opacity: root._advancedExpanded ? 1 : 0
                    Behavior on opacity {
                        enabled: !(typeof perfBudget !== "undefined" &&
                                   perfBudget !== null && perfBudget.animationsPaused)
                        NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType }
                    }

                    SearchBar {
                        id:              advSearch
                        width:           parent.width
                        placeholderText: qsTr("Search modules…")
                        onSearchChanged: (q) => { root._searchText = q }
                    }

                    // Responsive module grid
                    Flow {
                        id:      advFlow
                        width:   parent.width
                        spacing: Theme.spacingM

                        Repeater {
                            id:    advRepeater
                            model: root._modulesModel

                            delegate: Item {
                                id:    advSlot
                                required property int    index
                                required property string displayName
                                required property int    category
                                required property int    currentMode
                                required property int    supportedModesMask
                                required property int    statusHealth
                                required property string detailPage
                                required property bool   binary
                                required property string iconId

                                // Note: 'id' is a reserved QML keyword; the module id
                                // is accessed via _moduleId captured at construction.
                                readonly property string _moduleId: {
                                    if (root._modulesModel === null) return ""
                                    return root._role(index, 1) ?? ""
                                }

                                // Client-side search filter
                                readonly property bool _matches: {
                                    var q = root._searchText.trim().toLowerCase()
                                    if (q.length === 0) return true
                                    return displayName.toLowerCase().indexOf(q) >= 0
                                }

                                // Responsive column width: 3-col ≥900px, 2-col ≥580px, 1-col
                                readonly property int _colWidth: {
                                    if (advFlow.width >= 900)
                                        return Math.floor((advFlow.width - Theme.spacingM * 2) / 3)
                                    if (advFlow.width >= 580)
                                        return Math.floor((advFlow.width - Theme.spacingM) / 2)
                                    return advFlow.width
                                }

                                width:   _matches ? _colWidth : 0
                                height:  _matches ? (advCard.implicitHeight) : 0
                                visible: _matches

                                ModuleCard {
                                    id:                 advCard
                                    width:              parent.width
                                    moduleName:         advSlot._moduleId
                                    displayName:        advSlot.displayName
                                    iconSource:         "qrc:/icons/" + advSlot.iconId + ".svg"
                                    state:              root._healthToState(advSlot.statusHealth)
                                    enabled:            advSlot.currentMode > 0
                                    currentMode:        advSlot.currentMode
                                    supportedModesMask: advSlot.supportedModesMask

                                    onToggled: (v) => {
                                        if (root._modulesModel !== null && advSlot._moduleId.length > 0)
                                            root._modulesModel.toggleBinaryModule(advSlot._moduleId, v)
                                    }
                                    onModeChosen: (m) => {
                                        if (root._modulesModel !== null && advSlot._moduleId.length > 0)
                                            root._modulesModel.setModuleMode(advSlot._moduleId, m)
                                    }
                                    onOpenDetail: root._openModuleDetail(advSlot._moduleId,
                                                                        advSlot.detailPage)
                                }
                            }
                        }

                        // "No results" state for advanced search
                        Loader {
                            width: advFlow.width
                            sourceComponent: {
                                if (root._searchText.trim().length === 0) return null
                                if (root._modulesModel === null) return advNoResultsComp
                                var q = root._searchText.trim().toLowerCase()
                                for (var i = 0; i < root._modulesModel.rowCount(); i++) {
                                    var dn = root._role(i, 2) ?? ""
                                    if (dn.toLowerCase().indexOf(q) >= 0) return null
                                }
                                return advNoResultsComp
                            }

                            Component {
                                id: advNoResultsComp
                                EmptyState {
                                    width:   parent ? parent.width : 400
                                    height:  80
                                    title:   qsTr("No modules found")
                                    message: qsTr("No modules match \"%1\".").arg(root._searchText)
                                }
                            }
                        }
                    }
                }

                Item { width: 1; height: Theme.spacingL }
            }
        }
    }
}
