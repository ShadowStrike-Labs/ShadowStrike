/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SecurityPage.qml — Main protection configuration page.
 *
 * Layout:
 *   TopBar with Quarantine + PGTI navigation buttons
 *   Basic section:
 *     ModePillRow — global protection mode (Off/Balanced/Aggressive)
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
 * ProtectionViewModel.globalMode: 0=Off, 1=Balanced, 2=Aggressive
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

    /// ProtectionViewModel globalMode (0=Off,1=Balanced,2=Aggressive)
    /// → ModePillRow currentMode index (0=Off,1=Passive,2=Balanced,3=Aggressive).
    function _vmModeToUiMode(mode) {
        switch (mode) {
        case 0:  return 0   // Off → Off
        case 1:  return 2   // Balanced → Balanced
        case 2:  return 3   // Aggressive → Aggressive
        default: return 0
        }
    }
    /// Reverse mapping: ModePillRow index → ProtectionViewModel globalMode.
    function _uiModeToVmMode(uiMode) {
        switch (uiMode) {
        case 0:  return 0   // Off → Off
        case 2:  return 1   // Balanced → Balanced
        case 3:  return 2   // Aggressive → Aggressive
        default: return 0
        }
    }

    /// Read-only model role accessor (convenience wrapper).
    function _role(row, offset) {
        if (root._modulesModel === null) return undefined
        return root._modulesModel.data(root._modulesModel.index(row, 0), Qt.UserRole + offset)
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

                        // Global mode pill row
                        // Off=bit0, Balanced=bit2, Aggressive=bit3; Passive (bit1) not offered globally.
                        ModePillRow {
                            id:                 globalModePills
                            supportedModesMask: 0b1101
                            currentMode:        (typeof protectionViewModel !== "undefined")
                                                ? root._vmModeToUiMode(protectionViewModel.globalMode) : 0
                            onModeChosen: (m) => {
                                if (typeof protectionViewModel !== "undefined")
                                    protectionViewModel.setGlobalMode(root._uiModeToVmMode(m))
                            }
                        }

                        // Pause / resume row (visible only when protection is on)
                        Item {
                            width:  parent.width
                            height: pauseRow.implicitHeight
                            visible: (typeof protectionViewModel !== "undefined") &&
                                     protectionViewModel.globalMode > 0

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
                // Priority module cards — categories 0/1/2 (top 5 only)
                // -------------------------------------------------------------
                SectionTitle {
                    text:  qsTr("Core protection")
                    width: parent.width - Theme.spacingL * 2
                }

                Flow {
                    id:      priorityFlow
                    width:   parent.width - Theme.spacingL * 2
                    spacing: Theme.spacingM

                    Repeater {
                        id:    priorityRepeater
                        model: {
                            if (root._modulesModel === null) return 0
                            var total = root._modulesModel.rowCount()
                            var shown = 0
                            for (var i = 0; i < total && shown < 5; i++) {
                                var cat = root._role(i, 4)   // CategoryRole
                                if (cat !== undefined && cat <= 2) shown++
                            }
                            return shown
                        }

                        delegate: Item {
                            id:    prioritySlot
                            required property int index

                            // Locate the i-th module in categories 0/1/2
                            readonly property int _row: {
                                if (root._modulesModel === null) return -1
                                var total = root._modulesModel.rowCount()
                                var count = 0
                                for (var i = 0; i < total; i++) {
                                    var cat = root._role(i, 4)
                                    if (cat !== undefined && cat <= 2) {
                                        if (count === prioritySlot.index) return i
                                        count++
                                    }
                                }
                                return -1
                            }

                            width:  _row >= 0
                                    ? Math.max(260, Math.floor(
                                          (priorityFlow.width - Theme.spacingM) / 2))
                                    : 0
                            height: _row >= 0 ? priorityCard.implicitHeight : 0
                            visible: _row >= 0

                            ModuleCard {
                                id:                 priorityCard
                                width:              parent.width

                                moduleName:         root._role(prioritySlot._row, 1)  ?? ""
                                displayName:        root._role(prioritySlot._row, 2)  ?? qsTr("Module")
                                iconSource:         "qrc:/icons/" + (root._role(prioritySlot._row, 3) ?? "Shield") + ".svg"
                                currentMode:        root._role(prioritySlot._row, 5)  ?? 0
                                supportedModesMask: root._role(prioritySlot._row, 6)  ?? 0b1111
                                // detailPage from role +7; statusHealth from +8; statusDetail from +9; binary from +10
                                state:              root._healthToState(root._role(prioritySlot._row, 8) ?? -1)
                                enabled:            (root._role(prioritySlot._row, 5) ?? 0) > 0
                                description:        root._role(prioritySlot._row, 9) ?? ""

                                onToggled: (v) => {
                                    var mid = root._role(prioritySlot._row, 1) ?? ""
                                    if (root._modulesModel !== null && mid.length > 0)
                                        root._modulesModel.toggleBinaryModule(mid, v)
                                }
                                onModeChosen: (m) => {
                                    var mid = root._role(prioritySlot._row, 1) ?? ""
                                    if (root._modulesModel !== null && mid.length > 0)
                                        root._modulesModel.setModuleMode(mid, m)
                                }
                                onOpenDetail: {
                                    var dp  = root._role(prioritySlot._row, 7) ?? ""
                                    var cat = root._role(prioritySlot._row, 4) ?? -1
                                    if (typeof stack === "undefined") return
                                    if (dp.length > 0) {
                                        Qt.callLater(stack.push, "qrc:/qml/Pages/" + dp)
                                    } else if (cat === 1) {
                                        // BehavioralSecurity category → ZeroTrust detail
                                        Qt.callLater(stack.push, "qrc:/qml/Pages/ZeroTrustDetailPage.qml")
                                    }
                                }
                            }
                        }
                    }

                    // Empty state when no priority modules are found
                    Loader {
                        width: priorityFlow.width
                        sourceComponent: (priorityRepeater.count === 0 &&
                                          root._modulesModel !== null)
                                         ? priorityEmptyComp : null
                        Component {
                            id: priorityEmptyComp
                            EmptyState {
                                width:   parent ? parent.width : 400
                                height:  80
                                title:   qsTr("No modules available")
                                message: qsTr("Protection modules will appear here once loaded.")
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
                            text:           qsTr("Advanced")
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
                                    onOpenDetail: {
                                        if (advSlot.detailPage.length > 0 && typeof stack !== "undefined")
                                            Qt.callLater(stack.push, "qrc:/qml/Pages/" + advSlot.detailPage)
                                    }
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
