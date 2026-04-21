import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import "Theming"
import "components"
import "pages"

/*
 * Root application window for ShadowStrike Phantom Home.
 *
 * Frameless, borderless, tone-driven chrome. A single rounded surface
 * with a subtle shadow illusion; a restructured title bar row now
 * composes with the sidebar/page stack via a single ColumnLayout so no
 * top-anchored rogue items shift layout when the window resizes.
 */
ApplicationWindow {
    id: root
    width: 1280
    height: 800
    minimumWidth: 1240
    minimumHeight: 760
    visible: true
    flags: Qt.Window | Qt.FramelessWindowHint
    color: "transparent"
    title: "ShadowStrike Phantom"

    Accessible.role: Accessible.Window
    Accessible.name: qsTr("ShadowStrike Phantom Home")

    property var protectionVm: null
    property int currentPage: 0

    // --- Outer shadow illusion -------------------------------------------
    Rectangle {
        id: outerShadow
        anchors.fill: surface
        anchors.margins: -1
        radius: surface.radius + 1
        color: "transparent"
        border.color: Qt.rgba(0, 0, 0, 0.40)
        border.width: 1
        z: -1
    }

    // --- Rounded window surface -------------------------------------------
    Rectangle {
        id: surface
        anchors.fill: parent
        radius: Theme.radiusLg
        color: Theme.bg0
        border.width: 0

        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 1
            width: parent.width * 0.45
            height: 1
            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.30)
            z: 2
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 0

            // ---- Title bar row ------------------------------------
            Item {
                id: titleBar
                Layout.fillWidth: true
                Layout.preferredHeight: Theme.titleBarHeight

                DragHandler {
                    target: null
                    onActiveChanged: if (active) root.startSystemMove()
                }

                Rectangle {
                    id: search
                    anchors.left: parent.left
                    anchors.leftMargin: Theme.sidebarWidth + Theme.sp5
                    anchors.verticalCenter: parent.verticalCenter
                    width: 280
                    height: 30
                    radius: 15
                    color: Theme.bg2

                    Text {
                        anchors.left: parent.left
                        anchors.leftMargin: Theme.sp3
                        anchors.verticalCenter: parent.verticalCenter
                        text: "\uD83D\uDD0D"
                        color: Theme.textMuted
                        font.pixelSize: 12
                    }
                    TextInput {
                        id: searchInput
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.leftMargin: Theme.sp6 + 6
                        anchors.rightMargin: Theme.sp3
                        color: Theme.text
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                        selectByMouse: true
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: qsTr("Search (Ctrl+F)")
                            color: Theme.textDim
                            font: parent.font
                            visible: !parent.text && !parent.activeFocus
                        }
                    }
                }

                Row {
                    id: windowControls
                    anchors.right: parent.right
                    anchors.rightMargin: Theme.sp3
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 2

                    IconButton {
                        glyph: "\u2212"
                        onClicked: root.showMinimized()
                        Accessible.name: qsTr("Minimize")
                    }
                    IconButton {
                        glyph: "\u2715"
                        danger: true
                        onClicked: root.close()
                        Accessible.name: qsTr("Close")
                    }
                }
            }

            // ---- Body: sidebar + page stack ------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

                Sidebar {
                    id: sidebar
                    Layout.preferredWidth: Theme.sidebarWidth
                    Layout.fillHeight: true
                    selectedIndex: root.currentPage
                    engineOnline: protectionVm ? protectionVm.sensorOk : true
                    onNavigate: (i) => root.currentPage = i
                    onOpenSettings: root.currentPage = 8
                }

                StackLayout {
                    id: stack
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: root.currentPage

                    MainPage {
                        protectionState:  protectionVm ? protectionVm.protectionState  : "green"
                        stateCopy:        protectionVm ? protectionVm.stateCopy        : qsTr("You are protected")
                        stateSubCopy:     protectionVm ? protectionVm.stateSubCopy     : qsTr("Real-time protection is active.")
                        lastScan:         protectionVm ? protectionVm.lastScan         : "\u2014"
                        threatsBlocked7d: protectionVm ? protectionVm.threatsBlocked7d : 0
                        updateStatus:     protectionVm ? protectionVm.updateStatus     : qsTr("Checking for updates\u2026")
                        sensorOk:         protectionVm ? protectionVm.sensorOk         : false
                        sensorReason:     protectionVm ? protectionVm.sensorReason     : ""
                        cortexActive:     protectionVm ? protectionVm.cortexActive     : 0
                        cortexTotal:      protectionVm ? protectionVm.cortexTotal      : 0
                        modules:          protectionVm ? protectionVm.modules          : []
                        recentEvents:     protectionVm ? protectionVm.recentEvents     : []
                        onStartFastScan:    if (protectionVm) protectionVm.startFastScan()
                        onOpenScanTab:      root.currentPage = 4
                        onOpenUpdateTab:    root.currentPage = 8
                        onOpenSecurityTab:  root.currentPage = 1
                        onOpenReportsTab:   root.currentPage = 6
                    }
                    SecurityPage {
                        modules: protectionVm ? protectionVm.modules : []
                        onSetModuleEnabled:   (id, on)      => { if (protectionVm) protectionVm.setModuleEnabled(id, on) }
                        onSetDetectionAction: (id, action)  => { if (protectionVm && protectionVm.setDetectionAction) protectionVm.setDetectionAction(id, action) }
                        onConfigureModule:    (id, payload) => { if (protectionVm && protectionVm.configureModule) protectionVm.configureModule(id, payload) }
                    }
                    PerformancePage {
                        cpuPct:             protectionVm ? protectionVm.cpuPct             : 0.0
                        memPct:             protectionVm ? protectionVm.memPct             : 0.0
                        gameModeActive:     protectionVm ? protectionVm.gameModeActive     : false
                        batterySaverActive: protectionVm ? protectionVm.batterySaverActive : false
                        onRunTuneUp: (name) => { if (protectionVm && protectionVm.runTuneUp) protectionVm.runTuneUp(name) }
                    }
                    PrivacyPage {
                        modules:      protectionVm ? protectionVm.modules      : []
                        recentEvents: protectionVm ? protectionVm.recentEvents : []
                        onConfigureModule: (id, payload) => { if (protectionVm && protectionVm.configureModule) protectionVm.configureModule(id, payload) }
                        onSetToggle: (id, on) => { if (protectionVm) protectionVm.setModuleEnabled(id, on) }
                    }
                    ScanPage { }
                    QuarantinePage {
                        items:           protectionVm ? protectionVm.quarantineItems : []
                        quarantineItems: protectionVm ? protectionVm.quarantineItems : []
                        onRestore: (id) => { if (protectionVm && protectionVm.restoreQuarantineItem) protectionVm.restoreQuarantineItem(id) }
                        onPurge:   (id) => { if (protectionVm && protectionVm.deleteQuarantineItem)  protectionVm.deleteQuarantineItem(id) }
                    }
                    ReportsPage {
                        events: protectionVm ? protectionVm.recentEvents : []
                        onExportReportCsv: { if (protectionVm && protectionVm.exportReportCsv) protectionVm.exportReportCsv() }
                    }
                    IdentityPage {
                        onRunPasswordAudit: { if (protectionVm && protectionVm.runPasswordAudit) protectionVm.runPasswordAudit() }
                    }
                    SettingsPage {
                        sensorOk:     protectionVm ? protectionVm.sensorOk     : false
                        sensorReason: protectionVm ? protectionVm.sensorReason : ""
                        cortexActive: protectionVm ? protectionVm.cortexActive : 0
                        cortexTotal:  protectionVm ? protectionVm.cortexTotal  : 0
                        onConfigureModule: (id, payload) => { if (protectionVm && protectionVm.configureModule) protectionVm.configureModule(id, payload) }
                        onInstallUpdate: { if (protectionVm && protectionVm.installUpdate) protectionVm.installUpdate() }
                    }
                }
            }
        }
    }

    Shortcut {
        sequence: "Ctrl+F"
        onActivated: searchInput.forceActiveFocus()
    }
    Shortcut {
        sequence: "Escape"
        onActivated: {
            searchInput.text = "";
            searchInput.focus = false;
        }
    }

    NumberAnimation on opacity {
        from: 0.0; to: 1.0
        duration: Theme.motionNormal
        running: true
    }
}
