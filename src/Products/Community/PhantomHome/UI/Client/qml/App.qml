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
 * Frameless, borderless, tone-driven chrome. The window itself is a
 * single deep surface with rounded corners; the title bar carries the
 * search field and window controls, the left rail hosts navigation,
 * and the page stack fills the rest.
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

    // Injected from main.cpp (ProtectionViewModel).
    property var protectionVm: null

    // Currently-visible page index. Drives both Sidebar highlight and
    // the StackLayout below. Bound both ways via Sidebar's navigate().
    property int currentPage: 0

    // --- Rounded window surface -------------------------------------------
    Rectangle {
        id: surface
        anchors.fill: parent
        radius: Theme.radiusLg
        color: Theme.bg0
        border.width: 0

        // Very subtle top accent glow - a whisper of blue, not a line.
        Rectangle {
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.top: parent.top
            anchors.topMargin: 1
            width: parent.width * 0.45
            height: 1
            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.30)
        }
    }

    // --- Title bar --------------------------------------------------------
    Item {
        id: titleBar
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Theme.sidebarWidth
        height: Theme.titleBarHeight

        // Drag area (stops short of the window controls on the right).
        MouseArea {
            anchors.left: parent.left
            anchors.right: windowControls.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            acceptedButtons: Qt.LeftButton
            onPressed: root.startSystemMove()
        }

        // Search input (centered, narrow, top-of-page).
        Rectangle {
            id: search
            anchors.left: parent.left
            anchors.leftMargin: Theme.sp5
            anchors.verticalCenter: parent.verticalCenter
            width: 280
            height: 30
            radius: 15
            color: Theme.bg2

            Text {
                anchors.left: parent.left
                anchors.leftMargin: Theme.sp3
                anchors.verticalCenter: parent.verticalCenter
                text: "\uD83D\uDD0D"      // magnifier
                color: Theme.textMuted
                font.pixelSize: 12
            }
            TextInput {
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

        // Window controls (min / close). No maximize on Community.
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

    // --- Main body: sidebar + page stack ----------------------------------
    RowLayout {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.topMargin: 1        // keep accent glow visible
        spacing: 0

        Sidebar {
            id: sidebar
            Layout.preferredWidth: Theme.sidebarWidth
            Layout.fillHeight: true
            selectedIndex: root.currentPage
            engineOnline: protectionVm ? protectionVm.sensorOk : true
            onNavigate: (i) => root.currentPage = i
            onOpenSettings: root.currentPage = 7
        }

        // Page stack begins below the title bar row.
        StackLayout {
            id: stack
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: Theme.titleBarHeight
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
                onOpenUpdateTab:    root.currentPage = 7
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
            }
            PrivacyPage { }
            ScanPage { }
            QuarantinePage { }
            ReportsPage {
                events: protectionVm ? protectionVm.recentEvents : []
            }
            SettingsPage { }
        }
    }

    // Graceful fade-in on startup.
    NumberAnimation on opacity {
        from: 0.0; to: 1.0
        duration: Theme.motionNormal
        running: true
    }
}
