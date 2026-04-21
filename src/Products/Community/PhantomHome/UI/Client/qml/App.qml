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
 * - Frameless, draggable via the title bar.
 * - Fixed-aspect 1240 x 760 DIP on Community. Not resizable.
 * - All visual styling comes from Theme; nothing hard-codes colors.
 */
ApplicationWindow {
    id: root
    width: 1240
    height: 760
    minimumWidth: 1240
    minimumHeight: 760
    visible: true
    flags: Qt.Window | Qt.FramelessWindowHint
    color: "transparent"
    title: "ShadowStrike Phantom"

    Accessible.role: Accessible.Window
    Accessible.name: qsTr("ShadowStrike Phantom Home")
    Accessible.description: qsTr("ShadowStrike Phantom Home main window. Use Tab to move between controls.")

    // Injected from main.cpp (ProtectionViewModel)
    property var protectionVm: null

    // --- Rounded window surface -------------------------------------------
    Rectangle {
        id: surface
        anchors.fill: parent
        radius: Theme.radiusLg
        border.color: Theme.stroke
        border.width: 1
        gradient: Gradient {
            GradientStop { position: 0.0; color: Theme.bgGradTop }
            GradientStop { position: 1.0; color: Theme.bgGradBot }
        }

        // Subtle top accent line (1 px) - helps the chrome read as a window
        // rather than a flat panel.
        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: 1
            anchors.leftMargin: Theme.radiusLg
            anchors.rightMargin: Theme.radiusLg
            height: 1
            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.35)
        }
    }

    // --- Title bar --------------------------------------------------------
    Rectangle {
        id: titleBar
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: Theme.titleBarHeight
        color: Theme.bgHeader
        radius: Theme.radiusLg

        // The bottom corners of the title bar must not be rounded - square
        // them off with a second rectangle matching the title bar color.
        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: parent.height / 2
            color: parent.color
        }

        // Draggable area covers the full bar, but stops short of the window
        // control buttons on the right so clicks there land on the buttons.
        MouseArea {
            anchors.left: parent.left
            anchors.right: windowControls.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            acceptedButtons: Qt.LeftButton
            onPressed: root.startSystemMove()
            onDoubleClicked: {
                // Ignore double click on Community (non-resizable window).
            }
        }

        Row {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.sp4
            spacing: Theme.sp2

            // Accent mark - a tiny blue square to brand the chrome.
            Rectangle {
                width: 10; height: 10
                radius: 2
                anchors.verticalCenter: parent.verticalCenter
                color: Theme.accent
            }
            Text {
                text: "ShadowStrike Phantom"
                anchors.verticalCenter: parent.verticalCenter
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontBody
                font.weight: Font.DemiBold
            }
            Rectangle {
                width: 1; height: 14
                anchors.verticalCenter: parent.verticalCenter
                color: Theme.stroke
            }
            Text {
                text: "Home"
                anchors.verticalCenter: parent.verticalCenter
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
            }
        }

        // --- Window controls (visible, hover-highlighted) -----------------
        Row {
            id: windowControls
            anchors.right: parent.right
            anchors.rightMargin: Theme.sp2
            anchors.verticalCenter: parent.verticalCenter
            spacing: 2

            IconButton {
                glyph: "\u2212"               // minus (minimize)
                onClicked: root.showMinimized()
                Accessible.name: qsTr("Minimize")
                Accessible.description: qsTr("Minimize the ShadowStrike Phantom window")
            }
            IconButton {
                glyph: "\u2715"               // multiplication X (close)
                danger: true
                onClicked: root.close()
                Accessible.name: qsTr("Close")
                Accessible.description: qsTr("Close the ShadowStrike Phantom window")
            }
        }

        // Bottom hairline between title bar and main body.
        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 1
            color: Theme.stroke
        }
    }

    // --- Main body: sidebar + page stack ----------------------------------
    RowLayout {
        anchors.top: titleBar.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: 0

        Sidebar {
            id: sidebar
            Layout.preferredWidth: Theme.sidebarWidth
            Layout.fillHeight: true
            selectedIndex: 0
            onNavigate: (i) => stack.currentIndex = i
        }

        StackLayout {
            id: stack
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: 0

            MainPage {
                protectionState:  protectionVm ? protectionVm.protectionState  : "green"
                stateCopy:        protectionVm ? protectionVm.stateCopy        : "You are protected"
                stateSubCopy:     protectionVm ? protectionVm.stateSubCopy     : "Real-time protection is active."
                lastScan:         protectionVm ? protectionVm.lastScan         : "—"
                threatsBlocked7d: protectionVm ? protectionVm.threatsBlocked7d : 0
                updateStatus:     protectionVm ? protectionVm.updateStatus     : "Checking for updates…"
                sensorOk:         protectionVm ? protectionVm.sensorOk         : false
                sensorReason:     protectionVm ? protectionVm.sensorReason     : ""
                cortexActive:     protectionVm ? protectionVm.cortexActive     : 0
                cortexTotal:      protectionVm ? protectionVm.cortexTotal      : 0
                modules:          protectionVm ? protectionVm.modules          : []
                recentEvents:     protectionVm ? protectionVm.recentEvents     : []
                onStartFastScan:    if (protectionVm) protectionVm.startFastScan()
                onOpenScanTab:      stack.currentIndex = 4
                onOpenUpdateTab:    stack.currentIndex = 7
                onOpenSecurityTab:  stack.currentIndex = 1
                onOpenReportsTab:   stack.currentIndex = 6
            }
            SecurityPage {
                modules: protectionVm ? protectionVm.modules : []
                onSetModuleEnabled: (id, on) => { if (protectionVm) protectionVm.setModuleEnabled(id, on) }
                onSetDetectionAction: (id, action) => {
                    if (protectionVm && protectionVm.setDetectionAction) protectionVm.setDetectionAction(id, action)
                }
                onConfigureModule: (id, payload) => {
                    if (protectionVm && protectionVm.configureModule) protectionVm.configureModule(id, payload)
                }
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
