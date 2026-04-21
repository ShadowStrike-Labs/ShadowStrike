import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import "Theming"
import "components"
import "pages"

/*
 * Root application window.
 * - Frameless, draggable via the title area (above the sidebar & page stack).
 * - 1080 x 680 DIP fixed aspect. Not resizable on Community.
 * - Dark theme primary; Theme.dark toggle reserved for later.
 */
ApplicationWindow {
    id: root
    width: 1080
    height: 680
    minimumWidth: 1080
    minimumHeight: 680
    visible: true
    flags: Qt.Window | Qt.FramelessWindowHint
    color: "transparent"
    title: "ShadowStrike Phantom"

    Accessible.role: Accessible.Window
    Accessible.name: qsTr("ShadowStrike Phantom Home")
    Accessible.description: qsTr("ShadowStrike Phantom Home main window. Use Tab to move between controls.")

    // Injected from main.cpp
    property var protectionVm: null

    // Rounded background layer
    Rectangle {
        anchors.fill: parent
        color: Theme.bg0
        radius: Theme.radiusLg
        border.color: Theme.stroke
        border.width: 1
    }

    // --- Title bar (drag + window controls) -------------------------------
    Rectangle {
        id: titleBar
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: 36
        color: "transparent"

        MouseArea {
            anchors.fill: parent
            acceptedButtons: Qt.LeftButton
            property point pressPos
            onPressed: (mouse) => {
                pressPos = Qt.point(mouse.x, mouse.y)
                root.startSystemMove()
            }
        }

        Row {
            anchors.right: parent.right
            anchors.rightMargin: Theme.sp3
            anchors.verticalCenter: parent.verticalCenter
            spacing: Theme.sp1

            Button {
                text: "\u2014"                 // em-dash minimize
                flat: true
                onClicked: root.showMinimized()
                implicitWidth: 36; implicitHeight: 28
                focusPolicy: Qt.TabFocus
                Accessible.role: Accessible.Button
                Accessible.name: qsTr("Minimize")
                Accessible.description: qsTr("Minimize the ShadowStrike Phantom window")
            }
            Button {
                text: "\u2715"                 // ✕ close
                flat: true
                onClicked: root.close()
                implicitWidth: 36; implicitHeight: 28
                focusPolicy: Qt.TabFocus
                Accessible.role: Accessible.Button
                Accessible.name: qsTr("Close")
                Accessible.description: qsTr("Close the ShadowStrike Phantom window")
            }
        }
    }

    // --- Main body: sidebar + page stack ----------------------------------
    RowLayout {
        anchors.top: titleBar.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: 1
        spacing: 0

        Sidebar {
            id: sidebar
            Layout.preferredWidth: 196
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
                stateCopy:        protectionVm ? protectionVm.stateCopy        : "We are protecting you"
                stateSubCopy:     protectionVm ? protectionVm.stateSubCopy     : ""
                lastScan:         protectionVm ? protectionVm.lastScan         : "—"
                threatsBlocked7d: protectionVm ? protectionVm.threatsBlocked7d : 0
                updateStatus:     protectionVm ? protectionVm.updateStatus     : "Checking…"
                onStartFastScan: if (protectionVm) protectionVm.startFastScan()
            }
            SecurityPage {
                modules: protectionVm ? protectionVm.modules : []
                onSetModuleEnabled: (id, on) => { if (protectionVm) protectionVm.setModuleEnabled(id, on) }
            }
            PerformancePage {
                cpuPct: protectionVm ? protectionVm.cpuPct : 0.0
                memPct: protectionVm ? protectionVm.memPct : 0.0
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

    // Startup scale-in
    NumberAnimation on opacity {
        from: 0.0; to: 1.0
        duration: Theme.motionNormal
        running: true
    }
}
