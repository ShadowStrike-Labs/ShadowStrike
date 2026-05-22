/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 *
 * SettingsPage.qml — Phantom Home configuration surface.
 *
 * Bound to settingsViewModel (context property):
 *   get(key, defaultValue), set(key, value), refreshAll()
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components

PageHost {
    id: root

    property int settingsRevision: 0
    property string lastError: ""

    readonly property bool settingsAvailable:
        (typeof settingsViewModel !== "undefined" && settingsViewModel !== null)

    readonly property var sections: [
        {
            title: qsTr("Protection"),
            subtitle: qsTr("Core prevention and remediation controls."),
            items: [
                { key: "Home/Protection/RealTime",       label: qsTr("Real-time file protection"),      description: qsTr("Monitor file activity continuously."),                  defaultValue: true  },
                { key: "Home/Protection/CloudLookup",    label: qsTr("Cloud reputation lookup"),        description: qsTr("Use cloud intelligence for unknown files."),             defaultValue: true  },
                { key: "Home/Protection/AutoQuarantine", label: qsTr("Automatic quarantine"),           description: qsTr("Contain confirmed threats without prompting."),          defaultValue: true  },
                { key: "Home/Protection/PUPDetection",   label: qsTr("Potentially unwanted programs"), description: qsTr("Detect unwanted installers, bundles, and toolbars."),    defaultValue: true  },
                { key: "Home/Protection/RansomwareShield", label: qsTr("Ransomware behavior shield"),   description: qsTr("Block suspicious encryption and tampering behavior."),  defaultValue: true  }
            ]
        },
        {
            title: qsTr("Scanning"),
            subtitle: qsTr("Scheduled and on-access scan behavior."),
            items: [
                { key: "Home/Scan/QuickScanOnStartup", label: qsTr("Quick scan on startup"),   description: qsTr("Run a lightweight scan when Windows starts."), defaultValue: false },
                { key: "Home/Scan/ScheduledScan",      label: qsTr("Scheduled scans"),         description: qsTr("Allow Phantom Home to run planned scans."),    defaultValue: true  },
                { key: "Home/Scan/RemovableMedia",     label: qsTr("Scan removable media"),    description: qsTr("Inspect USB drives when they are attached."),  defaultValue: true  },
                { key: "Home/Scan/Archives",           label: qsTr("Scan archive contents"),   description: qsTr("Inspect supported compressed files."),         defaultValue: true  }
            ]
        },
        {
            title: qsTr("Notifications"),
            subtitle: qsTr("User-facing alerts and tray behavior."),
            items: [
                { key: "Home/UX/ShowThreatPopup",  label: qsTr("Threat popups"),      description: qsTr("Show a popup when a threat is blocked."),       defaultValue: true },
                { key: "Home/UX/ShowScanProgress", label: qsTr("Scan progress"),      description: qsTr("Show scan progress from the tray."),            defaultValue: true },
                { key: "Home/UX/ShowTrayIcon",     label: qsTr("System tray icon"),   description: qsTr("Keep Phantom Home visible in the tray."),       defaultValue: true },
                { key: "Home/UX/NotificationSound", label: qsTr("Notification sound"), description: qsTr("Play a sound for important local alerts."),    defaultValue: true }
            ]
        },
        {
            title: qsTr("Updates and diagnostics"),
            subtitle: qsTr("Maintenance and privacy-conscious diagnostics."),
            items: [
                { key: "Home/Update/AutoUpdate",           label: qsTr("Automatic updates"),       description: qsTr("Download and apply protection updates automatically."), defaultValue: true  },
                { key: "Home/Update/NotifyBeforeRestart",  label: qsTr("Restart notifications"),   description: qsTr("Notify before an update requires restart."),           defaultValue: true  },
                { key: "Home/Telemetry/OptIn",             label: qsTr("Telemetry opt-in"),        description: qsTr("Share privacy-conscious product telemetry."),          defaultValue: false },
                { key: "Home/Telemetry/CrashReporting",    label: qsTr("Crash reporting"),         description: qsTr("Send crash diagnostics to improve reliability."),      defaultValue: true  }
            ]
        }
    ]

    function toBool(value, fallback) {
        if (typeof value === "boolean") return value
        if (typeof value === "number") return value !== 0
        if (typeof value === "string") {
            const normalized = value.toLowerCase()
            return normalized === "true" || normalized === "1" || normalized === "yes"
        }
        return fallback
    }

    function readBool(key, fallback) {
        root.settingsRevision
        if (!root.settingsAvailable) return fallback
        return root.toBool(settingsViewModel.get(key, fallback), fallback)
    }

    function writeBool(key, value) {
        if (!root.settingsAvailable) return
        root.lastError = ""
        settingsViewModel.set(key, value)
    }

    function refreshSettings() {
        if (!root.settingsAvailable) return
        root.lastError = ""
        settingsViewModel.refreshAll()
    }

    Connections {
        target: root.settingsAvailable ? settingsViewModel : null

        function onSettingChanged(key, value) {
            root.settingsRevision += 1
            root.lastError = ""
        }

        function onRequestError(code, message) {
            root.lastError = message && message.length > 0
                           ? message
                           : qsTr("Settings request failed (%1).").arg(code)
        }
    }

    Component.onCompleted: refreshSettings()

    Column {
        anchors.fill: parent
        spacing: 0

        TopBar {
            id: topBar
            width: parent.width
            pageTitle: qsTr("Settings")
            showBack: true
            onBackClicked: {
                if (root.stack) root.stack.pop()
            }

            GhostButton {
                text: qsTr("Refresh")
                onClicked: root.refreshSettings()
            }
        }

        ScrollView {
            id: scroll
            width: parent.width
            height: parent.height - topBar.implicitHeight
            contentWidth: parent.width
            clip: true

            Column {
                width: scroll.width
                spacing: Theme.spacingL
                padding: Theme.spacingL

                Loader {
                    width: parent.width - Theme.spacingL * 2
                    active: !root.settingsAvailable
                    sourceComponent: Component {
                        EmptyState {
                            title: qsTr("Settings unavailable")
                            message: qsTr("The local service is not exposing the settings bridge. Protection continues with the last known configuration.")
                        }
                    }
                }

                Rectangle {
                    width: parent.width - Theme.spacingL * 2
                    height: errorText.implicitHeight + Theme.spacingM * 2
                    visible: root.lastError.length > 0
                    radius: Theme.radiusMedium
                    color: Qt.rgba(Theme.crit.r, Theme.crit.g, Theme.crit.b, 0.12)
                    border.color: Theme.crit
                    border.width: 1

                    Text {
                        id: errorText
                        anchors {
                            left: parent.left
                            right: parent.right
                            margins: Theme.spacingM
                            verticalCenter: parent.verticalCenter
                        }
                        text: root.lastError
                        color: Theme.textPrimary
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeLabel
                        wrapMode: Text.WordWrap
                    }
                }

                Repeater {
                    model: root.sections

                    delegate: Column {
                        required property var modelData

                        width: parent.width - Theme.spacingL * 2
                        spacing: Theme.spacingM
                        visible: root.settingsAvailable

                        SectionTitle {
                            text: modelData.title
                            subtitle: modelData.subtitle
                            width: parent.width
                        }

                        Card {
                            width: parent.width

                            Column {
                                width: parent.width
                                spacing: 0

                                Repeater {
                                    model: modelData.items

                                    delegate: Item {
                                        required property var modelData

                                        width: parent.width
                                        height: Math.max(64, rowContent.implicitHeight + Theme.spacingM)

                                        Rectangle {
                                            anchors.bottom: parent.bottom
                                            width: parent.width
                                            height: 1
                                            color: Theme.strokeSubtle
                                        }

                                        Row {
                                            id: rowContent
                                            anchors {
                                                left: parent.left
                                                right: parent.right
                                                verticalCenter: parent.verticalCenter
                                            }
                                            spacing: Theme.spacingM

                                            Column {
                                                width: parent.width - settingToggle.implicitWidth - Theme.spacingM
                                                spacing: 2

                                                Text {
                                                    text: modelData.label
                                                    color: Theme.textPrimary
                                                    font.family: Theme.fontFamily
                                                    font.pixelSize: Theme.fontSizeBody
                                                    font.weight: Theme.fontWeightMedium
                                                }

                                                Text {
                                                    text: modelData.description
                                                    color: Theme.textSecondary
                                                    font.family: Theme.fontFamily
                                                    font.pixelSize: Theme.fontSizeLabel
                                                    wrapMode: Text.WordWrap
                                                    width: parent.width
                                                }
                                            }

                                            ToggleSwitch {
                                                id: settingToggle
                                                checked: root.readBool(modelData.key, modelData.defaultValue)
                                                anchors.verticalCenter: parent.verticalCenter
                                                onToggled: function(newValue) {
                                                    root.writeBool(modelData.key, newValue)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
