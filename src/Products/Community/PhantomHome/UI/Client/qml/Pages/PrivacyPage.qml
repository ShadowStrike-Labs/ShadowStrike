/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PrivacyPage.qml — Calm-surface privacy protection dashboard.
 * Displays webcam/mic/location/cookie counters, active privacy modules,
 * recent privacy events, and quick-action buttons.
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Privacy dashboard counters (updated by VM binding if available)
    // -------------------------------------------------------------------------
    property int webcamAccessBlocked:    typeof privacyViewModel !== 'undefined' ? privacyViewModel.webcamAccessBlocked : 0
    property int micAccessBlocked:       typeof privacyViewModel !== 'undefined' ? privacyViewModel.micAccessBlocked : 0
    property int locationAccessBlocked:  typeof privacyViewModel !== 'undefined' ? privacyViewModel.locationAccessBlocked : 0
    property int cookiesBlocked:         typeof privacyViewModel !== 'undefined' ? privacyViewModel.cookiesBlocked : 0

    // -------------------------------------------------------------------------
    // Active privacy modules (if modulesListModel is not available, show static)
    // -------------------------------------------------------------------------
    readonly property var staticPrivacyModules: [
        { name: "WebcamProtector",    display: qsTr("Webcam Protector"),    description: qsTr("Blocks unauthorized webcam access"),        icon: "qrc:/icons/shield.svg",  enabled: true  },
        { name: "MicrophoneGuard",    display: qsTr("Microphone Guard"),    description: qsTr("Prevents silent microphone capture"),       icon: "qrc:/icons/shield.svg",  enabled: true  },
        { name: "LocationPrivacy",    display: qsTr("Location Privacy"),    description: qsTr("Masks precise location from apps"),         icon: "qrc:/icons/shield.svg",  enabled: true  },
        { name: "CookieManager",      display: qsTr("Cookie Manager"),      description: qsTr("Cleans tracking cookies on close"),         icon: "qrc:/icons/shield.svg",  enabled: false },
        { name: "DNSLeakProtection",  display: qsTr("DNS Leak Protection"), description: qsTr("Routes DNS through secure resolver"),       icon: "qrc:/icons/shield.svg",  enabled: true  },
        { name: "IPLeakProtection",   display: qsTr("IP Leak Protection"),  description: qsTr("Prevents real IP exposure via WebRTC"),     icon: "qrc:/icons/shield.svg",  enabled: true  },
        { name: "DataLeakProtection", display: qsTr("Data Leak Protection"),description: qsTr("Monitors clipboard and file transfers"),    icon: "qrc:/icons/shield.svg",  enabled: false },
        { name: "PrivacyCleaner",     display: qsTr("Privacy Cleaner"),     description: qsTr("Erases browsing artifacts on demand"),      icon: "qrc:/icons/shield.svg",  enabled: true  },
    ]

    // -------------------------------------------------------------------------
    // Recent privacy events (updated by VM binding if available)
    // -------------------------------------------------------------------------
    property var recentPrivacyEvents: typeof privacyViewModel !== 'undefined' ? privacyViewModel.recentPrivacyEvents : []

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
            // Page header
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Privacy")
                width: parent.width - Theme.spacingL * 2
            }

            // -----------------------------------------------------------------
            // 1. Privacy dashboard card
            // -----------------------------------------------------------------
            Card {
                width: parent.width - Theme.spacingL * 2
                glow:  true
                accent: Theme.accentCyan

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    Text {
                        text:           qsTr("Privacy dashboard")
                        color:          Theme.textPrimary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeTitle
                        font.weight:    Theme.fontWeightBold
                    }

                    Text {
                        text:           qsTr("Access attempts blocked across all sensors this session.")
                        color:          Theme.textSecondary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }

                    // 2×2 grid of sensor tiles
                    Grid {
                        columns:     2
                        spacing:     Theme.spacingM
                        width:       parent.width

                        Repeater {
                            model: [
                                { icon: "eye",      label: qsTr("Webcam"),     count: root.webcamAccessBlocked,   unit: qsTr("blocked") },
                                { icon: "alert",    label: qsTr("Microphone"), count: root.micAccessBlocked,      unit: qsTr("blocked") },
                                { icon: "info",     label: qsTr("Location"),   count: root.locationAccessBlocked, unit: qsTr("blocked") },
                                { icon: "shield",   label: qsTr("Cookies"),    count: root.cookiesBlocked,        unit: qsTr("cleaned") },
                            ]
                            delegate: Item {
                                width:  (parent.width - Theme.spacingM) / 2
                                height: 64

                                Rectangle {
                                    anchors.fill:   parent
                                    radius:         Theme.radiusMedium
                                    color:          Theme.bgSurfaceAlt
                                    border.color:   Theme.strokeSubtle
                                    border.width:   1
                                }

                                Column {
                                    anchors {
                                        verticalCenter: parent.verticalCenter
                                        left:           parent.left
                                        leftMargin:     Theme.spacingM
                                    }
                                    spacing: 2

                                    Text {
                                        text:           modelData.label
                                        color:          Theme.textSecondary
                                        font.family:    Theme.fontFamily
                                        font.pixelSize: Theme.fontSizeLabel
                                    }

                                    Row {
                                        spacing: Theme.spacingXS

                                        Text {
                                            text:           modelData.count.toString()
                                            color:          Theme.accentCyan
                                            font.family:    Theme.fontFamily
                                            font.pixelSize: Theme.fontSizeTitle
                                            font.weight:    Theme.fontWeightBold
                                        }

                                        Text {
                                            text:               modelData.unit
                                            color:              Theme.textMuted
                                            font.family:        Theme.fontFamily
                                            font.pixelSize:     Theme.fontSizeLabel
                                            anchors.baseline:   parent.children[0].baseline
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 2. Active privacy modules
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Active privacy modules")
                width: parent.width - Theme.spacingL * 2
            }

            // Prefer live modulesListModel filtered by category; fall back to static list.
            Repeater {
                id:    modulesRepeater
                model: (typeof privacyViewModel !== 'undefined' && privacyViewModel.modules.length > 0)
                       ? privacyViewModel.modules
                       : root.staticPrivacyModules
                delegate: ModuleCard {
                    required property var modelData
                    width:              parent.width - Theme.spacingL * 2
                    moduleName:         modelData.moduleId || modelData.name
                    displayName:        modelData.displayName || modelData.display
                    description:        modelData.description || ""
                    iconSource:         modelData.iconSource || modelData.icon
                    state:              modelData.state || (modelData.enabled ? "on" : "off")
                    enabled:            modelData.enabled
                    currentMode:        typeof modelData.currentMode === "number" ? modelData.currentMode : 1
                    supportedModesMask: typeof modelData.supportedModesMask === "number" ? modelData.supportedModesMask : 0x3
                    onToggled: function(nowEnabled) {
                        if (typeof privacyViewModel !== 'undefined') {
                            privacyViewModel.setModuleEnabled(moduleName, nowEnabled);
                        } else if (typeof modulesListModel !== 'undefined') {
                            modulesListModel.toggleBinaryModule(moduleName, nowEnabled);
                        } else {
                            console.log("[PrivacyPage] toggle", moduleName, "→", nowEnabled,
                                        "— modulesListModel not yet registered.");
                        }
                    }
                    onModeChosen: function(mode) {
                        if (typeof privacyViewModel !== 'undefined') {
                            privacyViewModel.setModuleMode(moduleName, mode);
                        } else if (typeof modulesListModel !== 'undefined') {
                            modulesListModel.setModuleMode(moduleName, mode);
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 3. Recent privacy events
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Recent privacy events")
                width: parent.width - Theme.spacingL * 2
            }

            Loader {
                width:  parent.width - Theme.spacingL * 2
                active: root.recentPrivacyEvents.length === 0
                sourceComponent: EmptyState {
                    title:   qsTr("No recent events")
                    message: qsTr("All privacy sensors are quiet. No suspicious access attempts detected.")
                }
            }

            Repeater {
                model: root.recentPrivacyEvents
                delegate: ThreatRow {
                    required property var modelData
                    width:            parent.width - Theme.spacingL * 2
                    threatName:       modelData.threatName   || ""
                    filePath:         modelData.filePath     || ""
                    action:           modelData.action       || "blocked"
                    timestampDisplay: modelData.timestamp    || ""
                }
            }

            // -----------------------------------------------------------------
            // 4. Quick actions
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Quick actions")
                width: parent.width - Theme.spacingL * 2
            }

            Row {
                spacing: Theme.spacingM
                width:   parent.width - Theme.spacingL * 2
                x:       Theme.spacingL

                GhostButton {
                    id:   cleanupBtn
                    text: qsTr("Run Privacy Cleanup")
                    onClicked: {
                        if (typeof privacyViewModel !== 'undefined') {
                            privacyViewModel.runPrivacyCleanup();
                        } else {
                            console.log("[PrivacyPage] runPrivacyCleanup requested — privacyViewModel not registered.");
                        }
                    }
                    FocusRing { target: cleanupBtn }
                    activeFocusOnTab: true
                    Accessible.role: Accessible.Button
                    Accessible.name: qsTr("Run Privacy Cleanup")
                }

                GhostButton {
                    id:   auditBtn
                    text: qsTr("Audit permissions")
                    onClicked: {
                        if (typeof privacyViewModel !== 'undefined') {
                            privacyViewModel.auditPermissions();
                        } else {
                            console.log("[PrivacyPage] auditPermissions requested — privacyViewModel not registered.");
                        }
                    }
                    FocusRing { target: auditBtn }
                    activeFocusOnTab: true
                    Accessible.role: Accessible.Button
                    Accessible.name: qsTr("Audit permissions")
                }

                GhostButton {
                    id:   browserPrivacyBtn
                    text: qsTr("Open browser privacy")
                    onClicked: {
                        if (typeof privacyViewModel !== 'undefined') {
                            privacyViewModel.openBrowserPrivacy();
                        } else {
                            console.log("[PrivacyPage] openBrowserPrivacy requested — privacyViewModel not registered.");
                        }
                    }
                    FocusRing { target: browserPrivacyBtn }
                    activeFocusOnTab: true
                    Accessible.role: Accessible.Button
                    Accessible.name: qsTr("Open browser privacy")
                }
            }

            // Bottom spacer
            Item { width: 1; height: Theme.spacingXL }
        }
    }
}
