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
    property int webcamAccessBlocked:    0
    property int micAccessBlocked:       0
    property int locationAccessBlocked:  0
    property int cookiesBlocked:         0

    // -------------------------------------------------------------------------
    // Active privacy modules (if modulesListModel is not available, show static)
    // -------------------------------------------------------------------------
    readonly property var staticPrivacyModules: [
        { name: qsTr("WebcamProtector"),       description: qsTr("Blocks unauthorized webcam access"), enabled: true  },
        { name: qsTr("MicrophoneGuard"),        description: qsTr("Prevents silent microphone capture"),  enabled: true  },
        { name: qsTr("LocationPrivacy"),        description: qsTr("Masks precise location from apps"),    enabled: true  },
        { name: qsTr("CookieManager"),          description: qsTr("Cleans tracking cookies on close"),    enabled: false },
        { name: qsTr("DNSLeakProtection"),      description: qsTr("Routes DNS through secure resolver"),  enabled: true  },
        { name: qsTr("IPLeakProtection"),       description: qsTr("Prevents real IP exposure via WebRTC"),enabled: true  },
        { name: qsTr("DataLeakProtection"),     description: qsTr("Monitors clipboard and file transfers"),enabled: false },
        { name: qsTr("PrivacyCleaner"),         description: qsTr("Erases browsing artifacts on demand"), enabled: true  },
    ]

    // -------------------------------------------------------------------------
    // Recent privacy events (updated by VM binding if available)
    // -------------------------------------------------------------------------
    property var recentPrivacyEvents: []

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
                model: root.staticPrivacyModules
                delegate: ModuleCard {
                    width:            parent.width - Theme.spacingL * 2
                    moduleName:       modelData.name
                    moduleDescription: modelData.description
                    enabled:          modelData.enabled
                    onToggled: function(nowEnabled) {
                        if (typeof modulesListModel !== 'undefined') {
                            modulesListModel.setEnabled(modelData.name, nowEnabled);
                        } else {
                            // TODO: wire to modulesListModel.setEnabled once the VM is authored.
                            console.log("[PrivacyPage] toggle", modelData.name, "→", nowEnabled,
                                        "— modulesListModel not yet registered.");
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
                    icon:    "shield"
                    title:   qsTr("No recent events")
                    message: qsTr("All privacy sensors are quiet. No suspicious access attempts detected.")
                }
            }

            Repeater {
                model: root.recentPrivacyEvents
                delegate: ThreatRow {
                    width:            parent.width - Theme.spacingL * 2
                    threatName:       modelData.threatName   || ""
                    filePath:         modelData.filePath     || ""
                    action:           modelData.action       || "blocked"
                    timestampDisplay: modelData.timestamp    || ""
                    severity:         modelData.severity     || "warning"
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
                            // TODO: wire to privacyViewModel.runPrivacyCleanup once the VM is authored.
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
                            // TODO: wire to privacyViewModel.auditPermissions once the VM is authored.
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
                            // TODO: wire to privacyViewModel.openBrowserPrivacy once the VM is authored.
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
