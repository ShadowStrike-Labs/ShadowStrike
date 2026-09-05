/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ModuleDetailPage.qml ÔÇö reusable configuration surface for catalog-backed
 * PhantomHome protection modules that do not require a dedicated view model.
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    property int settingsRevision: 0
    property string lastError: ""

    readonly property bool serviceConnected: (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.connected : false
    readonly property bool settingsAvailable: (typeof settingsViewModel !== "undefined" && settingsViewModel !== null)
    readonly property var modulesModel: {
        if (typeof modulesListModel !== "undefined" && modulesListModel !== null)
            return modulesListModel;
        if (typeof protectionViewModel !== "undefined" && protectionViewModel !== null && typeof protectionViewModel.modules !== "undefined")
            return protectionViewModel.modules;
        return null;
    }

    readonly property string moduleId: (root.stack !== null && root.stack.detailModuleId !== undefined) ? root.stack.detailModuleId : ""
    readonly property int moduleIndex: root.findModuleIndex(moduleId)
    readonly property string displayName: root.moduleRole(2, moduleId.length > 0 ? moduleId : qsTr("Protection module"))
    readonly property string iconId: root.moduleRole(3, "shield")
    readonly property int category: root.moduleRole(4, -1)
    readonly property int currentMode: root.moduleRole(5, 0)
    readonly property int supportedModesMask: root.moduleRole(6, 0x0F)
    readonly property int statusHealth: root.moduleRole(8, -1)
    readonly property string statusDetail: root.moduleRole(9, "")
    readonly property bool binary: root.moduleRole(10, false)
    readonly property var moduleProfile: root.profileForModule(root.moduleId, root.category)

    function findModuleIndex(id) {
        if (id.length === 0 || root.modulesModel === null)
            return -1;
        var rows = root.modulesModel.rowCount();
        for (var i = 0; i < rows; ++i) {
            var candidate = root.modulesModel.data(root.modulesModel.index(i, 0), Qt.UserRole + 1);
            if (candidate === id)
                return i;
        }
        return -1;
    }

    function moduleRole(offset, fallback) {
        if (root.moduleIndex < 0 || root.modulesModel === null)
            return fallback;
        var value = root.modulesModel.data(root.modulesModel.index(root.moduleIndex, 0), Qt.UserRole + offset);
        return value === undefined || value === null ? fallback : value;
    }

    function healthState(health) {
        switch (health) {
        case 0:
            return "on";
        case 1:
            return "warning";
        case 2:
            return "critical";
        default:
            return "off";
        }
    }

    function modeLabel(mode) {
        switch (mode) {
        case 0:
            return qsTr("Off");
        case 1:
            return qsTr("Passive");
        case 2:
            return qsTr("Balanced");
        case 3:
            return qsTr("Aggressive");
        default:
            return qsTr("Unknown");
        }
    }

    function categoryLabel(value) {
        switch (value) {
        case 0:
            return qsTr("Realtime protection");
        case 1:
            return qsTr("Behavioral security");
        case 2:
            return qsTr("Network security");
        case 3:
            return qsTr("Web and email");
        case 4:
            return qsTr("Privacy protection");
        case 5:
            return qsTr("Ransomware and backup");
        case 6:
            return qsTr("Specialized protection");
        default:
            return qsTr("Protection module");
        }
    }

    function contains(list, value) {
        return list.indexOf(value) >= 0;
    }

    function profileForModule(id, categoryValue) {
        var realtime = ["AmsiProvider", "SafeBrowsingAPI", "PhishingDetector", "MaliciousDownloadBlocker"];
        var webEmail = ["AdBlocker", "TrackerBlocker", "BrowserProtection", "ChromeExtensionScanner", "FirefoxAddonScanner", "EmailProtection"];
        var network = ["NetworkAttackBlocker", "DNSLeakProtection", "PrivacyIPLeakProtection", "IoTIPLeakProtection", "WiFiSecurityAnalyzer", "RouterSecurityChecker", "PoolConnectionDetector"];
        var privacy = ["WebcamProtector", "MicrophoneGuard", "LocationPrivacy", "CookieManager", "PrivacyCleaner", "DataLeakProtection"];
        var banking = ["BankingTrojanDetector", "CertificatePinning", "KeyloggerProtection", "ScreenshotBlocker", "SecureBrowser", "TransactionMonitor"];
        var backup = ["BackupManager"];
        var usb = ["DeviceControlManager", "BadUSBDetector", "USBAutorunBlocker", "USBDeviceMonitor", "USBScanner"];
        var iot = ["IoTDeviceScanner", "SmartHomeProtection", "IoTIPLeakProtection", "WiFiSecurityAnalyzer", "RouterSecurityChecker"];
        var crypto = ["CryptoMinerDetector", "BrowserMinerDetector", "CPUUsageAnalyzer", "GPUMiningDetector", "PoolConnectionDetector"];
        var game = ["GameProcessDetector", "PerformanceOptimizer", "OverlayProtection", "GameModeManager"];
        var base = [
            {
                title: qsTr("Operational safeguards"),
                subtitle: qsTr("Module-local policy persisted through the protected configuration bridge."),
                items: [
                    {
                        key: "AlertOnEnforcement",
                        label: qsTr("Notify on enforcement"),
                        description: qsTr("Show a local alert when this module blocks or remediates activity."),
                        defaultValue: true,
                        type: "bool"
                    },
                    {
                        key: "AuditTrail",
                        label: qsTr("Write audit events"),
                        description: qsTr("Record policy decisions for reports and incident review."),
                        defaultValue: true,
                        type: "bool"
                    }
                ]
            }
        ];
        if (id === "ZeroTrustGuard" || categoryValue === 1) {
            return {
                family: "behavior",
                summary: qsTr("Runtime behavior and Zero Trust controls for suspicious process activity."),
                sections: base.concat([
                    {
                        title: qsTr("Behavior controls"),
                        subtitle: qsTr("Harden execution decisions before unknown code is trusted."),
                        items: [
                            {
                                key: "BlockUnsignedChildren",
                                label: qsTr("Block unsigned child processes"),
                                description: qsTr("Stop unsigned process trees spawned by monitored applications."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "PromptOnLowTrust",
                                label: qsTr("Prompt on low trust"),
                                description: qsTr("Require user confirmation when trust signals are incomplete."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(realtime, id) || categoryValue === 0) {
            return {
                family: "realtime",
                summary: qsTr("AMSI, file, script, and download inspection controls for the real-time prevention path."),
                sections: base.concat([
                    {
                        title: qsTr("Inspection policy"),
                        subtitle: qsTr("Tune prevention without disabling the module."),
                        items: [
                            {
                                key: "InspectScripts",
                                label: qsTr("Inspect script content"),
                                description: qsTr("Scan PowerShell, JavaScript, and macro content before execution."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "BlockSuspiciousMacros",
                                label: qsTr("Block suspicious macros"),
                                description: qsTr("Prevent Office automation patterns commonly used for initial access."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "CloudReputation",
                                label: qsTr("Use cloud reputation"),
                                description: qsTr("Query reputation for unknown files when the service is connected."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(webEmail, id) || categoryValue === 3) {
            return {
                family: "web-email",
                summary: qsTr("Browser, URL, attachment, phishing, ad, and tracker protection controls."),
                sections: base.concat([
                    {
                        title: qsTr("Web and mail policy"),
                        subtitle: qsTr("Apply controls consistently across browsers and mail clients."),
                        items: [
                            {
                                key: "BlockPhishing",
                                label: qsTr("Block phishing pages"),
                                description: qsTr("Prevent navigation to URLs with phishing or credential-theft indicators."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "ScanAttachments",
                                label: qsTr("Scan email attachments"),
                                description: qsTr("Inspect attachments before they are opened or saved."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "TrackerDefense",
                                label: qsTr("Block trackers"),
                                description: qsTr("Reduce browser tracking surfaces without weakening security telemetry."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(network, id) || categoryValue === 2) {
            return {
                family: "network",
                summary: qsTr("Network Attack Blocker, DNS, IP leak, Wi-Fi, router, and pool-connection defenses."),
                sections: base.concat([
                    {
                        title: qsTr("Network enforcement"),
                        subtitle: qsTr("Control hostile lateral movement and unsafe network exposure."),
                        items: [
                            {
                                key: "BlockLateralMovement",
                                label: qsTr("Block lateral movement"),
                                description: qsTr("Stop suspicious SMB, RPC, and discovery behavior from untrusted sources."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "ProtectDns",
                                label: qsTr("Protect DNS resolution"),
                                description: qsTr("Detect DNS leaks and unsafe resolver changes."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "UntrustedNetworkProfile",
                                label: qsTr("Untrusted network posture"),
                                description: qsTr("Select the default posture when joining an unknown network."),
                                defaultValue: "balanced",
                                type: "choice",
                                options: [
                                    {
                                        label: qsTr("Monitor"),
                                        value: "monitor"
                                    },
                                    {
                                        label: qsTr("Balanced"),
                                        value: "balanced"
                                    },
                                    {
                                        label: qsTr("Strict"),
                                        value: "strict"
                                    }
                                ]
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(privacy, id) || categoryValue === 4) {
            return {
                family: "privacy",
                summary: qsTr("Camera, microphone, location, browser artifact, DNS/IP leak, and data-leak safeguards."),
                sections: base.concat([
                    {
                        title: qsTr("Privacy enforcement"),
                        subtitle: qsTr("Reduce sensitive-data exposure from local applications."),
                        items: [
                            {
                                key: "BlockUnknownApps",
                                label: qsTr("Block unknown applications"),
                                description: qsTr("Deny sensitive device access for unsigned or low-reputation processes."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "NotifyOnAccess",
                                label: qsTr("Notify on sensitive access"),
                                description: qsTr("Show an alert when camera, microphone, location, or private data is accessed."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "RedactTelemetry",
                                label: qsTr("Redact sensitive telemetry"),
                                description: qsTr("Remove private paths and identifiers from module diagnostics."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(backup, id) || categoryValue === 5) {
            return {
                family: "backup",
                summary: qsTr("Ransomware resilience and backup controls for protected data recovery."),
                sections: base.concat([
                    {
                        title: qsTr("Ransomware and backup"),
                        subtitle: qsTr("Keep recovery options available during suspicious file activity."),
                        items: [
                            {
                                key: "ProtectedFolders",
                                label: qsTr("Protect user folders"),
                                description: qsTr("Prioritize Desktop, Documents, Pictures, and configured work folders."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "RollbackSnapshots",
                                label: qsTr("Maintain rollback snapshots"),
                                description: qsTr("Preserve safe restore points for ransomware recovery."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "SnapshotCadence",
                                label: qsTr("Snapshot cadence"),
                                description: qsTr("Select the normal cadence for lightweight backup snapshots."),
                                defaultValue: "daily",
                                type: "choice",
                                options: [
                                    {
                                        label: qsTr("Daily"),
                                        value: "daily"
                                    },
                                    {
                                        label: qsTr("Twice daily"),
                                        value: "twice-daily"
                                    },
                                    {
                                        label: qsTr("On risky changes"),
                                        value: "risk-based"
                                    }
                                ]
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(banking, id)) {
            return {
                family: "banking",
                summary: qsTr("Banking session isolation, certificate, keylogger, screenshot, and transaction defenses."),
                sections: base.concat([
                    {
                        title: qsTr("Banking protection"),
                        subtitle: qsTr("Harden browser and transaction sessions against theft and overlay attacks."),
                        items: [
                            {
                                key: "SecureSessionIsolation",
                                label: qsTr("Isolate secure sessions"),
                                description: qsTr("Separate protected banking sessions from untrusted browser state."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "BlockScreenCapture",
                                label: qsTr("Block screen capture"),
                                description: qsTr("Prevent screenshot and overlay capture during protected sessions."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "ProtectClipboard",
                                label: qsTr("Protect clipboard"),
                                description: qsTr("Detect clipboard replacement and credential interception attempts."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(usb, id)) {
            return {
                family: "usb",
                summary: qsTr("USB device control, BadUSB detection, autorun blocking, monitoring, and scanning."),
                sections: base.concat([
                    {
                        title: qsTr("USB policy"),
                        subtitle: qsTr("Control removable media and suspicious HID behavior."),
                        items: [
                            {
                                key: "ScanOnInsert",
                                label: qsTr("Scan on insert"),
                                description: qsTr("Scan removable storage before files are opened."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "BlockAutorun",
                                label: qsTr("Block autorun"),
                                description: qsTr("Disable autorun and script launch from removable devices."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "RequireTrustedDevices",
                                label: qsTr("Require trusted devices"),
                                description: qsTr("Restrict unknown USB devices until they are approved."),
                                defaultValue: false,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(iot, id)) {
            return {
                family: "iot",
                summary: qsTr("IoT inventory, smart-home, router, Wi-Fi, and IP-leak inspection controls."),
                sections: base.concat([
                    {
                        title: qsTr("IoT discovery"),
                        subtitle: qsTr("Track unmanaged devices and unsafe home-network posture."),
                        items: [
                            {
                                key: "ScanLocalNetwork",
                                label: qsTr("Scan local network"),
                                description: qsTr("Discover new IoT devices without collecting payload content."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "AlertOnNewDevice",
                                label: qsTr("Alert on new devices"),
                                description: qsTr("Notify when a new device appears on trusted networks."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "RouterAudit",
                                label: qsTr("Audit router posture"),
                                description: qsTr("Check router configuration drift and exposed management services."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(crypto, id)) {
            return {
                family: "crypto",
                summary: qsTr("Crypto-miner process, browser, CPU, GPU, and mining-pool detection controls."),
                sections: base.concat([
                    {
                        title: qsTr("Miner detection"),
                        subtitle: qsTr("Detect resource abuse and mining network indicators."),
                        items: [
                            {
                                key: "DetectMiningPools",
                                label: qsTr("Detect mining pools"),
                                description: qsTr("Block known pool protocols and suspicious pool endpoints."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "ThrottleSuspiciousCpu",
                                label: qsTr("Throttle suspicious CPU use"),
                                description: qsTr("Reduce abusive compute activity while evidence is collected."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "BlockBrowserMining",
                                label: qsTr("Block browser mining"),
                                description: qsTr("Stop script-based miners in supported browsers."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        if (root.contains(game, id)) {
            return {
                family: "performance",
                summary: qsTr("Game and performance controls that keep protection active with low user-visible impact."),
                sections: base.concat([
                    {
                        title: qsTr("Game and performance"),
                        subtitle: qsTr("Reduce intrusive work while high-priority applications are active."),
                        items: [
                            {
                                key: "AutoGameMode",
                                label: qsTr("Automatic game mode"),
                                description: qsTr("Detect full-screen games and apply low-interruption protection."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "SuppressNonCriticalAlerts",
                                label: qsTr("Suppress non-critical alerts"),
                                description: qsTr("Delay informational notifications while game mode is active."),
                                defaultValue: true,
                                type: "bool"
                            },
                            {
                                key: "DeferHeavyScans",
                                label: qsTr("Defer heavy scans"),
                                description: qsTr("Postpone expensive scans until system activity drops."),
                                defaultValue: true,
                                type: "bool"
                            }
                        ]
                    }
                ])
            };
        }
        return {
            family: "generic",
            summary: qsTr("Catalog-backed protection module controls."),
            sections: base.concat([
                {
                    title: qsTr("Default policy"),
                    subtitle: qsTr("Safe defaults for modules without a dedicated backend verb."),
                    items: [
                        {
                            key: "PreventiveBlocking",
                            label: qsTr("Preventive blocking"),
                            description: qsTr("Block high-confidence malicious activity automatically."),
                            defaultValue: true,
                            type: "bool"
                        },
                        {
                            key: "UserPrompting",
                            label: qsTr("Prompt on uncertainty"),
                            description: qsTr("Ask before allowing activity that cannot be classified safely."),
                            defaultValue: true,
                            type: "bool"
                        }
                    ]
                }
            ])
        };
    }

    function settingKey(suffix) {
        return "Home/Modules/" + root.moduleId + "/" + suffix;
    }

    function readSetting(suffix, fallback) {
        root.settingsRevision;
        if (!root.settingsAvailable || root.moduleId.length === 0)
            return fallback;
        return settingsViewModel.get(root.settingKey(suffix), fallback);
    }

    function readBool(suffix, fallback) {
        var value = root.readSetting(suffix, fallback);
        if (typeof value === "boolean")
            return value;
        if (typeof value === "number")
            return value !== 0;
        if (typeof value === "string") {
            var normalized = value.toLowerCase();
            return normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "on";
        }
        return fallback;
    }

    function writeSetting(suffix, value) {
        if (!root.settingsAvailable || root.moduleId.length === 0)
            return;
        root.lastError = "";
        settingsViewModel.set(root.settingKey(suffix), value);
    }

    function optionSelected(suffix, fallback, value) {
        return String(root.readSetting(suffix, fallback)) === String(value);
    }

    function setModuleEnabled(enabled) {
        if (root.moduleId.length === 0)
            return;
        if (root.moduleProfile.family === "privacy" && typeof privacyViewModel !== "undefined" && privacyViewModel !== null) {
            privacyViewModel.setModuleEnabled(root.moduleId, enabled);
        } else if (root.modulesModel !== null) {
            root.modulesModel.toggleBinaryModule(root.moduleId, enabled);
        }
    }

    function setModuleMode(mode) {
        if (root.moduleId.length === 0)
            return;
        if (root.moduleProfile.family === "privacy" && typeof privacyViewModel !== "undefined" && privacyViewModel !== null) {
            privacyViewModel.setModuleMode(root.moduleId, mode);
        } else if (root.modulesModel !== null) {
            root.modulesModel.setModuleMode(root.moduleId, mode);
        }
    }

    function refresh() {
        if (root.modulesModel !== null)
            root.modulesModel.refresh();
        if (root.settingsAvailable)
            settingsViewModel.refreshAll();
        if (root.moduleProfile.family === "privacy" && typeof privacyViewModel !== "undefined" && privacyViewModel !== null)
            privacyViewModel.refresh();
    }

    Connections {
        target: root.settingsAvailable ? settingsViewModel : null
        function onSettingChanged(key, value) {
            if (key.indexOf("Home/Modules/" + root.moduleId + "/") === 0)
                root.settingsRevision += 1;
            root.lastError = "";
        }
        function onRequestError(code, message) {
            root.lastError = message && message.length > 0 ? message : qsTr("Settings request failed (%1).").arg(code);
        }
    }

    Connections {
        target: root.modulesModel
        function onRequestError(code, message) {
            root.lastError = message && message.length > 0 ? message : qsTr("Module request failed (%1).").arg(code);
        }
    }

    Component.onCompleted: root.refresh()

    Column {
        anchors.fill: parent
        spacing: 0

        TopBar {
            id: topBar
            width: parent.width
            pageTitle: root.displayName
            showBack: true
            onBackClicked: {
                if (root.stack !== null)
                    root.stack.pop();
            }

            GhostButton {
                text: qsTr("Refresh")
                onClicked: root.refresh()
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
                    active: root.moduleId.length === 0 || root.moduleIndex < 0
                    sourceComponent: EmptyState {
                        title: qsTr("Module details unavailable")
                        message: qsTr("The selected module is not present in the live module inventory. Refresh the protection state and try again.")
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

                Card {
                    width: parent.width - Theme.spacingL * 2
                    glow: true
                    accent: Theme.accentCyan
                    visible: root.moduleIndex >= 0

                    Column {
                        width: parent.width
                        spacing: Theme.spacingM

                        Row {
                            width: parent.width
                            spacing: Theme.spacingM

                            Column {
                                width: parent.width - moduleToggle.implicitWidth - Theme.spacingM
                                spacing: Theme.spacingXS

                                Text {
                                    text: root.displayName
                                    color: Theme.textPrimary
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSizeTitle
                                    font.weight: Theme.fontWeightBold
                                    elide: Text.ElideRight
                                    width: parent.width
                                }

                                Text {
                                    text: root.moduleProfile.summary
                                    color: Theme.textSecondary
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSizeBody
                                    wrapMode: Text.WordWrap
                                    width: parent.width
                                }
                            }

                            ToggleSwitch {
                                id: moduleToggle
                                checked: root.currentMode > 0
                                enabled: root.serviceConnected
                                anchors.verticalCenter: parent.verticalCenter
                                onToggled: function (newValue) {
                                    root.setModuleEnabled(newValue);
                                }
                            }
                        }

                        Flow {
                            width: parent.width
                            spacing: Theme.spacingS

                            StatusChip {
                                state: root.healthState(root.statusHealth)
                                label: root.healthState(root.statusHealth) === "on" ? qsTr("Healthy") : root.healthState(root.statusHealth)
                            }
                            StatusChip {
                                state: root.serviceConnected ? "on" : "offline"
                                label: root.serviceConnected ? qsTr("Service connected") : qsTr("Service offline")
                            }
                            StatusChip {
                                state: root.currentMode > 0 ? "on" : "off"
                                label: qsTr("Mode: %1").arg(root.modeLabel(root.currentMode))
                            }
                            StatusChip {
                                state: "on"
                                label: root.categoryLabel(root.category)
                            }
                        }

                        Text {
                            visible: root.statusDetail.length > 0
                            text: root.statusDetail
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                            wrapMode: Text.WordWrap
                            width: parent.width
                        }

                        ModePillRow {
                            visible: !root.binary
                            enabled: root.serviceConnected
                            opacity: enabled ? 1.0 : Theme.disabledOpacity
                            currentMode: root.currentMode
                            supportedModesMask: root.supportedModesMask
                            onModeChosen: function (mode) {
                                root.setModuleMode(mode);
                            }
                        }
                    }
                }

                Loader {
                    width: parent.width - Theme.spacingL * 2
                    active: root.moduleProfile.family === "privacy" && typeof privacyViewModel !== "undefined" && privacyViewModel !== null
                    sourceComponent: Card {
                        Column {
                            width: parent.width
                            spacing: Theme.spacingM

                            SectionTitle {
                                text: qsTr("Privacy telemetry")
                                subtitle: qsTr("Live counters from the privacy view model.")
                                width: parent.width
                            }

                            Flow {
                                width: parent.width
                                spacing: Theme.spacingS
                                StatusChip {
                                    state: "on"
                                    label: qsTr("Webcam blocked: %1").arg(privacyViewModel.webcamAccessBlocked)
                                }
                                StatusChip {
                                    state: "on"
                                    label: qsTr("Mic blocked: %1").arg(privacyViewModel.micAccessBlocked)
                                }
                                StatusChip {
                                    state: "on"
                                    label: qsTr("Location blocked: %1").arg(privacyViewModel.locationAccessBlocked)
                                }
                                StatusChip {
                                    state: "on"
                                    label: qsTr("Cookies cleaned: %1").arg(privacyViewModel.cookiesBlocked)
                                }
                            }

                            Row {
                                spacing: Theme.spacingS
                                GhostButton {
                                    text: qsTr("Run cleanup")
                                    onClicked: privacyViewModel.runPrivacyCleanup()
                                }
                                GhostButton {
                                    text: qsTr("Audit permissions")
                                    onClicked: privacyViewModel.auditPermissions()
                                }
                            }
                        }
                    }
                }

                Repeater {
                    model: root.moduleProfile.sections

                    delegate: Column {
                        required property var modelData
                        width: parent.width - Theme.spacingL * 2
                        spacing: Theme.spacingM
                        visible: root.moduleIndex >= 0

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
                                        id: configItem
                                        required property var modelData

                                        width: parent.width
                                        height: configColumn.implicitHeight + Theme.spacingM * 2

                                        Rectangle {
                                            anchors.bottom: parent.bottom
                                            width: parent.width
                                            height: 1
                                            color: Theme.strokeSubtle
                                        }

                                        Column {
                                            id: configColumn
                                            anchors {
                                                left: parent.left
                                                right: parent.right
                                                verticalCenter: parent.verticalCenter
                                            }
                                            spacing: Theme.spacingS

                                            Row {
                                                width: parent.width
                                                spacing: Theme.spacingM

                                                Column {
                                                    width: parent.width - boolToggle.implicitWidth - Theme.spacingM
                                                    spacing: 2

                                                    Text {
                                                        text: configItem.modelData.label
                                                        color: Theme.textPrimary
                                                        font.family: Theme.fontFamily
                                                        font.pixelSize: Theme.fontSizeBody
                                                        font.weight: Theme.fontWeightMedium
                                                        width: parent.width
                                                        wrapMode: Text.WordWrap
                                                    }

                                                    Text {
                                                        text: configItem.modelData.description
                                                        color: Theme.textSecondary
                                                        font.family: Theme.fontFamily
                                                        font.pixelSize: Theme.fontSizeLabel
                                                        wrapMode: Text.WordWrap
                                                        width: parent.width
                                                    }
                                                }

                                                ToggleSwitch {
                                                    id: boolToggle
                                                    visible: configItem.modelData.type !== "choice"
                                                    checked: root.readBool(configItem.modelData.key, configItem.modelData.defaultValue)
                                                    enabled: root.settingsAvailable
                                                    anchors.verticalCenter: parent.verticalCenter
                                                    onToggled: function (newValue) {
                                                        root.writeSetting(configItem.modelData.key, newValue);
                                                    }
                                                }
                                            }

                                            Flow {
                                                visible: configItem.modelData.type === "choice"
                                                width: parent.width
                                                spacing: Theme.spacingS

                                                Repeater {
                                                    model: configItem.modelData.options || []
                                                    delegate: GhostButton {
                                                        required property var modelData
                                                        text: (root.optionSelected(configItem.modelData.key, configItem.modelData.defaultValue, modelData.value) ? "Ô£ô " : "") + modelData.label
                                                        enabled: root.settingsAvailable
                                                        onClicked: root.writeSetting(configItem.modelData.key, modelData.value)
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

                Item {
                    width: 1
                    height: Theme.spacingL
                }
            }
        }
    }
}
