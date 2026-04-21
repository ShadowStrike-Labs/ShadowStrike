import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"
import "detail"

/*
 * SecurityPage
 * ------------
 * Kaspersky-class module control surface. Modules are grouped by their
 * `group` tag (Realtime / Web / Ransomware / Privacy / ...) and each
 * module is rendered as a ModuleCard with status dot, description,
 * master toggle and a fine-tune gear.
 *
 * The page hosts an internal StackView so clicking a tile's body pushes
 * a GenericModuleDetailPage onto the stack. The detail page exposes
 * sensitivity, action, exclusions and master toggle with Apply / Revert.
 * The cog on the list tile still opens the legacy ModuleSettingsDialog
 * for users who prefer the compact dialog.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Security modules")

    // Each module: { id, displayName, enabled, state, group }
    property var modules: []

    signal setModuleEnabled(string moduleId, bool enabled)
    signal setDetectionAction(string moduleId, int action)
    signal configureModule(string moduleId, var payload)

    // ------------------------------------------------------------------
    // Presentation metadata. The service delivers a minimal record, so
    // human descriptions and icon identifiers live on the UI side.
    // ------------------------------------------------------------------
    readonly property var moduleMeta: ({
        "RealTimeProtection":    { icon: "radar",   desc: qsTr("On-access scanner. Every file opened, created or executed is inspected by signature, heuristic and ML layers.") },
        "RansomwareProtection":  { icon: "lock",    desc: qsTr("Monitors filesystem activity for mass-encryption patterns and rolls back files that get tampered with.") },
        "WebProtection":         { icon: "globe",   desc: qsTr("Blocks malicious URLs, drive-by downloads, phishing sites, and unsafe TLS certificates.") },
        "EmailProtection":       { icon: "mail",    desc: qsTr("Scans inbound mail clients for malicious attachments and phishing indicators.") },
        "BankingProtection":     { icon: "card",    desc: qsTr("Hardened browser for online banking. Blocks keyloggers, screen-capture and DLL injection into financial sites.") },
        "PrivacyProtection":     { icon: "eye",     desc: qsTr("Stops apps from reading your webcam, microphone and clipboard without permission.") },
        "ExploitProtection":     { icon: "bolt",    desc: qsTr("Kernel-assisted mitigations for memory-corruption exploits in everyday apps (browsers, office, PDF).") },
        "ScriptProtection":      { icon: "code",    desc: qsTr("Inspects PowerShell, JavaScript and macro content for malicious behaviour before it executes.") },
        "NetworkProtection":     { icon: "network", desc: qsTr("Firewall + intrusion prevention for inbound / outbound traffic. Blocks known C2 infrastructure.") },
        "USBProtection":         { icon: "usb",     desc: qsTr("Scans removable media on insert and blocks known auto-run attacks.") },
        "IoTProtection":         { icon: "home",    desc: qsTr("Discovers and inventories devices on your home network; flags unsafe device states.") },
        "PasswordProtection":    { icon: "key",     desc: qsTr("Detects password-stealer malware and prevents credential exfiltration from browsers.") },
        "IdentityProtection":    { icon: "user",    desc: qsTr("Monitors dark-web credential leaks and alerts when your accounts appear in public breaches.") }
    })

    readonly property var groupIcon: ({
        "Realtime":   "radar",
        "Ransomware": "lock",
        "Web":        "globe",
        "Network":    "network",
        "Privacy":    "eye",
        "Exploit":    "bolt",
        "Script":     "code",
        "USB":        "usb",
        "IoT":        "home",
        "Banking":    "card",
        "Email":      "mail",
        "Identity":   "user",
        "Other":      "shield"
    })

    readonly property var groupOrder: [
        "Realtime", "Ransomware", "Web", "Network", "Privacy",
        "Exploit", "Script", "USB", "IoT", "Banking", "Email",
        "Identity", "Other"
    ]

    function metaFor(id) {
        var m = moduleMeta[id];
        if (m) return m;
        return {
            icon: "shield",
            desc: qsTr("Enterprise-grade protection module. Enable to include this layer in your defence-in-depth posture.")
        };
    }

    function iconForGroup(g) {
        return groupIcon[g] || "shield";
    }

    function groupFor(m) {
        var g = (m && m.group) ? m.group : "Other";
        return g.length ? g : "Other";
    }

    function modulesByGroup() {
        var byGroup = {};
        for (var i = 0; i < modules.length; ++i) {
            var m = modules[i];
            var g = groupFor(m);
            if (!byGroup[g]) byGroup[g] = [];
            byGroup[g].push(m);
        }
        var out = [];
        var seen = {};
        for (var k = 0; k < groupOrder.length; ++k) {
            var gn = groupOrder[k];
            if (byGroup[gn]) {
                out.push({ name: gn, items: byGroup[gn] });
                seen[gn] = true;
            }
        }
        var rest = [];
        for (var key in byGroup) if (!seen[key]) rest.push(key);
        rest.sort();
        for (var j = 0; j < rest.length; ++j) {
            out.push({ name: rest[j], items: byGroup[rest[j]] });
        }
        return out;
    }

    // Settings dialog still available from the cog for power users.
    ModuleSettingsDialog {
        id: settingsDialog
        parent: page
        onApplied: function(payload) {
            if (payload && payload.id) {
                page.setModuleEnabled(payload.id, payload.enabled === true)
                if (payload.action !== undefined) {
                    page.setDetectionAction(payload.id, payload.action)
                }
                page.configureModule(payload.id, payload)
            }
        }
    }

    // ------------------------------------------------------------------
    // StackView: list root ↔ detail drill-down.
    // ------------------------------------------------------------------
    StackView {
        id: stack
        anchors.fill: parent
        initialItem: listComponent
        clip: true

        pushEnter: Transition {
            ParallelAnimation {
                PropertyAnimation { property: "x"; from: stack.width * 0.25; to: 0; duration: Theme.motionNormal; easing.type: Easing.OutCubic }
                PropertyAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.motionNormal }
            }
        }
        popExit: Transition {
            ParallelAnimation {
                PropertyAnimation { property: "x"; from: 0; to: stack.width * 0.25; duration: Theme.motionNormal; easing.type: Easing.InCubic }
                PropertyAnimation { property: "opacity"; from: 1; to: 0; duration: Theme.motionNormal }
            }
        }
    }

    // ------------------------------------------------------------------
    // List (root) page.
    // ------------------------------------------------------------------
    Component {
        id: listComponent

        Item {
            ButtonGroup { id: actionGroup }

            ScrollView {
                anchors.fill: parent
                clip: true

                ColumnLayout {
                    width: page.width - 2
                    spacing: Theme.sp5

                    // --- Page header ----------------------------------
                    Column {
                        Layout.fillWidth: true
                        Layout.topMargin: Theme.sp6
                        Layout.leftMargin: Theme.sp8
                        Layout.rightMargin: Theme.sp8
                        spacing: 4
                        Text {
                            text: qsTr("Protection modules")
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontTitle
                            font.weight: Font.DemiBold
                        }
                        Text {
                            text: qsTr("Each protection layer can be toggled and fine-tuned independently. Click a module to open its full settings — the gear opens the compact dialog.")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontBody
                            wrapMode: Text.WordWrap
                            width: parent.width
                        }
                    }

                    // --- Empty state ----------------------------------
                    Text {
                        visible: page.modules.length === 0
                        Layout.leftMargin: Theme.sp8
                        Layout.rightMargin: Theme.sp8
                        text: qsTr("Loading protection modules from the Phantom service\u2026")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                    }

                    // --- Grouped module cards -------------------------
                    Repeater {
                        model: page.modulesByGroup()
                        delegate: ColumnLayout {
                            Layout.fillWidth: true
                            Layout.leftMargin: Theme.sp8
                            Layout.rightMargin: Theme.sp8
                            spacing: Theme.sp3

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.sp2
                                Layout.topMargin: Theme.sp3

                                Iconed {
                                    iconName: page.iconForGroup(modelData.name)
                                    size: 14
                                    tint: Theme.accentAlt
                                }
                                Text {
                                    text: modelData.name
                                    color: Theme.accentAlt
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontSmall
                                    font.weight: Font.DemiBold
                                    font.capitalization: Font.AllUppercase
                                    font.letterSpacing: 1.2
                                }
                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.alignment: Qt.AlignVCenter
                                    height: 1
                                    color: Theme.strokeSoft
                                }
                                Text {
                                    text: qsTr("%1 modules").arg(modelData.items.length)
                                    color: Theme.textMuted
                                    font.family: Theme.fontFamily
                                    font.pixelSize: Theme.fontCaption
                                }
                            }

                            Repeater {
                                model: modelData.items
                                delegate: ModuleCard {
                                    moduleId:    modelData.id
                                    displayName: modelData.displayName
                                    description: page.metaFor(modelData.id).desc
                                    iconName:    page.metaFor(modelData.id).icon
                                    state:       modelData.state
                                    enabled:     modelData.enabled === true

                                    onToggled: function(on) { page.setModuleEnabled(modelData.id, on) }
                                    onConfigureRequested: {
                                        settingsDialog.moduleId      = modelData.id
                                        settingsDialog.displayName   = modelData.displayName
                                        settingsDialog.description   = page.metaFor(modelData.id).desc
                                        settingsDialog.moduleEnabled = modelData.enabled === true
                                        settingsDialog.sensitivity   = 1
                                        settingsDialog.action        = 1
                                        settingsDialog.exclusions    = ""
                                        settingsDialog.open()
                                    }
                                    onDetailRequested: {
                                        var detail = stack.push("detail/GenericModuleDetailPage.qml", {
                                            moduleId:      modelData.id,
                                            displayName:   modelData.displayName,
                                            description:   page.metaFor(modelData.id).desc,
                                            iconName:      page.metaFor(modelData.id).icon,
                                            state:         modelData.state,
                                            moduleEnabled: modelData.enabled === true,
                                            sensitivity:   1,
                                            action:        1,
                                            exclusions:    ""
                                        });
                                        if (detail) {
                                            detail.backRequested.connect(function() { stack.pop() });
                                            detail.applied.connect(function(payload) {
                                                if (!payload || !payload.id) return;
                                                page.setModuleEnabled(payload.id, payload.enabled === true);
                                                if (payload.action !== undefined) {
                                                    page.setDetectionAction(payload.id, payload.action);
                                                }
                                                page.configureModule(payload.id, payload);
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // --- Default detection action ---------------------
                    CardFrame {
                        Layout.fillWidth: true
                        Layout.leftMargin: Theme.sp8
                        Layout.rightMargin: Theme.sp8
                        Layout.topMargin: Theme.sp4
                        Layout.bottomMargin: Theme.sp6
                        title: qsTr("Default action on detection")
                        subtitle: qsTr("Applied when a module has no explicit action configured. Per-module overrides take priority.")

                        RadioButton { ButtonGroup.group: actionGroup; text: qsTr("Ask me")
                            focusPolicy: Qt.StrongFocus
                            Accessible.role: Accessible.RadioButton
                            Accessible.name: qsTr("Ask me on detection")
                            contentItem: Text {
                                leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                                verticalAlignment: Text.AlignVCenter
                                text: parent.text; color: Theme.text
                                font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                            }
                        }
                        RadioButton { ButtonGroup.group: actionGroup; text: qsTr("Quarantine (recommended)"); checked: true
                            focusPolicy: Qt.StrongFocus
                            Accessible.role: Accessible.RadioButton
                            Accessible.name: qsTr("Quarantine on detection")
                            contentItem: Text {
                                leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                                verticalAlignment: Text.AlignVCenter
                                text: parent.text; color: Theme.text
                                font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                            }
                        }
                        RadioButton { ButtonGroup.group: actionGroup; text: qsTr("Delete")
                            focusPolicy: Qt.StrongFocus
                            Accessible.role: Accessible.RadioButton
                            Accessible.name: qsTr("Delete on detection")
                            contentItem: Text {
                                leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                                verticalAlignment: Text.AlignVCenter
                                text: parent.text; color: Theme.text
                                font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                            }
                        }
                        RadioButton { ButtonGroup.group: actionGroup; text: qsTr("Log only")
                            focusPolicy: Qt.StrongFocus
                            Accessible.role: Accessible.RadioButton
                            Accessible.name: qsTr("Log only on detection")
                            contentItem: Text {
                                leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                                verticalAlignment: Text.AlignVCenter
                                text: parent.text; color: Theme.text
                                font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                            }
                        }
                    }

                    Item { Layout.fillHeight: true }
                }
            }
        }
    }
}
