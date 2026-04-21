import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * SecurityPage
 * ------------
 * Kaspersky-class module control surface. Modules are grouped by their
 * `group` tag (Realtime / Web / Ransomware / Privacy / ...) and each
 * module is rendered as a ModuleCard with status dot, description,
 * master toggle and a fine-tune gear that opens ModuleSettingsDialog.
 *
 * The page is read-only above the fold until the view-model delivers
 * its first list of modules. The small "Default action" card at the
 * bottom sets the service-wide fallback policy; per-module action is
 * configurable inside the fine-tune dialog.
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
    // Presentation metadata for well-known modules. The service delivers
    // a minimal {id, displayName, group, state, enabled} record — the
    // human description and icon for each module live on the UI side so
    // copy can be tuned without touching the service ABI.
    //
    // Unknown module ids fall back to the generic icon and a default
    // description. This keeps the page forward-compatible with new
    // modules added in later releases.
    // ------------------------------------------------------------------
    readonly property var moduleMeta: ({
        "RansomwareProtection": {
            glyph: "\uD83D\uDD12",
            desc:  qsTr("Monitors filesystem activity for mass-encryption patterns and rolls back files that get tampered with.")
        },
        "RealTimeProtection": {
            glyph: "\u26E1",
            desc:  qsTr("On-access scanner. Every file opened, created or executed is inspected by signature, heuristic and ML layers.")
        },
        "WebProtection": {
            glyph: "\uD83C\uDF10",
            desc:  qsTr("Blocks malicious URLs, drive-by downloads, phishing sites, and unsafe TLS certificates.")
        },
        "EmailProtection": {
            glyph: "\u2709",
            desc:  qsTr("Scans inbound mail clients for malicious attachments and phishing indicators.")
        },
        "BankingProtection": {
            glyph: "\uD83D\uDCB3",
            desc:  qsTr("Hardened browser for online banking. Blocks keyloggers, screen-capture and DLL injection into financial sites.")
        },
        "PrivacyProtection": {
            glyph: "\uD83D\uDC41",
            desc:  qsTr("Stops apps from reading your webcam, microphone and clipboard without permission.")
        },
        "ExploitProtection": {
            glyph: "\u26A1",
            desc:  qsTr("Kernel-assisted mitigations for memory-corruption exploits in everyday apps (browsers, office, PDF).")
        },
        "ScriptProtection": {
            glyph: "\u276F_",
            desc:  qsTr("Inspects PowerShell, JavaScript and macro content for malicious behaviour before it executes.")
        },
        "NetworkProtection": {
            glyph: "\uD83D\uDEE1",
            desc:  qsTr("Firewall + intrusion prevention for inbound / outbound traffic. Blocks known C2 infrastructure.")
        },
        "USBProtection": {
            glyph: "\u21AF",
            desc:  qsTr("Scans removable media on insert and blocks known auto-run attacks.")
        },
        "IoTProtection": {
            glyph: "\uD83C\uDFE0",
            desc:  qsTr("Discovers and inventories devices on your home network; flags unsafe device states.")
        },
        "PasswordProtection": {
            glyph: "\uD83D\uDD11",
            desc:  qsTr("Detects password-stealer malware and prevents credential exfiltration from browsers.")
        }
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
            glyph: "\u25A0",
            desc:  qsTr("Enterprise-grade protection module. Enable to include this layer in your defence-in-depth posture.")
        };
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
        // Render known groups in curated order first, then trailing unknowns alphabetical.
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

    ButtonGroup { id: actionGroup }

    // ------------------------------------------------------------------
    // Per-module fine-tune dialog (single instance; re-used for every
    // module). Instantiated once so its visual transitions stay crisp.
    // ------------------------------------------------------------------
    ModuleSettingsDialog {
        id: settingsDialog
        parent: page
        onApplied: function(payload) {
            // Master toggle delta always goes through setModuleEnabled,
            // action delta through setDetectionAction. Sensitivity +
            // exclusions are forwarded as a generic configure payload
            // that the view-model maps to SetModuleConfig IPC.
            if (payload && payload.id) {
                page.setModuleEnabled(payload.id, payload.enabled === true)
                if (payload.action !== undefined) {
                    page.setDetectionAction(payload.id, payload.action)
                }
                page.configureModule(payload.id, payload)
            }
        }
    }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            // --- Page header -------------------------------------------
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
                    text: qsTr("Each protection layer can be toggled and fine-tuned independently. Configuration is applied live — no restart required.")
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    wrapMode: Text.WordWrap
                    width: parent.width
                }
            }

            // --- Empty state -------------------------------------------
            Text {
                visible: page.modules.length === 0
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                text: qsTr("Loading protection modules from the Phantom service\u2026")
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontBody
            }

            // --- Grouped module cards ----------------------------------
            Repeater {
                model: page.modulesByGroup()
                delegate: ColumnLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    spacing: Theme.sp3

                    // Group header.
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp2
                        Layout.topMargin: Theme.sp3
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
                            glyph:       page.metaFor(modelData.id).glyph
                            state:       modelData.state
                            enabled:     modelData.enabled === true

                            onToggled: function(on) { page.setModuleEnabled(modelData.id, on) }
                            onConfigureRequested: {
                                settingsDialog.moduleId    = modelData.id
                                settingsDialog.displayName = modelData.displayName
                                settingsDialog.description = page.metaFor(modelData.id).desc
                                settingsDialog.moduleEnabled = modelData.enabled === true
                                settingsDialog.sensitivity = 1
                                settingsDialog.action      = 1
                                settingsDialog.exclusions  = ""
                                settingsDialog.open()
                            }
                        }
                    }
                }
            }

            // --- Default detection action ------------------------------
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
