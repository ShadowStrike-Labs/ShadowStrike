import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"
import "detail"

/*
 * PrivacyPage
 * -----------
 * Privacy posture summary, Privacy-group module grid with drill-down,
 * and a tracker/telemetry configuration section.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Privacy")

    // Legacy toggles retained for backwards compatibility with older
    // callers — the new layout routes all privacy configuration through
    // the ModuleCard drill-down and the tracker/telemetry card.
    property bool webcamBlocked:     false
    property bool dnsLeakProtection: true
    property bool ipLeakProtection:  true
    property bool trackerBlocker:    true

    // Wired from App.qml via ProtectionViewModel.
    property var modules:      []
    property var recentEvents: []

    signal setToggle(string id, bool on)
    signal configureModule(string id, var payload)

    // --- Derived summaries --------------------------------------------
    function _privacyModules() {
        var out = [];
        for (var i = 0; i < modules.length; ++i) {
            var m = modules[i];
            if (m && m.group === "Privacy") out.push(m);
        }
        return out;
    }
    function _privacyEnabledCount() {
        var mods = _privacyModules();
        var c = 0;
        for (var i = 0; i < mods.length; ++i) if (mods[i].enabled === true) ++c;
        return c;
    }
    function _privacyBlockedThisWeek() {
        // We don't yet have a module→group map for events; approximate
        // by counting events whose module name contains "Privacy" /
        // "Tracker" / "Webcam" — a safe superset.
        var c = 0;
        var cutoff = Math.floor(Date.now() / 1000) - 7 * 86400;
        for (var i = 0; i < recentEvents.length; ++i) {
            var e = recentEvents[i];
            if (!e) continue;
            if (e.timeUnix && e.timeUnix < cutoff) continue;
            var mod = String(e.module || "").toLowerCase();
            if (mod.indexOf("privacy") >= 0 ||
                mod.indexOf("tracker") >= 0 ||
                mod.indexOf("webcam") >= 0) {
                ++c;
            }
        }
        return c;
    }

    // --- Module presentation metadata (mirrors SecurityPage) ----------
    readonly property var moduleMeta: ({
        "PrivacyProtection":  { icon: "eye",  desc: qsTr("Stops apps from reading your webcam, microphone and clipboard without permission.") },
        "PasswordProtection": { icon: "key",  desc: qsTr("Detects password-stealer malware and prevents credential exfiltration from browsers.") },
        "IdentityProtection": { icon: "user", desc: qsTr("Monitors dark-web credential leaks and alerts when your accounts appear in public breaches.") }
    })
    function metaFor(id) {
        var m = moduleMeta[id];
        if (m) return m;
        return { icon: "eye", desc: qsTr("Privacy protection layer. Toggle to include in your posture.") };
    }

    // --- Tracker / telemetry edit state -------------------------------
    property int  _telemetryLevel:     1          // 0=Off, 1=Essential, 2=Detailed
    property bool _blockCookies:       true
    property bool _hideUserAgent:      false
    property bool _blockFingerprinting: true

    function _resetTrackerDefaults() {
        _telemetryLevel      = 1;
        _blockCookies        = true;
        _hideUserAgent       = false;
        _blockFingerprinting = true;
    }

    ButtonGroup { id: telemetryGroup }

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

    Component {
        id: listComponent

        ScrollView {
            id: scroller
            clip: true

            ColumnLayout {
                width: scroller.availableWidth
                spacing: Theme.sp5

                // ---- Page header --------------------------------
                Column {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.sp6
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    spacing: 4
                    Text { text: qsTr("Privacy"); color: Theme.textStrong
                           font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
                           font.weight: Font.DemiBold }
                    Text { text: qsTr("Webcam, microphone, identity and tracker defences.")
                           color: Theme.textMuted
                           font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody }
                }

                // ---- Privacy posture ----------------------------
                CardFrame {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    title: qsTr("Privacy posture")
                    subtitle: qsTr("A snapshot of your privacy protections over the last week.")

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: Theme.sp3
                        spacing: Theme.sp8

                        Column {
                            spacing: 2
                            Text { text: page._privacyEnabledCount()
                                   color: Theme.textStrong
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontDisplay
                                   font.weight: Font.Bold }
                            Text { text: qsTr("Privacy modules enabled")
                                   color: Theme.textMuted
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontSmall }
                        }
                        Rectangle { width: 1; Layout.preferredHeight: 48; color: Qt.rgba(1,1,1,0.08) }
                        Column {
                            spacing: 2
                            Text { text: page._privacyBlockedThisWeek()
                                   color: Theme.textStrong
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontDisplay
                                   font.weight: Font.Bold }
                            Text { text: qsTr("Blocked this week")
                                   color: Theme.textMuted
                                   font.family: Theme.fontFamily
                                   font.pixelSize: Theme.fontSmall }
                        }
                        Item { Layout.fillWidth: true }
                    }
                }

                // ---- Privacy modules grid -----------------------
                SectionHeader {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    sectionTitle: qsTr("Privacy modules")
                    count: page._privacyModules().length
                }

                Text {
                    visible: page._privacyModules().length === 0
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    text: qsTr("No privacy modules reported yet. Waiting for the Phantom service\u2026")
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                }

                GridLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    columns: 2
                    rowSpacing: Theme.sp3
                    columnSpacing: Theme.sp3

                    Repeater {
                        model: page._privacyModules()
                        delegate: ModuleCard {
                            moduleId:    modelData.id
                            displayName: modelData.displayName
                            description: page.metaFor(modelData.id).desc
                            iconName:    page.metaFor(modelData.id).icon
                            state:       modelData.state
                            enabled:     modelData.enabled

                            onToggled: (on) => page.setToggle(moduleId, on)
                            onConfigureRequested: page.configureModule(moduleId, {})
                            onDetailRequested: {
                                stack.push(detailComponent, {
                                    moduleId:      moduleId,
                                    displayName:   displayName,
                                    description:   description,
                                    iconName:      iconName,
                                    state:         state,
                                    moduleEnabled: enabled
                                });
                            }
                        }
                    }
                }

                // ---- Tracker & telemetry ------------------------
                CardFrame {
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.sp8
                    Layout.rightMargin: Theme.sp8
                    Layout.bottomMargin: Theme.sp6
                    title: qsTr("Tracker & telemetry")
                    subtitle: qsTr("Control how much information leaves your device.")

                    Text {
                        Layout.fillWidth: true
                        Layout.topMargin: Theme.sp3
                        text: qsTr("Telemetry level")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSmall
                        font.weight: Font.DemiBold
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp4
                        RadioButton {
                            text: qsTr("Off")
                            ButtonGroup.group: telemetryGroup
                            checked: page._telemetryLevel === 0
                            onClicked: page._telemetryLevel = 0
                        }
                        RadioButton {
                            text: qsTr("Essential")
                            ButtonGroup.group: telemetryGroup
                            checked: page._telemetryLevel === 1
                            onClicked: page._telemetryLevel = 1
                        }
                        RadioButton {
                            text: qsTr("Detailed")
                            ButtonGroup.group: telemetryGroup
                            checked: page._telemetryLevel === 2
                            onClicked: page._telemetryLevel = 2
                        }
                        Item { Layout.fillWidth: true }
                    }

                    CheckBox {
                        text: qsTr("Block third-party cookies")
                        checked: page._blockCookies
                        onToggled: page._blockCookies = checked
                    }
                    CheckBox {
                        text: qsTr("Hide user agent")
                        checked: page._hideUserAgent
                        onToggled: page._hideUserAgent = checked
                    }
                    CheckBox {
                        text: qsTr("Block fingerprinting scripts")
                        checked: page._blockFingerprinting
                        onToggled: page._blockFingerprinting = checked
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: Theme.sp3
                        spacing: Theme.sp3
                        Item { Layout.fillWidth: true }
                        SecondaryButton {
                            text: qsTr("Revert")
                            onClicked: page._resetTrackerDefaults()
                        }
                        PrimaryButton {
                            text: qsTr("Apply settings")
                            onClicked: page.configureModule("PrivacyProtection", {
                                telemetryLevel:       page._telemetryLevel,
                                blockCookies:         page._blockCookies,
                                hideUserAgent:        page._hideUserAgent,
                                blockFingerprinting:  page._blockFingerprinting
                            })
                        }
                    }
                }

                Item { Layout.fillHeight: true; implicitHeight: 1 }
            }
        }
    }

    Component {
        id: detailComponent
        GenericModuleDetailPage {
            onBackRequested: stack.pop()
            onApplied: function(payload) {
                if (payload && payload.id) {
                    page.setToggle(payload.id, payload.enabled === true);
                    page.configureModule(payload.id, payload);
                }
                stack.pop();
            }
        }
    }
}
