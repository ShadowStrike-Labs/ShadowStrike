import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * SettingsPage
 * ------------
 * Sectioned accordion: General, Updates, Exclusions, Notifications,
 * Diagnostics (engine health JSON), About. Each section is a CardFrame
 * whose body is toggled via a local `expanded_*` boolean. Clicking the
 * header rotates the chevron glyph.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Settings")

    property bool   launchOnStartup:   true
    property bool   showNotifications: true
    property int    logLevelIndex:     1
    property bool   automaticUpdates:  true
    property string lastUpdateCheck:   "Never"

    property bool   sensorOk:      false
    property string sensorReason:  ""
    property int    cortexActive:  0
    property int    cortexTotal:   0

    signal setLaunchOnStartup(bool on)
    signal setShowNotifications(bool on)
    signal setLogLevel(int index)
    signal setAutomaticUpdates(bool on)
    signal checkForUpdates()
    signal configureModule(string id, var payload)
    signal installUpdate()

    readonly property var logLevelModel: ["Error", "Info", "Debug"]
    readonly property var languageModel: ["English", "Deutsch", "Espa\u00f1ol", "Fran\u00e7ais"]

    property bool _expandedGeneral:      true
    property bool _expandedUpdates:      false
    property bool _expandedExclusions:   false
    property bool _expandedNotifications: false
    property bool _expandedDiagnostics:  false
    property bool _expandedAbout:        false

    property int  _themeIndex:       1
    property bool _showTray:         true
    property bool _notifyTips:       true
    property bool _notifyNews:       false
    property string _exclusions:     ""

    function _diagnosticsJson() {
        return "{\n" +
               "  \"sensorOk\":     " + (sensorOk ? "true" : "false") + ",\n" +
               "  \"sensorReason\": \"" + String(sensorReason).replace(/\\/g, "\\\\").replace(/"/g, "\\\"") + "\",\n" +
               "  \"cortexActive\": " + cortexActive + ",\n" +
               "  \"cortexTotal\":  " + cortexTotal + "\n" +
               "}";
    }

    ButtonGroup { id: themeGroup }
    ButtonGroup { id: updateModeGroup }

    // Hidden helper used to place text on the system clipboard.
    TextEdit {
        id: clipHelper
        visible: false
        width: 1; height: 1
    }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp4

            Column {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: 4
                Text { text: qsTr("Settings"); color: Theme.textStrong
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
                       font.weight: Font.DemiBold }
                Text { text: qsTr("Application behaviour, update policy and diagnostics.")
                       color: Theme.textMuted
                       font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody }
            }

            // ==========================================================
            //  General
            // ==========================================================
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("General")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontHeading
                        font.weight: Font.DemiBold
                    }
                    Text {
                        text: page._expandedGeneral ? "\u25B4" : "\u25BE"
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                    }
                    TapHandler { onTapped: page._expandedGeneral = !page._expandedGeneral }
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                ColumnLayout {
                    visible: page._expandedGeneral
                    clip: true
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp3
                        Text { text: qsTr("Language"); color: Theme.text
                               font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                               Layout.preferredWidth: 160 }
                        ComboBox {
                            Layout.preferredWidth: 220
                            model: page.languageModel
                            currentIndex: 0
                        }
                        Item { Layout.fillWidth: true }
                    }

                    Text {
                        text: qsTr("Theme")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSmall
                        font.weight: Font.DemiBold
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp4
                        RadioButton {
                            text: qsTr("Auto")
                            ButtonGroup.group: themeGroup
                            enabled: false
                            ToolTip.visible: hovered
                            ToolTip.text: qsTr("Coming soon")
                            checked: page._themeIndex === 0
                            onClicked: page._themeIndex = 0
                        }
                        RadioButton {
                            text: qsTr("Dark")
                            ButtonGroup.group: themeGroup
                            checked: page._themeIndex === 1
                            onClicked: page._themeIndex = 1
                        }
                        RadioButton {
                            text: qsTr("Light")
                            ButtonGroup.group: themeGroup
                            checked: page._themeIndex === 2
                            onClicked: page._themeIndex = 2
                        }
                        Item { Layout.fillWidth: true }
                    }

                    CheckBox {
                        text: qsTr("Launch at startup")
                        checked: page.launchOnStartup
                        onToggled: page.setLaunchOnStartup(checked)
                    }
                    CheckBox {
                        text: qsTr("Show tray icon")
                        checked: page._showTray
                        onToggled: page._showTray = checked
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp3
                        Text { text: qsTr("Log verbosity"); color: Theme.text
                               font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                               Layout.preferredWidth: 160 }
                        ComboBox {
                            Layout.preferredWidth: 220
                            model: page.logLevelModel
                            currentIndex: page.logLevelIndex
                            onActivated: page.setLogLevel(currentIndex)
                        }
                        Item { Layout.fillWidth: true }
                    }
                }
            }

            // ==========================================================
            //  Updates
            // ==========================================================
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            text: qsTr("Updates")
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontHeading
                            font.weight: Font.DemiBold
                        }
                        Text {
                            text: qsTr("Last check: %1").arg(page.lastUpdateCheck)
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                    }
                    Text {
                        text: page._expandedUpdates ? "\u25B4" : "\u25BE"
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                    }
                    TapHandler { onTapped: page._expandedUpdates = !page._expandedUpdates }
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                ColumnLayout {
                    visible: page._expandedUpdates
                    clip: true
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp4
                        RadioButton {
                            text: qsTr("Automatic")
                            ButtonGroup.group: updateModeGroup
                            checked: page.automaticUpdates
                            onClicked: page.setAutomaticUpdates(true)
                        }
                        RadioButton {
                            text: qsTr("Check manually")
                            ButtonGroup.group: updateModeGroup
                            checked: !page.automaticUpdates
                            onClicked: page.setAutomaticUpdates(false)
                        }
                        Item { Layout.fillWidth: true }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp3
                        Item { Layout.fillWidth: true }
                        PrimaryButton {
                            text: qsTr("Check for updates now")
                            onClicked: {
                                page.checkForUpdates();
                                page.installUpdate();
                            }
                        }
                    }
                }
            }

            // ==========================================================
            //  Exclusions
            // ==========================================================
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            text: qsTr("Exclusions")
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontHeading
                            font.weight: Font.DemiBold
                        }
                        Text {
                            text: qsTr("Files, folders or hashes the scanner should skip. One entry per line.")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            wrapMode: Text.WordWrap
                        }
                    }
                    Text {
                        text: page._expandedExclusions ? "\u25B4" : "\u25BE"
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                    }
                    TapHandler { onTapped: page._expandedExclusions = !page._expandedExclusions }
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                ColumnLayout {
                    visible: page._expandedExclusions
                    clip: true
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 160
                        color: Theme.bg1
                        radius: Theme.radiusSm
                        border.width: 0

                        ScrollView {
                            anchors.fill: parent
                            clip: true
                            TextArea {
                                id: exTa
                                placeholderText: qsTr("C:\\Path\\To\\Trusted\\Folder\n<hash>")
                                text: page._exclusions
                                onTextChanged: page._exclusions = text
                                color: Theme.text
                                font.family: Theme.fontFamilyMono
                                font.pixelSize: Theme.fontSmall
                                selectByMouse: true
                                background: Rectangle { color: "transparent" }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp3
                        SecondaryButton {
                            text: qsTr("Browse\u2026")
                            onClicked: { /* wired when a file picker lands */ }
                        }
                        Item { Layout.fillWidth: true }
                        PrimaryButton {
                            text: qsTr("Apply")
                            onClicked: page.configureModule("RealTimeProtection", {
                                exclusions: page._exclusions
                            })
                        }
                    }
                }
            }

            // ==========================================================
            //  Notifications
            // ==========================================================
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Notifications")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontHeading
                        font.weight: Font.DemiBold
                    }
                    Text {
                        text: page._expandedNotifications ? "\u25B4" : "\u25BE"
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                    }
                    TapHandler { onTapped: page._expandedNotifications = !page._expandedNotifications }
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                ColumnLayout {
                    visible: page._expandedNotifications
                    clip: true
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    CheckBox {
                        text: qsTr("Show threat blocked toasts")
                        checked: page.showNotifications
                        onToggled: page.setShowNotifications(checked)
                    }
                    CheckBox {
                        text: qsTr("Show performance tips")
                        checked: page._notifyTips
                        onToggled: page._notifyTips = checked
                    }
                    CheckBox {
                        text: qsTr("Show product news")
                        checked: page._notifyNews
                        onToggled: page._notifyNews = checked
                    }
                }
            }

            // ==========================================================
            //  Diagnostics
            // ==========================================================
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            text: qsTr("Diagnostics")
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontHeading
                            font.weight: Font.DemiBold
                        }
                        Text {
                            text: qsTr("Live engine health snapshot.")
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                    }
                    Text {
                        text: page._expandedDiagnostics ? "\u25B4" : "\u25BE"
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                    }
                    TapHandler { onTapped: page._expandedDiagnostics = !page._expandedDiagnostics }
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                ColumnLayout {
                    visible: page._expandedDiagnostics
                    clip: true
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: diagText.implicitHeight + Theme.sp5 * 2
                        color: Theme.bg1
                        radius: Theme.radiusSm
                        border.width: 0

                        Text {
                            id: diagText
                            anchors.fill: parent
                            anchors.margins: Theme.sp5
                            text: page._diagnosticsJson()
                            color: Theme.text
                            font.family: Theme.fontFamilyMono
                            font.pixelSize: Theme.fontSmall
                            wrapMode: Text.NoWrap
                            textFormat: Text.PlainText
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp3
                        Item { Layout.fillWidth: true }
                        SecondaryButton {
                            text: qsTr("Copy to clipboard")
                            onClicked: {
                                clipHelper.text = page._diagnosticsJson();
                                clipHelper.selectAll();
                                clipHelper.copy();
                            }
                        }
                    }
                }
            }

            // ==========================================================
            //  About
            // ==========================================================
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.sp3
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("About")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontHeading
                        font.weight: Font.DemiBold
                    }
                    Text {
                        text: page._expandedAbout ? "\u25B4" : "\u25BE"
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                    }
                    TapHandler { onTapped: page._expandedAbout = !page._expandedAbout }
                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                }

                ColumnLayout {
                    visible: page._expandedAbout
                    clip: true
                    Layout.fillWidth: true
                    spacing: Theme.sp3

                    Text { text: qsTr("ShadowStrike Phantom Home")
                           color: Theme.textStrong
                           font.family: Theme.fontFamily
                           font.pixelSize: Theme.fontBody
                           font.weight: Font.DemiBold }
                    Text { text: qsTr("Version %1").arg(Qt.application.version && Qt.application.version.length ? Qt.application.version : "1.0.0")
                           color: Theme.textMuted
                           font.family: Theme.fontFamily
                           font.pixelSize: Theme.fontSmall }
                    Text { text: qsTr("Build %1").arg("build-000000")
                           color: Theme.textMuted
                           font.family: Theme.fontFamilyMono
                           font.pixelSize: Theme.fontSmall }
                    Text { text: qsTr("\u00a9 2024\u20132025 ShadowStrike-Labs")
                           color: Theme.textDim
                           font.family: Theme.fontFamily
                           font.pixelSize: Theme.fontSmall }
                }
            }

            Item { Layout.fillHeight: true; implicitHeight: 1 }
        }
    }
}
