import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * SecurityPage
 * ------------
 * User-facing toggles for protection modules + detection-action policy.
 * Wired to Security tab. Actions emit to the backend via ProtectionViewModel
 * (hooked up in a later pass — Tier 3).
 */
Item {
    id: page

    // Backend-driven list of modules. Each element:
    //   { id, displayName, enabled, state ("running"|"degraded"|"disabled") }
    property var modules: []

    signal setModuleEnabled(string moduleId, bool enabled)
    signal setDetectionAction(string moduleId, int action)    // 0=Ask 1=Quarantine 2=Delete 3=LogOnly

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - Theme.sp8
            anchors.margins: Theme.sp6
            spacing: Theme.sp4

            Text {
                text: "Security"
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontTitle
                font.weight: Font.DemiBold
            }
            Text {
                text: "Configure real-time protection modules and detection actions."
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontBody
            }

            CardFrame {
                title: "Protection modules"
                Layout.fillWidth: true

                Repeater {
                    model: page.modules
                    delegate: RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sp4

                        Text {
                            Layout.fillWidth: true
                            text: modelData.displayName
                            color: Theme.text
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontBody
                        }
                        Text {
                            text: modelData.state
                            color: modelData.state === "running" ? Theme.success
                                 : modelData.state === "degraded" ? Theme.warning
                                 : Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                        }
                        Switch {
                            checked: modelData.enabled
                            onToggled: page.setModuleEnabled(modelData.id, checked)
                        }
                    }
                }

                Text {
                    visible: page.modules.length === 0
                    text: "Loading modules…"
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                }
            }

            CardFrame {
                title: "When a threat is detected"
                Layout.fillWidth: true

                ButtonGroup { id: actionGroup }

                RadioButton { ButtonGroup.group: actionGroup; text: "Ask me";       checked: true }
                RadioButton { ButtonGroup.group: actionGroup; text: "Quarantine (recommended)" }
                RadioButton { ButtonGroup.group: actionGroup; text: "Delete" }
                RadioButton { ButtonGroup.group: actionGroup; text: "Log only" }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
