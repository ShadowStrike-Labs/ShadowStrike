import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * SecurityPage
 * ------------
 * User-facing toggles for individual protection modules and the default
 * action policy when a detection fires.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Security")

    // Each module: { id, displayName, enabled, state ("running"|"degraded"|"disabled") }
    property var modules: []

    signal setModuleEnabled(string moduleId, bool enabled)
    signal setDetectionAction(string moduleId, int action)    // 0=Ask 1=Quarantine 2=Delete 3=LogOnly

    // ButtonGroup is a non-visual QtObject; lives at Item scope, not inside a card.
    ButtonGroup { id: actionGroup }

    function severityFor(state) {
        if (state === "running")  return "ok"
        if (state === "degraded") return "warn"
        if (state === "disabled") return "muted"
        return "info"
    }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            // Page header
            Column {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: 4
                Text {
                    text: "Security"
                    color: Theme.textStrong
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontTitle
                    font.weight: Font.DemiBold
                }
                Text {
                    text: "Configure real-time protection modules and the default action for detections."
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                title: "Protection modules"
                subtitle: "Each module can be toggled individually."

                Repeater {
                    model: page.modules
                    delegate: Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: 52
                        radius: Theme.radiusSm
                        color: mouse.containsMouse ? Theme.bg3 : "transparent"
                        border.color: Theme.strokeSoft
                        border.width: 1
                        Behavior on color { ColorAnimation { duration: Theme.motionFast } }

                        HoverHandler { id: mouse }

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.sp4
                            anchors.rightMargin: Theme.sp3
                            spacing: Theme.sp3

                            Rectangle {
                                width: 8; height: 8; radius: 4
                                color: modelData.state === "running"  ? Theme.success
                                     : modelData.state === "degraded" ? Theme.warning
                                     : Theme.textMuted
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData.displayName
                                color: Theme.text
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                                elide: Text.ElideRight
                            }
                            StatePill {
                                label: modelData.state
                                severity: page.severityFor(modelData.state)
                            }
                            Switch {
                                checked: modelData.enabled
                                onToggled: page.setModuleEnabled(modelData.id, checked)
                                focusPolicy: Qt.StrongFocus
                                Accessible.role: Accessible.CheckBox
                                Accessible.name: qsTr("%1 enabled").arg(modelData.displayName)
                                Accessible.description: qsTr("Toggle the %1 protection module").arg(modelData.displayName)
                            }
                        }
                    }
                }

                Text {
                    visible: page.modules.length === 0
                    text: "Loading modules\u2026"
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                }
            }

            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp6
                title: "When a threat is detected"
                subtitle: "The default action applied automatically across modules."

                RadioButton { ButtonGroup.group: actionGroup; text: "Ask me"; checked: true
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
                RadioButton { ButtonGroup.group: actionGroup; text: "Quarantine (recommended)"
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
                RadioButton { ButtonGroup.group: actionGroup; text: "Delete"
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
                RadioButton { ButtonGroup.group: actionGroup; text: "Log only"
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
