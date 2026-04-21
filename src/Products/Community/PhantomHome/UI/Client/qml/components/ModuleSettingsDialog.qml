import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * ModuleSettingsDialog
 * --------------------
 * Per-module fine-tuning surface. Opens in response to the gear icon
 * on a ModuleCard. Presents the controls a home user actually needs:
 *
 *   - Master enable toggle (mirrors the card).
 *   - Sensitivity (Low / Balanced / High).  Community-tier only exposes
 *     these three named buckets; the underlying service translates the
 *     bucket to a detection-weight triple.
 *   - Default action on detection (Ask / Quarantine / Delete / Log).
 *   - Exclusions list (comma-separated paths/hashes/processes). Kept
 *     intentionally compact; advanced exclusion management lives in
 *     SettingsPage.
 *
 * The dialog is policy-only: it emits `applied(payload)` carrying a
 * QVariantMap that the calling page forwards to ProtectionViewModel.
 * The dialog never touches the service directly.
 */
Popup {
    id: root
    modal: true
    focus: true
    dim: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutsideParent
    padding: 0

    property string moduleId:    ""
    property string displayName: ""
    property string description: ""
    property bool   moduleEnabled: true
    property int    sensitivity: 1                    // 0=Low 1=Balanced 2=High
    property int    action:      1                    // 0=Ask 1=Quarantine 2=Delete 3=LogOnly
    property string exclusions:  ""

    signal applied(var payload)
    signal canceled()

    // Size the dialog relative to the parent window so it reads as a
    // proper modal surface on the 1240x760 app canvas.
    width:  Math.min(560, parent ? parent.width  - 80 : 560)
    height: Math.min(560, parent ? parent.height - 80 : 560)
    anchors.centerIn: parent

    background: Rectangle {
        radius: Theme.radiusLg
        color: Theme.bg1
        border.color: Theme.stroke
        border.width: 1

        // Accent top hairline so the modal reads as an elevated surface
        // without a heavy drop-shadow (which Qt 6 doesn't ship cross-
        // platform without layer.effect + a graphical effect module).
        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: Theme.radiusLg
            anchors.rightMargin: Theme.radiusLg
            anchors.topMargin: 1
            height: 1
            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.5)
        }
    }

    // Entry / exit fade so the modal never just "pops".
    enter: Transition {
        NumberAnimation { property: "opacity"; from: 0.0; to: 1.0; duration: Theme.motionNormal }
        NumberAnimation { property: "scale";   from: 0.96; to: 1.0; duration: Theme.motionNormal; easing.type: Easing.OutCubic }
    }
    exit: Transition {
        NumberAnimation { property: "opacity"; from: 1.0; to: 0.0; duration: Theme.motionFast }
    }

    ButtonGroup { id: sensitivityGroup }
    ButtonGroup { id: actionGroup }

    contentItem: ColumnLayout {
        spacing: 0

        // ---- Header -----------------------------------------------------
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 72
            color: "transparent"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.sp6
                anchors.rightMargin: Theme.sp3
                spacing: Theme.sp3

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text {
                        text: qsTr("Configure")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSmall
                        font.weight: Font.Medium
                    }
                    Text {
                        text: root.displayName
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontHeading
                        font.weight: Font.DemiBold
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                }

                IconButton {
                    glyph: "\u2715"
                    onClicked: { root.canceled(); root.close() }
                    Accessible.name: qsTr("Close configuration")
                }
            }

            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                height: 1
                color: Theme.strokeSoft
            }
        }

        // ---- Body -------------------------------------------------------
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            ColumnLayout {
                width: root.width - 2
                spacing: Theme.sp5

                // Description block ------------------------------------------------
                Text {
                    Layout.leftMargin: Theme.sp6
                    Layout.rightMargin: Theme.sp6
                    Layout.topMargin: Theme.sp5
                    Layout.fillWidth: true
                    text: root.description.length > 0
                          ? root.description
                          : qsTr("Fine-tune the %1 protection module.").arg(root.displayName)
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    wrapMode: Text.WordWrap
                }

                // Master toggle --------------------------------------------
                Rectangle {
                    Layout.leftMargin: Theme.sp6
                    Layout.rightMargin: Theme.sp6
                    Layout.fillWidth: true
                    implicitHeight: 56
                    radius: Theme.radiusSm
                    color: Theme.bg2
                    border.color: Theme.stroke
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.sp4
                        anchors.rightMargin: Theme.sp3
                        spacing: Theme.sp3

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            Text {
                                text: qsTr("Module enabled")
                                color: Theme.text
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                                font.weight: Font.DemiBold
                            }
                            Text {
                                text: qsTr("Turn this protection layer on or off.")
                                color: Theme.textMuted
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                            }
                        }
                        Switch {
                            checked: root.moduleEnabled
                            focusPolicy: Qt.StrongFocus
                            onToggled: root.moduleEnabled = checked
                            Accessible.name: qsTr("%1 enabled").arg(root.displayName)
                        }
                    }
                }

                // Sensitivity ----------------------------------------------
                ColumnLayout {
                    Layout.leftMargin: Theme.sp6
                    Layout.rightMargin: Theme.sp6
                    Layout.fillWidth: true
                    spacing: Theme.sp2

                    Text {
                        text: qsTr("Detection sensitivity")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                        font.weight: Font.DemiBold
                    }
                    Text {
                        text: qsTr("Higher sensitivity catches more threats but may flag more clean files.")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSmall
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.topMargin: Theme.sp2
                        spacing: Theme.sp2

                        Repeater {
                            model: [
                                { label: qsTr("Low"),       value: 0, desc: qsTr("Minimize false positives") },
                                { label: qsTr("Balanced"),  value: 1, desc: qsTr("Recommended") },
                                { label: qsTr("High"),      value: 2, desc: qsTr("Maximum protection") }
                            ]
                            delegate: AbstractButton {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 58
                                hoverEnabled: true
                                focusPolicy: Qt.StrongFocus
                                ButtonGroup.group: sensitivityGroup
                                checkable: true
                                checked: root.sensitivity === modelData.value
                                onClicked: root.sensitivity = modelData.value

                                Accessible.role: Accessible.RadioButton
                                Accessible.name: qsTr("Sensitivity: %1").arg(modelData.label)

                                background: Rectangle {
                                    anchors.fill: parent
                                    radius: Theme.radiusSm
                                    color: parent.checked ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.14)
                                                          : parent.hovered ? Theme.bg3 : Theme.bg2
                                    border.color: parent.checked ? Theme.accent
                                                                 : (parent.hovered ? Theme.accentAlt : Theme.stroke)
                                    border.width: 1
                                    Behavior on color { ColorAnimation { duration: Theme.motionFast } }
                                    Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }
                                }

                                contentItem: ColumnLayout {
                                    spacing: 0
                                    Text {
                                        text: modelData.label
                                        color: Theme.textStrong
                                        font.family: Theme.fontFamily
                                        font.pixelSize: Theme.fontBody
                                        font.weight: Font.DemiBold
                                        horizontalAlignment: Text.AlignHCenter
                                        Layout.fillWidth: true
                                        Layout.topMargin: 8
                                    }
                                    Text {
                                        text: modelData.desc
                                        color: Theme.textMuted
                                        font.family: Theme.fontFamily
                                        font.pixelSize: Theme.fontSmall
                                        horizontalAlignment: Text.AlignHCenter
                                        wrapMode: Text.WordWrap
                                        Layout.fillWidth: true
                                        Layout.bottomMargin: 8
                                    }
                                }
                            }
                        }
                    }
                }

                // Action on detection --------------------------------------
                ColumnLayout {
                    Layout.leftMargin: Theme.sp6
                    Layout.rightMargin: Theme.sp6
                    Layout.fillWidth: true
                    spacing: Theme.sp2

                    Text {
                        text: qsTr("When a threat is detected")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                        font.weight: Font.DemiBold
                    }

                    Repeater {
                        model: [
                            { label: qsTr("Ask me"),                       value: 0 },
                            { label: qsTr("Quarantine (recommended)"),     value: 1 },
                            { label: qsTr("Delete"),                       value: 2 },
                            { label: qsTr("Log only"),                     value: 3 }
                        ]
                        delegate: RadioButton {
                            ButtonGroup.group: actionGroup
                            checked: root.action === modelData.value
                            text: modelData.label
                            focusPolicy: Qt.StrongFocus
                            onToggled: if (checked) root.action = modelData.value
                            Accessible.role: Accessible.RadioButton
                            contentItem: Text {
                                leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                                verticalAlignment: Text.AlignVCenter
                                text: parent.text
                                color: Theme.text
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontBody
                            }
                        }
                    }
                }

                // Exclusions -----------------------------------------------
                ColumnLayout {
                    Layout.leftMargin: Theme.sp6
                    Layout.rightMargin: Theme.sp6
                    Layout.fillWidth: true
                    Layout.bottomMargin: Theme.sp4
                    spacing: Theme.sp2

                    Text {
                        text: qsTr("Exclusions")
                        color: Theme.textStrong
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                        font.weight: Font.DemiBold
                    }
                    Text {
                        text: qsTr("Comma-separated paths, file hashes, or process names. Use with care — anything listed here is not scanned.")
                        color: Theme.textMuted
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSmall
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                    TextField {
                        id: exclusionField
                        Layout.fillWidth: true
                        placeholderText: qsTr("e.g. C:\\Projects\\build, ab12cd..., notepad.exe")
                        text: root.exclusions
                        color: Theme.text
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontBody
                        selectByMouse: true
                        onTextChanged: root.exclusions = text
                        background: Rectangle {
                            radius: Theme.radiusSm
                            color: Theme.bg2
                            border.color: exclusionField.activeFocus ? Theme.accent : Theme.stroke
                            border.width: 1
                            Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }
                        }
                    }
                }
            }
        }

        // ---- Footer -----------------------------------------------------
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 60
            color: Theme.bgHeader

            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                height: 1
                color: Theme.stroke
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.sp6
                anchors.rightMargin: Theme.sp6
                spacing: Theme.sp3

                Item { Layout.fillWidth: true }

                SecondaryButton {
                    text: qsTr("Cancel")
                    onClicked: { root.canceled(); root.close() }
                }
                PrimaryButton {
                    text: qsTr("Apply")
                    onClicked: {
                        root.applied({
                            "id":          root.moduleId,
                            "enabled":     root.moduleEnabled,
                            "sensitivity": root.sensitivity,
                            "action":      root.action,
                            "exclusions":  root.exclusions
                        })
                        root.close()
                    }
                }
            }
        }
    }
}
