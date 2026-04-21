import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../../Theming"
import "../../components"

/*
 * GenericModuleDetailPage
 * -----------------------
 * Drill-down view pushed onto SecurityPage's StackView when the user
 * clicks the body of a ModuleCard tile. Exposes the full tunable set:
 *
 *   - Master toggle (duplicated here for accessibility).
 *   - Sensitivity (Low / Balanced / Aggressive).
 *   - Action on detection (Ask / Quarantine / Delete / Log).
 *   - Exclusions (newline-separated paths / hashes / process names).
 *   - Apply / Revert buttons — emits a merged payload via `applied`.
 *
 * Parent seeds moduleId / displayName / description / iconName /
 * moduleEnabled / sensitivity / action / exclusions before pushing.
 */
Item {
    id: page

    property string moduleId:      ""
    property string displayName:   ""
    property string description:   ""
    property string iconName:      "shield"
    property string state:         "running"
    property bool   moduleEnabled: true
    property int    sensitivity:   1
    property int    action:        1
    property string exclusions:    ""

    signal backRequested()
    signal applied(var payload)

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Configure %1").arg(displayName)

    property bool   _enabledEdit:     moduleEnabled
    property int    _sensitivityEdit: sensitivity
    property int    _actionEdit:      action
    property string _exclusionsEdit:  exclusions

    onModuleEnabledChanged: _enabledEdit = moduleEnabled
    onSensitivityChanged:   _sensitivityEdit = sensitivity
    onActionChanged:        _actionEdit = action
    onExclusionsChanged:    _exclusionsEdit = exclusions

    function _dirty() {
        return _enabledEdit     !== moduleEnabled ||
               _sensitivityEdit !== sensitivity   ||
               _actionEdit      !== action        ||
               _exclusionsEdit  !== exclusions;
    }

    ButtonGroup { id: sensGroup }
    ButtonGroup { id: actGroup  }

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            // --- Breadcrumb header ------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp6
                Layout.rightMargin: Theme.sp6
                spacing: Theme.sp3

                AbstractButton {
                    id: backBtn
                    implicitWidth: 34
                    implicitHeight: 34
                    hoverEnabled: true
                    focusPolicy: Qt.StrongFocus
                    onClicked: page.backRequested()
                    Accessible.role: Accessible.Button
                    Accessible.name: qsTr("Back to protection modules")
                    ToolTip.text: qsTr("Back")
                    ToolTip.visible: hovered
                    ToolTip.delay: 600
                    background: Rectangle {
                        anchors.fill: parent
                        radius: Theme.radiusSm
                        color: backBtn.pressed ? Theme.overlayPressed
                             : backBtn.hovered ? Theme.overlayHover : "transparent"
                        border.color: backBtn.activeFocus ? Theme.accent : "transparent"
                        border.width: 1
                        Behavior on color { ColorAnimation { duration: Theme.motionFast } }
                    }
                    contentItem: Iconed {
                        iconName: "chevron-left"
                        size: 18
                        tint: backBtn.hovered ? Theme.accentAlt : Theme.text
                    }
                }

                Text {
                    text: qsTr("Protection modules")
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: page.backRequested()
                    }
                }
                Text {
                    text: "\u203A"
                    color: Theme.textDim
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                }
                Text {
                    text: page.displayName
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    font.weight: Font.DemiBold
                }
                Item { Layout.fillWidth: true }
            }

            // --- Hero strip ------------------------------------------
            Rectangle {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp6
                Layout.rightMargin: Theme.sp6
                radius: Theme.radiusLg
                color: Theme.bg2
                border.color: Theme.stroke
                border.width: 1
                implicitHeight: heroRow.implicitHeight + Theme.sp6 * 2

                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.08) }
                    GradientStop { position: 1.0; color: Theme.bg2 }
                }

                RowLayout {
                    id: heroRow
                    anchors.fill: parent
                    anchors.margins: Theme.sp6
                    spacing: Theme.sp5

                    Rectangle {
                        Layout.preferredWidth: 72
                        Layout.preferredHeight: 72
                        radius: Theme.radiusMd
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.25) }
                            GradientStop { position: 1.0; color: Qt.rgba(Theme.accentDeep.r, Theme.accentDeep.g, Theme.accentDeep.b, 0.30) }
                        }
                        border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.40)
                        border.width: 1

                        Iconed {
                            anchors.centerIn: parent
                            iconName: page.iconName
                            size: 38
                            tint: Theme.accentAlt
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        Text {
                            text: page.displayName
                            color: Theme.textStrong
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontTitle
                            font.weight: Font.DemiBold
                        }
                        Text {
                            text: page.description
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontBody
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        RowLayout {
                            spacing: Theme.sp2
                            Layout.topMargin: Theme.sp2
                            Rectangle {
                                width: 8; height: 8; radius: 4
                                color: page.state === "running"  ? Theme.success
                                     : page.state === "degraded" ? Theme.warning
                                     : Theme.textMuted
                            }
                            Text {
                                text: page.state === "running"  ? qsTr("Running")
                                    : page.state === "degraded" ? qsTr("Attention required")
                                    : page.state === "disabled" ? qsTr("Disabled")
                                    : qsTr("Unknown")
                                color: page.state === "degraded" ? Theme.warning : Theme.textMuted
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSmall
                                font.weight: Font.DemiBold
                            }
                        }
                    }

                    Switch {
                        checked: page._enabledEdit
                        focusPolicy: Qt.StrongFocus
                        onToggled: page._enabledEdit = checked
                        Accessible.role: Accessible.CheckBox
                        Accessible.name: qsTr("%1 enabled").arg(page.displayName)
                    }
                }
            }

            // --- Sensitivity -----------------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp6
                Layout.rightMargin: Theme.sp6
                title: qsTr("Detection sensitivity")
                subtitle: qsTr("Controls how aggressively this module flags suspicious behaviour. Higher sensitivity increases detection but may produce more alerts.")

                RadioButton {
                    ButtonGroup.group: sensGroup
                    text: qsTr("Low \u2014 fewer alerts, signature-weighted")
                    focusPolicy: Qt.StrongFocus
                    checked: page._sensitivityEdit === 0
                    onToggled: if (checked) page._sensitivityEdit = 0
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
                RadioButton {
                    ButtonGroup.group: sensGroup
                    text: qsTr("Balanced \u2014 recommended for most users")
                    focusPolicy: Qt.StrongFocus
                    checked: page._sensitivityEdit === 1
                    onToggled: if (checked) page._sensitivityEdit = 1
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
                RadioButton {
                    ButtonGroup.group: sensGroup
                    text: qsTr("Aggressive \u2014 heuristic + ML forward, more alerts")
                    focusPolicy: Qt.StrongFocus
                    checked: page._sensitivityEdit === 2
                    onToggled: if (checked) page._sensitivityEdit = 2
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
            }

            // --- Action on detection ---------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp6
                Layout.rightMargin: Theme.sp6
                title: qsTr("Action on detection")
                subtitle: qsTr("What this module does when it identifies a threat. Overrides the service-wide default.")

                RadioButton {
                    ButtonGroup.group: actGroup
                    text: qsTr("Ask me")
                    focusPolicy: Qt.StrongFocus
                    checked: page._actionEdit === 0
                    onToggled: if (checked) page._actionEdit = 0
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
                RadioButton {
                    ButtonGroup.group: actGroup
                    text: qsTr("Quarantine (recommended)")
                    focusPolicy: Qt.StrongFocus
                    checked: page._actionEdit === 1
                    onToggled: if (checked) page._actionEdit = 1
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
                RadioButton {
                    ButtonGroup.group: actGroup
                    text: qsTr("Delete")
                    focusPolicy: Qt.StrongFocus
                    checked: page._actionEdit === 2
                    onToggled: if (checked) page._actionEdit = 2
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
                RadioButton {
                    ButtonGroup.group: actGroup
                    text: qsTr("Log only")
                    focusPolicy: Qt.StrongFocus
                    checked: page._actionEdit === 3
                    onToggled: if (checked) page._actionEdit = 3
                    contentItem: Text {
                        leftPadding: parent.indicator ? parent.indicator.width + Theme.sp2 : 0
                        verticalAlignment: Text.AlignVCenter
                        text: parent.text; color: Theme.text
                        font.family: Theme.fontFamily; font.pixelSize: Theme.fontBody
                    }
                }
            }

            // --- Exclusions ------------------------------------------
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp6
                Layout.rightMargin: Theme.sp6
                title: qsTr("Exclusions")
                subtitle: qsTr("Paths, file hashes or process names this module should ignore. One per line.")

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 110
                    radius: Theme.radiusSm
                    color: Theme.bg1
                    border.color: exclArea.activeFocus ? Theme.accent : Theme.stroke
                    border.width: 1

                    ScrollView {
                        anchors.fill: parent
                        anchors.margins: Theme.sp2
                        clip: true
                        TextArea {
                            id: exclArea
                            text: page._exclusionsEdit
                            onTextChanged: page._exclusionsEdit = text
                            color: Theme.text
                            placeholderText: qsTr("C:\\TrustedTool\\*\nmy-internal-installer.exe")
                            placeholderTextColor: Theme.textDim
                            font.family: Theme.fontFamilyMono
                            font.pixelSize: Theme.fontBody
                            wrapMode: TextEdit.Wrap
                            selectByMouse: true
                            background: null
                        }
                    }
                }
            }

            // --- Apply / Revert --------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp6
                Layout.rightMargin: Theme.sp6
                Layout.bottomMargin: Theme.sp6
                spacing: Theme.sp3

                Item { Layout.fillWidth: true }

                SecondaryButton {
                    text: qsTr("Revert")
                    enabled: page._dirty()
                    onClicked: {
                        page._enabledEdit     = page.moduleEnabled
                        page._sensitivityEdit = page.sensitivity
                        page._actionEdit      = page.action
                        page._exclusionsEdit  = page.exclusions
                    }
                }
                PrimaryButton {
                    text: qsTr("Apply")
                    enabled: page._dirty()
                    onClicked: {
                        page.applied({
                            id:          page.moduleId,
                            enabled:     page._enabledEdit,
                            sensitivity: page._sensitivityEdit,
                            action:      page._actionEdit,
                            exclusions:  page._exclusionsEdit
                        })
                        page.moduleEnabled = page._enabledEdit
                        page.sensitivity   = page._sensitivityEdit
                        page.action        = page._actionEdit
                        page.exclusions    = page._exclusionsEdit
                    }
                }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
