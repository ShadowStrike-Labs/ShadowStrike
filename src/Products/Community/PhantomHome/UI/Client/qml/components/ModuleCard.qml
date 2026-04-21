import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * ModuleCard
 * ----------
 * Kaspersky-class tile for a single protection module. Borderless;
 * depth comes from tonal steps (bg2 -> bg3 on hover). A soft status
 * bar on the left edge signals running / degraded / disabled.
 *
 *   +-----------------------------------------------------------------+
 *   |  [icon chip]  Module display name          (dot) Running  [cog] |
 *   |               short human description                   [toggle]|
 *   +-----------------------------------------------------------------+
 *
 * The tile body is a click surface that emits detailRequested() so the
 * parent page can push a detail view onto its StackView. The cog and
 * toggle keep their own affordances and stop propagation.
 */
Rectangle {
    id: root

    property string moduleId:    ""
    property string displayName: ""
    property string description: ""
    property string state:       "running"
    property bool   enabled:     true
    property string iconName:    "shield"

    signal toggled(bool enabled)
    signal configureRequested()
    signal detailRequested()

    Layout.fillWidth: true
    implicitHeight: 96

    radius: Theme.radiusMd
    color: hover.hovered ? Theme.bg3 : Theme.bg2
    border.width: 0

    Behavior on color { ColorAnimation { duration: Theme.motionFast } }

    HoverHandler { id: hover }

    TapHandler {
        acceptedButtons: Qt.LeftButton
        onTapped: root.detailRequested()
    }

    Accessible.role: Accessible.Button
    Accessible.name: displayName
    Accessible.description: qsTr("%1. Click to view settings.").arg(description)

    // Status bar on the left edge - green / amber / muted.
    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.topMargin: Theme.sp3
        anchors.bottomMargin: Theme.sp3
        anchors.leftMargin: Theme.sp2
        width: 3
        radius: 1.5
        color: root.state === "running"  ? Theme.success
             : root.state === "degraded" ? Theme.warning
             : Theme.statePause
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.sp5 + Theme.sp2
        anchors.rightMargin: Theme.sp4
        spacing: Theme.sp4

        // ---- Icon chip -----------------------------------------------
        Rectangle {
            Layout.preferredWidth: 46
            Layout.preferredHeight: 46
            radius: Theme.radiusSm
            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.16)

            Iconed {
                anchors.centerIn: parent
                iconName: root.iconName
                size: 22
                tint: root.state === "disabled" ? Theme.textMuted : Theme.accentAlt
            }
        }

        // ---- Name + description --------------------------------------
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 3

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.sp2

                Text {
                    text: root.displayName
                    color: Theme.textStrong
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody + 1
                    font.weight: Font.DemiBold
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }

                Rectangle {
                    width: 8; height: 8; radius: 4
                    color: root.state === "running"  ? Theme.success
                         : root.state === "degraded" ? Theme.warning
                         : Theme.textMuted
                    Layout.alignment: Qt.AlignVCenter
                }
                Text {
                    text: root.state === "running"  ? qsTr("Running")
                        : root.state === "degraded" ? qsTr("Attention")
                        : root.state === "disabled" ? qsTr("Disabled")
                        : qsTr("Unknown")
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            Text {
                text: root.description
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap
                elide: Text.ElideRight
                maximumLineCount: 2
                Layout.fillWidth: true
            }
        }

        // ---- Configure (gear) ----------------------------------------
        AbstractButton {
            id: gearBtn
            implicitWidth: 36
            implicitHeight: 36
            hoverEnabled: true
            focusPolicy: Qt.TabFocus
            onClicked: root.configureRequested()

            Accessible.role: Accessible.Button
            Accessible.name: qsTr("Configure %1").arg(root.displayName)
            Accessible.description: qsTr("Open fine-tuning for this protection module")

            ToolTip.text: qsTr("Configure")
            ToolTip.visible: hovered
            ToolTip.delay: 600

            background: Rectangle {
                anchors.fill: parent
                radius: Theme.radiusSm
                color: gearBtn.pressed
                       ? Theme.overlayPressed
                       : gearBtn.hovered ? Theme.overlayHover : "transparent"
                border.color: gearBtn.activeFocus ? Theme.accent : "transparent"
                border.width: gearBtn.activeFocus ? 1 : 0
                Behavior on color { ColorAnimation { duration: Theme.motionFast } }
            }
            contentItem: Iconed {
                iconName: "cog"
                size: 18
                tint: gearBtn.hovered ? Theme.accentAlt : Theme.textMuted
            }
        }

        // ---- Master toggle -------------------------------------------
        Switch {
            id: toggle
            checked: root.enabled
            focusPolicy: Qt.StrongFocus
            onToggled: root.toggled(checked)

            Accessible.role: Accessible.CheckBox
            Accessible.name: qsTr("%1 enabled").arg(root.displayName)
            Accessible.description: qsTr("Toggle the %1 protection module on or off").arg(root.displayName)
        }
    }
}
