import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * ModuleCard
 * ----------
 * Kaspersky-class visual representation of a single protection module.
 *
 *   +---------------------------------------------------------------+
 *   | [icon]  Module display name                    (●) status    |
 *   |         short human description                 [Configure ⚙]|
 *   |                                                  [ toggle ]  |
 *   +---------------------------------------------------------------+
 *
 * The card is intentionally tall (88 px) so the icon + two-line copy
 * and the status cluster can breathe. Hover lifts the card with a blue
 * rim. Focus lights the same rim in accent for keyboard navigation.
 *
 * Inputs
 *   moduleId     : string  – stable module id (e.g. "RansomwareProtection")
 *   displayName  : string  – human name
 *   description  : string  – one-line explanation ("what this does")
 *   state        : string  – "running" | "degraded" | "disabled"
 *   enabled      : bool    – current on/off
 *   glyph        : string  – icon codepoint (Unicode symbol)
 *
 * Signals
 *   toggled(bool enabled)
 *   configureRequested()
 */
Rectangle {
    id: root

    property string moduleId:    ""
    property string displayName: ""
    property string description: ""
    property string state:       "running"
    property bool   enabled:     true
    property string glyph:       "\u25A0"

    signal toggled(bool enabled)
    signal configureRequested()

    Layout.fillWidth: true
    implicitHeight: 92

    radius: Theme.radiusMd
    color: hover.hovered ? Theme.bg3 : Theme.bg2
    border.color: hover.hovered ? Theme.accentAlt : Theme.stroke
    border.width: 1

    Behavior on color        { ColorAnimation { duration: Theme.motionFast } }
    Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }

    HoverHandler { id: hover }

    Accessible.role: Accessible.Pane
    Accessible.name: displayName
    Accessible.description: description

    // Soft status bar on the left edge — green / amber / grey.
    Rectangle {
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.margins: 2
        width: 3
        radius: 1.5
        color: root.state === "running"  ? Theme.success
             : root.state === "degraded" ? Theme.warning
             : Theme.statePause
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: Theme.sp5
        anchors.rightMargin: Theme.sp4
        spacing: Theme.sp4

        // ---- Icon tile -----------------------------------------------
        Rectangle {
            Layout.preferredWidth: 48
            Layout.preferredHeight: 48
            radius: Theme.radiusSm
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.22) }
                GradientStop { position: 1.0; color: Qt.rgba(Theme.accentDeep.r, Theme.accentDeep.g, Theme.accentDeep.b, 0.25) }
            }
            border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.35)
            border.width: 1

            Text {
                anchors.centerIn: parent
                text: root.glyph
                color: Theme.accentAlt
                font.family: Theme.fontFamily
                font.pixelSize: 22
                font.bold: true
            }
        }

        // ---- Name + description --------------------------------------
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

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

                // Status dot + label cluster.
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
            implicitWidth: 34
            implicitHeight: 34
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
                border.width: 1
                Behavior on color { ColorAnimation { duration: Theme.motionFast } }
            }
            contentItem: Text {
                text: "\u2699"
                anchors.centerIn: parent
                color: gearBtn.hovered ? Theme.accentAlt : Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: 18
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
