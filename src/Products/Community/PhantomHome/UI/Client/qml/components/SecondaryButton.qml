import QtQuick
import QtQuick.Controls
import "../Theming"

/*
 * SecondaryButton
 * ---------------
 * Low-emphasis action. Borderless at rest; hover surfaces a faint tonal
 * fill. Accent text color on hover to signal interactivity. Used for
 * Cancel, Restore, View Details, and any non-primary CTA.
 */
Button {
    id: root
    implicitHeight: 36
    implicitWidth: Math.max(100, contentItem.implicitWidth + Theme.sp6)
    focusPolicy: Qt.StrongFocus
    hoverEnabled: true

    property bool danger: false

    background: Rectangle {
        anchors.fill: parent
        radius: Theme.radiusSm
        color: root.pressed
               ? (root.danger ? Theme.overlayDanger : Theme.overlayPressed)
               : root.hovered
                  ? (root.danger ? Qt.rgba(0.94, 0.27, 0.27, 0.10) : Theme.overlayHover)
                  : "transparent"
        border.color: root.activeFocus
                      ? (root.danger ? Theme.danger : Theme.accent)
                      : "transparent"
        border.width: root.activeFocus ? 2 : 0
        Behavior on color { ColorAnimation { duration: Theme.motionFast } }
    }

    contentItem: Text {
        text: root.text
        color: root.danger
               ? (root.hovered ? Theme.danger : Qt.lighter(Theme.danger, 1.1))
               : root.hovered ? Theme.accentAlt : Theme.textMuted
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontBody
        font.weight: Font.Medium
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment:   Text.AlignVCenter
        elide: Text.ElideRight
        leftPadding:  Theme.sp4
        rightPadding: Theme.sp4
    }
}
