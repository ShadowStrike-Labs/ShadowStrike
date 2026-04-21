import QtQuick
import QtQuick.Controls
import "../Theming"

/*
 * SecondaryButton
 * ---------------
 * Low-emphasis action. Ghost style: transparent with a 1 px border that
 * brightens on hover. Used whenever PrimaryButton would be too loud
 * (Cancel, Restore, Delete in tables, navigation secondaries).
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
                  ? (root.danger ? Qt.rgba(1, 0.31, 0.43, 0.08) : Theme.overlayHover)
                  : "transparent"
        border.color: root.activeFocus
                      ? (root.danger ? Theme.danger : Theme.accent)
                      : root.hovered
                         ? (root.danger ? Theme.danger : Theme.accentAlt)
                         : Theme.stroke
        border.width: 1
        Behavior on color        { ColorAnimation { duration: Theme.motionFast } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }
    }

    contentItem: Text {
        text: root.text
        color: root.danger
               ? (root.hovered ? Theme.danger : Qt.lighter(Theme.danger, 1.1))
               : root.hovered ? Theme.text : Theme.textMuted
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
