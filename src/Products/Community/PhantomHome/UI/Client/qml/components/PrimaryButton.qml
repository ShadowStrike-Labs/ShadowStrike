import QtQuick
import QtQuick.Controls
import "../Theming"

/*
 * PrimaryButton
 * -------------
 * Flat, pill-ish primary action button. Single-tone fill (blue or red
 * for destructive), quiet hover/press states. This is the only "loud"
 * button style in the app - used for the dominant action on a page.
 */
Button {
    id: root
    implicitHeight: 38
    implicitWidth: Math.max(128, contentItem.implicitWidth + Theme.sp8)
    focusPolicy: Qt.StrongFocus
    hoverEnabled: true

    property bool danger: false

    background: Rectangle {
        anchors.fill: parent
        radius: Theme.radiusSm
        color: root.danger
               ? (root.pressed ? "#B91C1C" : root.hovered ? "#F87171" : Theme.danger)
               : (root.pressed ? Theme.accentPress : root.hovered ? Theme.accentHover : Theme.accent)
        Behavior on color { ColorAnimation { duration: Theme.motionFast } }

        // Focus ring - rendered as a soft second outline, not a hard border.
        Rectangle {
            anchors.fill: parent
            radius: parent.radius
            color: "transparent"
            border.color: root.activeFocus
                          ? Qt.rgba(1, 1, 1, 0.45)
                          : "transparent"
            border.width: 2
        }
    }

    contentItem: Text {
        text: root.text
        color: "#FFFFFF"
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontBody
        font.weight: Font.DemiBold
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment:   Text.AlignVCenter
        elide: Text.ElideRight
        leftPadding:  Theme.sp5
        rightPadding: Theme.sp5
    }
}
