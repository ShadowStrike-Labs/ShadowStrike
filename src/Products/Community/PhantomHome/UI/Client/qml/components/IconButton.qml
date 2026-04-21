import QtQuick
import QtQuick.Controls
import "../Theming"

/*
 * IconButton
 * ----------
 * Compact square button used for title-bar window controls and other
 * icon-only affordances. Provides a visible hover / press surface so
 * users can actually find the close / minimize buttons at a glance.
 */
AbstractButton {
    id: root
    width:  36
    height: 28

    property string glyph: ""
    property color  accentBg: Qt.rgba(0.17, 0.48, 1.00, 0.18)
    property bool   danger: false
    focusPolicy: Qt.TabFocus
    hoverEnabled: true

    background: Rectangle {
        anchors.fill: parent
        radius: Theme.radiusXs
        color: root.pressed
               ? (root.danger ? Qt.rgba(1.0, 0.31, 0.43, 0.34) : root.accentBg)
               : root.hovered
                  ? (root.danger ? Theme.overlayDanger : Theme.overlayHover)
                  : "transparent"
        border.color: root.activeFocus ? Theme.accent : "transparent"
        border.width: root.activeFocus ? 1 : 0
        Behavior on color { ColorAnimation { duration: Theme.motionFast } }
    }

    contentItem: Text {
        text: root.glyph.length ? root.glyph : root.text
        color: root.hovered && root.danger ? "#FFFFFF" : Theme.text
        font.family: Theme.fontFamily
        font.pixelSize: 13
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment:   Text.AlignVCenter
    }
}
