import QtQuick
import QtQuick.Controls
import "../Theming"

/*
 * PrimaryButton
 * -------------
 * The single visual treatment used for "this is the main action on the
 * page" - Fast Scan, Check for Updates, Resolve Now. Uses the primary
 * electric-blue accent with a subtle gradient and press/hover states.
 *
 * Use SecondaryButton for anything that isn't the dominant action.
 */
Button {
    id: root
    implicitHeight: 40
    implicitWidth: Math.max(148, contentItem.implicitWidth + Theme.sp8)
    focusPolicy: Qt.StrongFocus
    hoverEnabled: true

    property bool danger: false

    background: Rectangle {
        anchors.fill: parent
        radius: Theme.radiusSm
        gradient: Gradient {
            GradientStop { position: 0.0
                color: root.danger
                       ? (root.pressed ? "#C72D47" : root.hovered ? "#FF5F7C" : "#FF4F6E")
                       : (root.pressed ? Theme.accentPress : root.hovered ? Theme.accentHover : Theme.accent)
            }
            GradientStop { position: 1.0
                color: root.danger
                       ? (root.pressed ? "#9B1B32" : "#E0355A")
                       : (root.pressed ? "#153F91" : root.hovered ? "#2F7BE0" : "#1F5ECC")
            }
        }
        border.color: root.activeFocus
                      ? Qt.lighter(root.danger ? Theme.danger : Theme.accent, 1.35)
                      : Qt.rgba(1, 1, 1, 0.10)
        border.width: 1
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast } }
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
        leftPadding:  Theme.sp4
        rightPadding: Theme.sp4
    }
}
