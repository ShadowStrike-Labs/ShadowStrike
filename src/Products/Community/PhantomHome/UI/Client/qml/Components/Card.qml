import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    default property alias content: inner.children
    property int   padding: Theme.spacingL
    property color accent:  Theme.accentCyan
    property bool  glow:    false

    implicitWidth:  300
    implicitHeight: inner.implicitHeight + root.padding * 2

    // Soft outer glow when enabled
    Rectangle {
        id: glowRect
        visible: root.glow
        anchors.fill:    bg
        anchors.margins: -4
        radius:          bg.radius + 4
        color:           Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.13)
        border.width:    0
        z:               -1
    }

    Rectangle {
        id: bg
        anchors.fill: parent
        radius:       Theme.radiusLarge
        color:        Theme.bgSurface
        border.color: ma.containsMouse
                      ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.40)
                      : Theme.strokeSubtle
        border.width: 1

        Behavior on border.color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

        Item {
            id: inner
            anchors {
                fill:    parent
                margins: root.padding
            }
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: true
            // Pass through clicks to children
            propagateComposedEvents: true
            onClicked: (mouse) => mouse.accepted = false
        }
    }
}
