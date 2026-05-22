import QtQuick
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    default property alias content: inner.children
    property int   padding: Theme.spacingL
    property color accent:  Theme.accentCyan
    property bool  glow:    false
    property bool  elevated: false
    property bool  interactive: false
    property bool  selected: false
    property string accessibleName: ""

    implicitWidth:  Theme.cardMinWidth
    implicitHeight: inner.implicitHeight + root.padding * 2
    activeFocusOnTab: root.interactive

    // Soft outer glow when enabled
    Rectangle {
        id: glowRect
        visible: root.glow && !Theme.highContrast
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
        color:        Theme.surfaceColor(root.elevated || root.selected, root.interactive && ma.containsMouse)
        border.color: root.selected ? root.accent
                                     : Theme.interactiveBorder(root.interactive && ma.containsMouse,
                                                               root.activeFocus,
                                                               "info")
        border.width: Theme.highContrast || root.selected ? 2 : 1

        Behavior on color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

        Item {
            id: inner
            anchors {
                fill:    parent
                margins: root.padding
            }
            implicitWidth:  childrenRect.width
            implicitHeight: childrenRect.height
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: root.interactive
            // Pass through clicks to children
            propagateComposedEvents: true
            onClicked: (mouse) => mouse.accepted = false
        }
    }

    FocusRing { target: root }

    Accessible.role: Accessible.Pane
    Accessible.name: root.accessibleName
}
