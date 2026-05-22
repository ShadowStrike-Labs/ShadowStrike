// ShadowStrike PhantomHome — FocusRing.qml
// Renders a visible keyboard-focus indicator around any focusable Item.
// Import ShadowStrike.Accessibility 1.0 and attach as a child or sibling.
//
// Usage:
//   Button {
//       id: myBtn
//       FocusRing { target: myBtn }
//   }

import QtQuick
import ShadowStrike.Theming

Rectangle {
    id: ring

    // The item this ring tracks.  Must be set by the parent.
    required property Item target
    readonly property bool targetFocused:
        target ? (target.activeFocus || (target.parent && target.parent.activeFocus)) : false
    function resolvedRadius() {
        if (!target)
            return 0

        const value = target["radius"]
        return value === undefined ? 0 : value
    }

    anchors.fill:    target
    anchors.margins: -2

    // Match the target's corner radius so the ring hugs its shape.
    radius: resolvedRadius() + 2

    color:        "transparent"
    border.color: Theme.focusRingColor
    border.width: Theme.focusRingWidth

    visible: targetFocused
    opacity: visible ? 1.0 : 0.0

    Behavior on opacity {
        NumberAnimation {
            duration:     Theme.motionFast
            easing.type:  Theme.easingType
        }
    }
}
