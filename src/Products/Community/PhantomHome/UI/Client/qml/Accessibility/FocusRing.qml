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

    anchors.fill:    target
    anchors.margins: -2

    // Match the target's corner radius so the ring hugs its shape.
    radius: (target && target.radius !== undefined ? target.radius : 0) + 2

    color:        "transparent"
    border.color: Theme.accentCyan
    border.width: 2

    visible: target ? target.activeFocus : false
    opacity: visible ? 1.0 : 0.0

    Behavior on opacity {
        NumberAnimation {
            duration:     Theme.motionFast
            easing.type:  Easing.OutCubic
        }
    }
}
