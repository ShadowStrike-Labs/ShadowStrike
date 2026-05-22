import QtQuick
import ShadowStrike.Theming

Item {
    id: root

    default property alias pageContent: host.data
    property var stack: null

    anchors.fill: parent

    Item {
        id: host
        anchors.fill: parent
    }

    // Entry animation: fade in + translate up
    opacity: 0
    y: 12

    Component.onCompleted: entryAnim.start()

    ParallelAnimation {
        id: entryAnim
        NumberAnimation {
            target:      root
            property:    "opacity"
            from:        0;  to: 1
            duration:    Theme.motionPage
            easing.type: Theme.easingType
        }
        NumberAnimation {
            target:      root
            property:    "y"
            from:        12; to: 0
            duration:    Theme.motionPage
            easing.type: Theme.easingType
        }
    }
}
