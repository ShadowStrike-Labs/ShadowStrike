import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property url    iconSource
    property int    iconSize:  Theme.fontSizeTitle
    property string tooltip:   ""
    property bool   enabled:   true
    signal clicked()

    implicitWidth:  Theme.controlHeight
    implicitHeight: Theme.controlHeight
    opacity: root.enabled ? 1.0 : Theme.disabledOpacity
    Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

    Rectangle {
        id: bg
        anchors.fill: parent
        radius:       Theme.radiusSmall
        color:        ma.containsMouse && root.enabled ? Theme.surfaceColor(false, true) : "transparent"
        border.color: Theme.highContrast ? Theme.strokeStrong : (ma.containsMouse && root.enabled ? Theme.strokeStrong : "transparent")
        border.width: Theme.highContrast ? 2 : 1
        Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        Image {
            source:              root.iconSource
            width:               root.iconSize
            height:              root.iconSize
            anchors.centerIn:    parent
            fillMode:            Image.PreserveAspectFit
            sourceSize.width:    root.iconSize * 2
            sourceSize.height:   root.iconSize * 2
            opacity: root.enabled ? 1.0 : Theme.disabledOpacity
        }

        MouseArea {
            id: ma
            anchors.fill:  parent
            enabled:       root.enabled
            hoverEnabled:  root.enabled
            cursorShape:   root.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked:     root.clicked()
        }

        ToolTip.visible: root.tooltip.length > 0 && ma.containsMouse
        ToolTip.text:    root.tooltip
        ToolTip.delay:   600

        FocusRing { target: bg }
    }

    Keys.onSpacePressed:  if (root.enabled) root.clicked()
    Keys.onReturnPressed: if (root.enabled) root.clicked()
    activeFocusOnTab:     root.enabled

    Accessible.role:        Accessible.Button
    Accessible.name:        root.tooltip.length > 0 ? root.tooltip : qsTr("Icon button")
    Accessible.description: qsTr("Activate")
}
