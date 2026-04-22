import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property url    iconSource
    property int    iconSize:  Theme.fontSizeTitle
    property string tooltip:   ""
    signal clicked()

    implicitWidth:  36
    implicitHeight: 36

    Rectangle {
        id: bg
        anchors.fill: parent
        radius:       Theme.radiusSmall
        color:        ma.containsMouse ? Theme.bgSurfaceAlt : "transparent"
        Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        Image {
            source:              root.iconSource
            width:               root.iconSize
            height:              root.iconSize
            anchors.centerIn:    parent
            fillMode:            Image.PreserveAspectFit
            sourceSize.width:    root.iconSize * 2
            sourceSize.height:   root.iconSize * 2
        }

        MouseArea {
            id: ma
            anchors.fill:  parent
            hoverEnabled:  true
            cursorShape:   Qt.PointingHandCursor
            onClicked:     root.clicked()
        }

        ToolTip.visible: root.tooltip.length > 0 && ma.containsMouse
        ToolTip.text:    root.tooltip
        ToolTip.delay:   600

        FocusRing { target: bg }
    }

    Keys.onSpacePressed:  root.clicked()
    Keys.onReturnPressed: root.clicked()
    activeFocusOnTab:     true

    Accessible.role:        Accessible.Button
    Accessible.name:        root.tooltip.length > 0 ? root.tooltip : qsTr("Icon button")
    Accessible.description: qsTr("Activate")
}
