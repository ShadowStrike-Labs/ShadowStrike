import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string label
    required property url    iconSource
    required property bool   selected
    required property bool   collapsed
    signal activated()

    width:  parent ? parent.width : 220
    height: 44

    // Left accent bar
    Rectangle {
        id: accentBar
        width:   3
        height:  parent.height
        anchors.left: parent.left
        color:   root.selected ? Theme.accentCyan : "transparent"
        Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
    }

    // Background
    Rectangle {
        id: itemBg
        anchors.fill: parent
        color: root.selected || ma.containsMouse ? Theme.bgSurfaceAlt : "transparent"
        Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        // Subtle cyan glow when selected
        Rectangle {
            visible:      root.selected
            anchors.fill: parent
            color:        Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.06)
        }

        Row {
            anchors {
                left:           parent.left
                leftMargin:     root.collapsed ? 0 : Theme.spacingM
                verticalCenter: parent.verticalCenter
            }
            spacing: Theme.spacingS

            Item {
                width: root.collapsed ? itemBg.width : 22
                height: 22
                anchors.verticalCenter: parent.verticalCenter

                Image {
                    source:   root.iconSource
                    width:    20; height: 20
                    fillMode: Image.PreserveAspectFit
                    anchors.centerIn: parent
                    sourceSize.width: 40; sourceSize.height: 40
                }
            }

            Text {
                id: itemLabel
                visible: !root.collapsed
                text:    root.label
                color:   root.selected ? Theme.accentCyan : Theme.textSecondary
                font.family:    Theme.fontFamily
                font.pixelSize: Theme.fontSizeBody
                font.weight:    root.selected ? Theme.fontWeightMedium : Theme.fontWeightRegular
                anchors.verticalCenter: parent.verticalCenter

                opacity: root.collapsed ? 0 : 1
                Behavior on opacity { NumberAnimation { duration: 80; easing.type: Theme.easingType } }
                Behavior on color   { ColorAnimation  { duration: Theme.motionFast; easing.type: Theme.easingType } }
            }
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: true
            cursorShape:  Qt.PointingHandCursor
            onClicked:    root.activated()
        }

        // Tooltip when collapsed
        ToolTip.visible: root.collapsed && ma.containsMouse
        ToolTip.text:    root.label
        ToolTip.delay:   400

        FocusRing { target: itemBg }
    }

    activeFocusOnTab: true
    Keys.onReturnPressed: root.activated()
    Keys.onSpacePressed:  root.activated()

    Accessible.role:        Accessible.MenuItem
    Accessible.name:        root.label
    Accessible.description: root.selected ? qsTr("Selected") : qsTr("Navigate to %1").arg(root.label)
}
