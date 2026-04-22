import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string moduleName
    required property string displayName
    required property string iconSource
    required property string state           // "on"|"off"|"paused"|"warning"|"critical"
    required property bool   enabled
    required property int    currentMode     // 0..3
    required property int    supportedModesMask

    property string description: ""
    signal toggled(bool enabled)
    signal modeChosen(int mode)
    signal openDetail()

    implicitWidth:  300
    implicitHeight: contentCol.implicitHeight + Theme.spacingL * 2

    // Card background
    Rectangle {
        id: cardBg
        anchors.fill: parent
        radius:       Theme.radiusLarge
        color:        cardHover.containsMouse ? Theme.bgSurfaceAlt : Theme.bgSurface
        border.color: cardHover.containsMouse
                      ? Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.38)
                      : Theme.strokeSubtle
        border.width: 1
        Behavior on color        { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
        Behavior on border.color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

        // Background click — detect clicks not consumed by inner controls
        MouseArea {
            id: cardHover
            anchors.fill: parent
            hoverEnabled: true
            propagateComposedEvents: true
            cursorShape: Qt.PointingHandCursor
            onClicked: (mouse) => {
                // Only emit if the click wasn't caught by a child control
                if (!mouse.accepted) root.openDetail()
                mouse.accepted = false
            }
        }
    }

    Column {
        id: contentCol
        anchors {
            top:    parent.top
            left:   parent.left
            right:  parent.right
            margins: Theme.spacingL
        }
        spacing: Theme.spacingS

        // Header row: icon + name + status chip + toggle
        Row {
            width: parent.width
            spacing: Theme.spacingS

            Image {
                id: moduleIcon
                source:   root.iconSource
                width:    32; height: 32
                fillMode: Image.PreserveAspectFit
                sourceSize.width:  64; sourceSize.height: 64
                anchors.verticalCenter: parent.verticalCenter
            }

            Column {
                width:   parent.width - moduleIcon.width - statusChip.width - toggleSwitch.width - parent.spacing * 3
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

                Text {
                    text:  root.displayName
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    font.weight:    Theme.fontWeightBold
                    elide: Text.ElideRight
                    width: parent.width
                }

                Text {
                    visible: root.description.length > 0
                    text:    root.description
                    color:   Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMicro
                    wrapMode: Text.WordWrap
                    maximumLineCount: 2
                    elide: Text.ElideRight
                    width: parent.width
                }
            }

            StatusChip {
                id: statusChip
                state: root.state
                label: {
                    switch (root.state) {
                    case "on":       return qsTr("On")
                    case "off":      return qsTr("Off")
                    case "paused":   return qsTr("Paused")
                    case "warning":  return qsTr("Warning")
                    case "critical": return qsTr("Critical")
                    default:         return root.state
                    }
                }
                anchors.verticalCenter: parent.verticalCenter
            }

            ToggleSwitch {
                id: toggleSwitch
                checked: root.enabled
                anchors.verticalCenter: parent.verticalCenter
                onToggled: (v) => root.toggled(v)
                MouseArea {
                    anchors.fill: parent
                    propagateComposedEvents: true
                    onClicked: (mouse) => {
                        mouse.accepted = true   // stop card click from firing
                    }
                }
            }
        }

        // Mode pill row
        ModePillRow {
            id: modeRow
            currentMode:        root.currentMode
            supportedModesMask: root.supportedModesMask
            onModeChosen: (m) => root.modeChosen(m)
            MouseArea {
                anchors.fill: parent
                propagateComposedEvents: true
                onClicked: (mouse) => { mouse.accepted = true }
            }
        }
    }

    // Keyboard navigation
    activeFocusOnTab: true
    Keys.onReturnPressed: root.openDetail()
    Keys.onSpacePressed:  root.openDetail()

    FocusRing { target: root }

    Accessible.role:        Accessible.ListItem
    Accessible.name:        root.displayName
    Accessible.description: qsTr("%1, state: %2").arg(root.description).arg(root.state)
}
