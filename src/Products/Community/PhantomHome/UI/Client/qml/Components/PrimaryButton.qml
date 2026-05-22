import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property alias text: label.text
    property bool   busy:    false
    property bool   enabled: true
    property string accessibleName: label.text
    signal clicked()

    implicitWidth:  Math.max(128, label.implicitWidth + Theme.spacingXL * 2)
    implicitHeight: Theme.controlHeight

    opacity: root.enabled ? 1.0 : Theme.disabledOpacity
    Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

    Rectangle {
        id: bg
        anchors.fill: parent
        radius: Theme.radiusMedium
        border.color: Theme.highContrast ? Theme.strokeStrong
                                          : Qt.rgba(Theme.accentGlow.r, Theme.accentGlow.g, Theme.accentGlow.b,
                                                    ma.containsMouse && root.enabled ? 0.9 : 0.0)
        border.width: Theme.highContrast ? 2 : 1

        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: root.enabled && (ma.containsMouse || ma.pressed) ? Qt.lighter(Theme.accentBlue, 1.15) : Theme.accentBlue }
            GradientStop { position: 1.0; color: root.enabled && (ma.containsMouse || ma.pressed) ? Qt.lighter(Theme.accentCyan, 1.08) : Theme.accentCyan }
        }
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        transform: Scale {
            origin.x: bg.width / 2
            origin.y: bg.height / 2
            xScale: root.enabled && !Theme.reducedMotion ? (ma.pressed ? 0.98 : (ma.containsMouse ? 1.015 : 1.0)) : 1.0
            yScale: xScale
            Behavior on xScale { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        }

        BusyIndicator {
            id: busyInd
            visible: root.busy
            anchors.centerIn: parent
            width:  20; height: 20
            running: root.busy
            palette.dark: Theme.highContrast ? Theme.bgDeep : Theme.textPrimary
        }

        Text {
            id: label
            visible: !root.busy
            anchors.centerIn: parent
            color: Theme.textPrimary
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeBody
            font.weight:    Theme.fontWeightMedium
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: root.enabled
            enabled:      root.enabled && !root.busy
            cursorShape:  root.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked:    root.clicked()
        }

        FocusRing { target: bg }
    }

    Keys.onSpacePressed:  { if (root.enabled && !root.busy) root.clicked() }
    Keys.onReturnPressed: { if (root.enabled && !root.busy) root.clicked() }
    activeFocusOnTab: root.enabled

    Accessible.role:        Accessible.Button
    Accessible.name:        root.accessibleName.length > 0 ? root.accessibleName : label.text
    Accessible.description: root.busy ? qsTr("Loading") : qsTr("Activate")
}
