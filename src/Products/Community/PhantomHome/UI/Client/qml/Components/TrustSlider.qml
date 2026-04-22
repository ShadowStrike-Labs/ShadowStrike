import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property real value:         0.85
    property bool zeroTrustMode: false
    signal valueChanged(real v)

    implicitWidth:  400
    implicitHeight: 80

    // When zeroTrustMode flips true: animate value to 0.999 and lock
    onZeroTrustModeChanged: {
        if (root.zeroTrustMode) {
            lockAnim.start()
        }
    }

    NumberAnimation {
        id:       lockAnim
        target:   root
        property: "value"
        to:       0.999
        duration: 240
        easing.type: Theme.easingType
        onFinished: root.valueChanged(root.value)
    }

    // Posture label from value
    readonly property string _posture: {
        if (root.value >= 0.999) return qsTr("Zero-Trust")
        if (root.value >= 0.95)  return qsTr("Aggressive")
        if (root.value >= 0.85)  return qsTr("Balanced")
        if (root.value >= 0.50)  return qsTr("Standard")
        return qsTr("Permissive")
    }

    Column {
        anchors.fill: parent
        spacing: Theme.spacingXS

        // Thumb value tag — shown on drag
        Item {
            width:  parent.width
            height: 20

            Rectangle {
                id: valueTag
                width:   52; height: 18
                radius:  Theme.radiusSmall
                color:   Theme.bgSurfaceAlt
                border.color: Theme.accentCyan
                border.width: 1
                visible: trackArea.pressed || root.zeroTrustMode
                x: Math.max(0, Math.min(track.width - width,
                   (track.width - thumbRect.width) * root.value + thumbRect.width / 2 - width / 2))

                Text {
                    anchors.centerIn: parent
                    text:  root.value.toFixed(3)
                    color: Theme.accentCyan
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMicro
                    font.weight:    Theme.fontWeightMedium
                }
            }
        }

        // Track + thumb
        Item {
            id: track
            width:  parent.width
            height: 8
            anchors.horizontalCenter: parent.horizontalCenter

            // Track gradient: warn → accentCyan → accentBlue → crit
            Rectangle {
                anchors.fill: parent
                radius: height / 2
                gradient: Gradient {
                    orientation: Gradient.Horizontal
                    GradientStop { position: 0.00; color: Theme.warn }
                    GradientStop { position: 0.50; color: Theme.accentCyan }
                    GradientStop { position: 0.85; color: Theme.accentBlue }
                    GradientStop { position: 1.00; color: Theme.crit }
                }
                opacity: root.zeroTrustMode ? 0.85 : 1.0
                Behavior on opacity { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
            }

            // Filled portion up to thumb
            Rectangle {
                x:      0
                width:  thumbRect.x + thumbRect.width / 2
                height: parent.height
                radius: height / 2
                color:  "transparent"
            }

            // Thumb
            Rectangle {
                id: thumbRect
                width:  24; height: 24
                radius: 12
                anchors.verticalCenter: parent.verticalCenter
                x: (track.width - width) * root.value
                Behavior on x { NumberAnimation { duration: root.zeroTrustMode ? 240 : 0; easing.type: Theme.easingType } }

                gradient: Gradient {
                    GradientStop { position: 0.0; color: Theme.accentCyan }
                    GradientStop { position: 1.0; color: Theme.accentBlue }
                }
                border.color: Theme.accentCyan
                border.width: 2

                // Pulse glow in zero-trust mode
                SequentialAnimation on scale {
                    running: root.zeroTrustMode
                    loops: Animation.Infinite
                    NumberAnimation { from: 1.0; to: 1.12; duration: 900;  easing.type: Easing.InOutSine }
                    NumberAnimation { from: 1.12; to: 1.0; duration: 900;  easing.type: Easing.InOutSine }
                }

                // Glow ring
                Rectangle {
                    anchors.fill:    parent
                    anchors.margins: -4
                    radius:          parent.radius + 4
                    color:           "transparent"
                    border.color:    Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b,
                                     root.zeroTrustMode ? 0.55 : 0.28)
                    border.width:    3
                    Behavior on border.color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
                }
            }

            // Tick marks
            Repeater {
                model: [
                    { pos: 0.000, lbl: "0.000" },
                    { pos: 0.500, lbl: "0.500" },
                    { pos: 0.850, lbl: "0.850" },
                    { pos: 0.950, lbl: "0.950" },
                    { pos: 0.999, lbl: "0.999" }
                ]
                delegate: Item {
                    required property var modelData
                    x: modelData.pos * (track.width - 2) - 1
                    y: track.height / 2 - 4
                    width: 2; height: 8

                    Rectangle {
                        width: 1; height: 8
                        color: Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 0.6)
                    }
                    Text {
                        anchors.top:              parent.bottom
                        anchors.topMargin:        2
                        anchors.horizontalCenter: parent.horizontalCenter
                        text:  modelData.lbl
                        color: Theme.textMuted
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeMicro
                    }
                }
            }

            MouseArea {
                id: trackArea
                anchors.fill:    parent
                anchors.margins: -12   // generous hit area
                enabled:         !root.zeroTrustMode
                cursorShape:     root.zeroTrustMode ? Qt.ForbiddenCursor : Qt.SizeHorCursor
                hoverEnabled:    true

                onPositionChanged: (mouse) => {
                    if (trackArea.pressed) {
                        var clamped = Math.max(0.0, Math.min(0.999,
                            (mouse.x - thumbRect.width / 2) / (track.width - thumbRect.width)))
                        root.value = clamped
                        root.valueChanged(clamped)
                    }
                }
                onClicked: (mouse) => {
                    var clamped = Math.max(0.0, Math.min(0.999,
                        (mouse.x - thumbRect.width / 2) / (track.width - thumbRect.width)))
                    root.value = clamped
                    root.valueChanged(clamped)
                }
            }
        }
    }

    // Keyboard navigation
    activeFocusOnTab: !root.zeroTrustMode
    Keys.onLeftPressed:  (ev) => {
        if (!root.zeroTrustMode) {
            var step = ev.modifiers & Qt.ShiftModifier ? 0.001 : 0.01
            root.value = Math.max(0.0, root.value - step)
            root.valueChanged(root.value)
        }
    }
    Keys.onRightPressed: (ev) => {
        if (!root.zeroTrustMode) {
            var step = ev.modifiers & Qt.ShiftModifier ? 0.001 : 0.01
            root.value = Math.min(0.999, root.value + step)
            root.valueChanged(root.value)
        }
    }
    Keys.onHomePressed: {
        if (!root.zeroTrustMode) {
            root.value = 0.0
            root.valueChanged(root.value)
        }
    }
    Keys.onEndPressed: {
        if (!root.zeroTrustMode) {
            root.value = 0.999
            root.valueChanged(root.value)
        }
    }

    FocusRing { target: root }

    Accessible.role:        Accessible.Slider
    Accessible.name:        qsTr("Trust threshold")
    Accessible.description: root._posture
    Accessible.minimumValue: 0
    Accessible.maximumValue: 999
    Accessible.currentValue: Math.round(root.value * 1000)
}
