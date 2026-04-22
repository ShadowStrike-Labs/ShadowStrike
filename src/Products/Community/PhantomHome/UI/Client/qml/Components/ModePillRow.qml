import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property int currentMode          // 0=Off,1=Passive,2=Balanced,3=Aggressive
    required property int supportedModesMask   // bitmask
    signal modeChosen(int mode)

    implicitWidth:  pillRow.implicitWidth
    implicitHeight: 28

    readonly property var modeLabels: [qsTr("Off"), qsTr("Passive"), qsTr("Balanced"), qsTr("Aggressive")]
    readonly property var modeColors: [Theme.textMuted, Theme.warn, Theme.accentBlue, Theme.crit]

    // Sliding selection indicator
    Rectangle {
        id: selectionIndicator
        y:      0
        height: parent.height
        width:  pillRow.children.length > root.currentMode
                ? pillRow.children[root.currentMode].width : 0
        x:      pillRow.children.length > root.currentMode
                ? pillRow.children[root.currentMode].x : 0
        radius: Theme.radiusSmall
        color:  "transparent"

        Behavior on x     { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
        Behavior on width { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: {
                if (root.currentMode >= 2) return Theme.accentBlue
                if (root.currentMode === 1) return Theme.warn
                return Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 0.35)
            }}
            GradientStop { position: 1.0; color: {
                if (root.currentMode >= 2) return Theme.accentCyan
                if (root.currentMode === 1) return Qt.lighter(Theme.warn, 1.15)
                return Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 0.25)
            }}
        }
    }

    Row {
        id: pillRow
        spacing: Theme.spacingXS

        Repeater {
            model: 4
            delegate: Item {
                id: pillItem
                readonly property bool supported: (root.supportedModesMask & (1 << index)) !== 0
                readonly property bool isSelected: root.currentMode === index

                width:  pillLabel.implicitWidth + Theme.spacingM * 2
                height: 28
                opacity: supported ? 1.0 : 0.25

                Rectangle {
                    anchors.fill: parent
                    radius: Theme.radiusSmall
                    color: pillItem.isSelected
                           ? "transparent"   // covered by sliding indicator
                           : Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 0.10)
                    border.color: pillItem.isSelected ? "transparent" : Theme.strokeSubtle
                    border.width: 1
                }

                Text {
                    id: pillLabel
                    anchors.centerIn: parent
                    text:  root.modeLabels[index]
                    color: pillItem.isSelected ? Theme.textPrimary : Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLabel
                    font.weight:    pillItem.isSelected ? Theme.fontWeightMedium : Theme.fontWeightRegular
                    Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
                }

                MouseArea {
                    anchors.fill: parent
                    enabled:      pillItem.supported
                    cursorShape:  pillItem.supported ? Qt.PointingHandCursor : Qt.ForbiddenCursor
                    onClicked:    root.modeChosen(index)
                }

                FocusRing { target: pillItem }
                activeFocusOnTab: pillItem.supported

                Accessible.role:        Accessible.Button
                Accessible.name:        root.modeLabels[index]
                Accessible.description: pillItem.isSelected ? qsTr("Selected") : (pillItem.supported ? qsTr("Activate") : qsTr("Unsupported"))
            }
        }
    }
}
