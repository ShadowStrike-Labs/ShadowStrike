import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    property string placeholderText: qsTr("Search...")
    property alias  text:            input.text
    signal searchChanged(string query)

    implicitWidth:  280
    implicitHeight: 36

    Rectangle {
        id: bg
        anchors.fill: parent
        radius:       Theme.radiusMedium
        color:        Theme.bgSurface
        border.color: input.activeFocus
                      ? Theme.accentCyan
                      : (ma.containsMouse ? Theme.strokeSubtle : Theme.strokeSubtle)
        border.width: input.activeFocus ? 2 : 1
        Behavior on border.color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
        Behavior on border.width { NumberAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }

        // Search icon
        Image {
            id: searchIcon
            source: "qrc:/icons/search.svg"
            width:  16; height: 16
            fillMode: Image.PreserveAspectFit
            anchors {
                left:           parent.left
                leftMargin:     Theme.spacingM
                verticalCenter: parent.verticalCenter
            }
            opacity: 0.6
        }

        TextInput {
            id: input
            anchors {
                left:           searchIcon.right
                leftMargin:     Theme.spacingS
                right:          clearBtn.left
                rightMargin:    Theme.spacingS
                verticalCenter: parent.verticalCenter
            }
            color:             Theme.textPrimary
            selectionColor:    Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.35)
            selectedTextColor: Theme.textPrimary
            font.family:       Theme.fontFamily
            font.pixelSize:    Theme.fontSizeBody
            clip:              true

            onTextChanged: root.searchChanged(text)

            Text {
                anchors.fill: parent
                text:         root.placeholderText
                color:        Theme.textMuted
                font:         input.font
                visible:      input.text.length === 0 && !input.activeFocus
            }
        }

        // Clear button
        IconButton {
            id: clearBtn
            visible: input.text.length > 0
            anchors {
                right:          parent.right
                rightMargin:    Theme.spacingXS
                verticalCenter: parent.verticalCenter
            }
            iconSource: "qrc:/icons/close.svg"
            iconSize:   14
            tooltip:    qsTr("Clear search")
            onClicked:  { input.text = ""; root.searchChanged("") }
        }

        MouseArea {
            id: ma
            anchors.fill: parent
            hoverEnabled: true
            onClicked:    input.forceActiveFocus()
        }

        FocusRing { target: bg }
    }

    Accessible.role:        Accessible.EditableText
    Accessible.name:        root.placeholderText
    Accessible.description: qsTr("Search field")
}
