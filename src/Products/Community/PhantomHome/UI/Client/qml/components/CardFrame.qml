import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * CardFrame
 * ---------
 * Panel used to group related controls. Provides:
 *   - subtle vertical gradient (reads as lifted surface on dark bg)
 *   - 1 px hairline border
 *   - optional title text
 *   - default property area for children (Column.children, list<Item>).
 *
 * NOTE: Only visual Items may be placed as children. Non-visual QtObjects
 * such as ButtonGroup must live at the enclosing scope, not inside a card.
 */
Rectangle {
    id: root
    color: "transparent"
    border.width: 0
    radius: Theme.radiusMd
    implicitHeight: contentHost.implicitHeight + Theme.sp5 * 2

    property string title: ""
    property string subtitle: ""
    property bool   padded: true

    default property alias contentChildren: inner.children

    // Gradient fill layer (darker at the bottom for depth).
    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        gradient: Gradient {
            GradientStop { position: 0.0; color: Theme.bg2 }
            GradientStop { position: 1.0; color: Qt.darker(Theme.bg2, 1.10) }
        }
        border.color: Theme.stroke
        border.width: 1
    }

    // Thin accent highlight on the top edge (1 px) for definition.
    Rectangle {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 1
        anchors.leftMargin: 1
        anchors.rightMargin: 1
        height: 1
        radius: 1
        color: Qt.rgba(1, 1, 1, 0.04)
    }

    ColumnLayout {
        id: contentHost
        anchors.fill: parent
        anchors.margins: root.padded ? Theme.sp5 : 0
        spacing: Theme.sp3

        Column {
            id: titleBlock
            visible: root.title.length > 0
            Layout.fillWidth: true
            spacing: 2
            Text {
                text: root.title
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontHeading
                font.weight: Font.DemiBold
            }
            Text {
                visible: root.subtitle.length > 0
                text: root.subtitle
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap
                width: parent.width
            }
        }

        ColumnLayout {
            id: inner
            Layout.fillWidth: true
            spacing: Theme.sp3
        }
    }
}
