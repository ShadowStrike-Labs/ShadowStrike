import QtQuick
import QtQuick.Layouts
import "../Theming"

/*
 * QuickActionTile
 * ---------------
 * Compact clickable action tile. Icon chip, title, subtitle, tonal
 * hover. Used on MainPage for the row of top-level actions.
 */
Rectangle {
    id: root

    property string title:    ""
    property string subtitle: ""
    property string iconName: "bolt"

    signal activated()

    radius: Theme.radiusMd
    border.width: 0
    color: mouse.containsMouse ? Theme.bg3 : Theme.bg2
    implicitHeight: 88
    Layout.fillWidth: true
    Behavior on color { ColorAnimation { duration: Theme.motionFast } }

    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.activated()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.sp4
        spacing: Theme.sp2

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.sp3

            Rectangle {
                Layout.preferredWidth: 32
                Layout.preferredHeight: 32
                radius: Theme.radiusSm
                color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.15)
                Iconed { anchors.centerIn: parent; iconName: root.iconName; size: 18; tint: Theme.accentAlt }
            }
            Text {
                Layout.fillWidth: true
                text: root.title
                color: Theme.textStrong
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontBody
                font.weight: Font.DemiBold
                elide: Text.ElideRight
            }
        }
        Text {
            Layout.fillWidth: true
            text: root.subtitle
            color: Theme.textMuted
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSmall
            wrapMode: Text.WordWrap
            elide: Text.ElideRight
            maximumLineCount: 2
        }
    }
}
