import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming

Item {
    id: root

    required property string title
    required property string message
    property url iconSource

    implicitWidth:  280
    implicitHeight: col.implicitHeight

    Column {
        id: col
        anchors.centerIn: parent
        spacing:          Theme.spacingM
        width:            Math.min(parent.width, 320)

        Image {
            visible:  root.iconSource.toString().length > 0
            source:   root.iconSource
            width:    48; height: 48
            fillMode: Image.PreserveAspectFit
            sourceSize.width: 96; sourceSize.height: 96
            anchors.horizontalCenter: parent.horizontalCenter
            opacity: 0.5
        }

        Text {
            width:               parent.width
            horizontalAlignment: Text.AlignHCenter
            text:   root.title
            color:  Theme.textSecondary
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeTitle
            font.weight:    Theme.fontWeightMedium
        }

        Text {
            width:               parent.width
            horizontalAlignment: Text.AlignHCenter
            text:    root.message
            color:   Theme.textMuted
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeBody
            wrapMode: Text.WordWrap
        }
    }

    Accessible.role:        Accessible.StaticText
    Accessible.name:        root.title
    Accessible.description: root.message
}
