import QtQuick
import QtQuick.Controls
import "../Theming"

/*
 * CardFrame — a rounded panel used across pages for section grouping.
 * Set `title` and drop children in the default property area.
 */
Rectangle {
    id: root
    color: Theme.bg1
    border.color: Theme.stroke
    border.width: 1
    radius: Theme.radiusMd

    property string title: ""
    default property alias contentChildren: content.children

    Column {
        id: content
        anchors.fill: parent
        anchors.margins: Theme.sp4
        spacing: Theme.sp3

        Text {
            visible: root.title.length > 0
            text: root.title
            color: Theme.text
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontHeading
            font.weight: Font.DemiBold
        }
    }
}
