import QtQuick
import QtQuick.Layouts
import "../Theming"

/*
 * SectionHeader
 * -------------
 * Small-caps label, thin divider line, optional count pill. Used to
 * separate visual sections inside a page without dropping a heavy
 * border.
 */
Item {
    id: root

    property string sectionTitle: ""
    property int    count:        -1

    implicitHeight: 28
    Layout.fillWidth: true

    RowLayout {
        anchors.fill: parent
        spacing: Theme.sp3

        Text {
            text: root.sectionTitle.toUpperCase()
            color: Theme.textDim
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontCaption
            font.weight: Font.DemiBold
            font.letterSpacing: 1.2
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            height: 1
            color: Qt.rgba(1, 1, 1, 0.06)
        }

        Rectangle {
            visible: root.count >= 0
            Layout.preferredWidth: cntLabel.implicitWidth + Theme.sp3
            Layout.preferredHeight: 18
            radius: 9
            color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.15)
            Text {
                id: cntLabel
                anchors.centerIn: parent
                text: root.count
                color: Theme.accentAlt
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontCaption
                font.weight: Font.DemiBold
            }
        }
    }
}
