import QtQuick
import QtQuick.Layouts
import "../Theming"

/*
 * Banner
 * ------
 * Slim callout strip used on MainPage for sensor-offline and
 * cortex-standby warnings. A colored accent bar on the left, an icon,
 * the message, and an optional right-aligned CTA. The whole strip is
 * clickable when a CTA is present.
 */
Item {
    id: root

    property string message:  ""
    property string iconName: "bolt"
    property string ctaText:  ""
    property color  barColor: Theme.warning

    signal activated()

    implicitHeight: 48
    Layout.fillWidth: true

    CardFrame {
        anchors.fill: parent
        padded: false
        accentBar: root.barColor
        elevated: false
        hoverable: root.ctaText.length > 0
        clickable: root.ctaText.length > 0
        onClicked: if (root.ctaText.length > 0) root.activated()

        RowLayout {
            Layout.fillWidth: true
            Layout.preferredHeight: root.implicitHeight
            Layout.leftMargin: Theme.sp6 + Theme.sp3
            Layout.rightMargin: Theme.sp4
            Layout.topMargin: Theme.sp3
            Layout.bottomMargin: Theme.sp3
            spacing: Theme.sp3

            Iconed {
                iconName: root.iconName
                size: 16
                tint: root.barColor
            }
            Text {
                Layout.fillWidth: true
                text: root.message
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap
            }
            Text {
                visible: root.ctaText.length > 0
                text: root.ctaText
                color: Theme.accentAlt
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                font.weight: Font.DemiBold
            }
        }
    }
}
