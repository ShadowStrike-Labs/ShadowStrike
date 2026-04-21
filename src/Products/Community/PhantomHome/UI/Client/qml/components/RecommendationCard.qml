import QtQuick
import QtQuick.Layouts
import "../Theming"

/*
 * RecommendationCard
 * ------------------
 * Feature-promotion tile with a horizontal gradient background, a large
 * icon, a title/subtitle stack and a CTA arrow. Clicking anywhere
 * activates the card.
 */
Rectangle {
    id: root

    property string title:    ""
    property string subtitle: ""
    property string iconName: "bolt"
    property string ctaText:  qsTr("Learn more")
    property color  gradientStartColor: Theme.accent
    property color  gradientEndColor:   Theme.accentDeep

    signal activated()

    radius: Theme.radiusLg
    implicitHeight: content.implicitHeight + Theme.sp6 * 2
    clip: true
    border.width: 0

    gradient: Gradient {
        orientation: Gradient.Horizontal
        GradientStop { position: 0.0; color: root.gradientStartColor }
        GradientStop { position: 1.0; color: root.gradientEndColor }
    }

    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        color: Qt.rgba(1, 1, 1, 0.03)
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.activated()
    }
    Rectangle {
        anchors.fill: parent
        radius: parent.radius
        color: mouse.containsMouse ? Qt.rgba(1, 1, 1, 0.05) : "transparent"
        Behavior on color { ColorAnimation { duration: Theme.motionFast } }
    }

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: Theme.sp6
        spacing: Theme.sp3

        Iconed { iconName: root.iconName; size: 32; tint: "#FFFFFF" }

        Text {
            text: root.title
            color: "#FFFFFF"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSubhead
            font.weight: Font.DemiBold
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Text {
            text: root.subtitle
            color: Qt.rgba(1, 1, 1, 0.75)
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSmall
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }
        Item { Layout.fillHeight: true; implicitHeight: Theme.sp2 }
        Text {
            text: root.ctaText + " \u2192"
            color: "#FFFFFF"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSmall
            font.weight: Font.DemiBold
        }
    }
}
