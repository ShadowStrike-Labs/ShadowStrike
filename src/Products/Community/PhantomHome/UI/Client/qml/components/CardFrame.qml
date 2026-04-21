import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * CardFrame
 * ---------
 * Panel used to group related controls. Borderless, tone-based - depth
 * comes from the bg2 -> bg3 step rather than a stroke. Provides:
 *   - optional title / subtitle block
 *   - default child area (contentChildren)
 *   - optional hover elevation (bg2 -> bg3)
 *   - optional clickable surface with pointer cursor
 *   - optional left accent bar for emphasis (blue/green/amber)
 *
 * NOTE: Only visual Items may be placed as children. Non-visual QtObjects
 * such as ButtonGroup must live at the enclosing scope, not inside a card.
 */
Rectangle {
    id: root
    color: "transparent"
    border.width: 0
    radius: Theme.radiusMd
    implicitHeight: contentHost.implicitHeight + (root.padded ? Theme.sp5 * 2 : 0)

    property string title: ""
    property string subtitle: ""
    property bool   padded: true

    // Light polish extensions (opt-in; default behavior matches the
    // legacy CardFrame so every existing caller stays pixel-compatible).
    property bool   hoverable:  false
    property bool   clickable:  false
    property color  accentBar:  "transparent"
    property bool   elevated:   false
    signal clicked()
    signal doubleClicked()

    default property alias contentChildren: inner.children

    // --- Surface ---------------------------------------------------------
    Rectangle {
        id: surface
        anchors.fill: parent
        radius: parent.radius
        color: (root.elevated || ((root.hoverable || root.clickable) && mouse.containsMouse))
               ? Theme.bg3
               : Theme.bg2
        Behavior on color { ColorAnimation { duration: Theme.motionFast } }
    }

    // --- Optional accent bar (left edge, 3 px) ---------------------------
    Rectangle {
        visible: root.accentBar !== "transparent"
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.leftMargin: Theme.sp2
        anchors.topMargin: Theme.sp3
        anchors.bottomMargin: Theme.sp3
        width: 3
        radius: 1.5
        color: root.accentBar
    }

    // --- Hover / click surface (sits under content, above background) ----
    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: root.hoverable || root.clickable
        acceptedButtons: Qt.LeftButton
        cursorShape: root.clickable ? Qt.PointingHandCursor : Qt.ArrowCursor
        enabled: root.hoverable || root.clickable
        onClicked: if (root.clickable) root.clicked()
        onDoubleClicked: if (root.clickable) root.doubleClicked()
        propagateComposedEvents: true
    }

    // --- Content ---------------------------------------------------------
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
                color: Theme.textStrong
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
