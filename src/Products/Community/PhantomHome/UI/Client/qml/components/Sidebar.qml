import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * Sidebar
 * -------
 * Left navigation rail. Kaspersky-style layout:
 *   - Compact brand block at top (small mark + product wordmark).
 *   - Quiet nav items: icon + label, left accent bar when selected, no
 *     border. Hover is a tonal fill, selection is a stronger tint.
 *   - Footer: engine status dot + Settings glyph.
 *
 * Selection is driven externally via `selectedIndex` so the page stack
 * remains the source of truth. Emits `navigate(index)` on activation.
 */
Rectangle {
    id: root
    color:         Theme.bg1
    implicitWidth: Theme.sidebarWidth

    Accessible.role: Accessible.PageTabList
    Accessible.name: qsTr("Navigation")

    property int  selectedIndex: 0
    property bool engineOnline:  true

    signal navigate(int index)
    signal openSettings()

    // ----- Brand block ----------------------------------------------------
    Item {
        id: brand
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: 72

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.sp5
            anchors.rightMargin: Theme.sp4
            spacing: Theme.sp3

            // Brand mark - rounded blue square with phantom glyph.
            Rectangle {
                Layout.preferredWidth: 36
                Layout.preferredHeight: 36
                radius: Theme.radiusSm
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Theme.accent }
                    GradientStop { position: 1.0; color: Theme.accentDeep }
                }
                Text {
                    anchors.centerIn: parent
                    text: "\u25C6"   // diamond glyph
                    color: "#FFFFFF"
                    font.pixelSize: 16
                    font.bold: true
                }
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 0
                Text {
                    text: "ShadowStrike"
                    color: Theme.textStrong
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSubhead
                    font.weight: Font.DemiBold
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }
                Text {
                    text: "Phantom Home"
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }
            }
        }
    }

    // ----- Nav model ------------------------------------------------------
    ListModel {
        id: navModel
        ListElement { label: qsTr("Home");        badge: ""   }
        ListElement { label: qsTr("Security");    badge: "AI" }
        ListElement { label: qsTr("Performance"); badge: ""   }
        ListElement { label: qsTr("Privacy");     badge: ""   }
        ListElement { label: qsTr("Scan");        badge: ""   }
        ListElement { label: qsTr("Quarantine");  badge: ""   }
        ListElement { label: qsTr("Reports");     badge: ""   }
        ListElement { label: qsTr("Identity");    badge: ""   }
    }

    // Monochrome geometric glyphs (work in every font).
    function glyphFor(i) {
        switch (i) {
        case 0: return "\u2302"   // house
        case 1: return "\u29CB"   // triangular outline (shield)
        case 2: return "\u25B2"   // up triangle (perf)
        case 3: return "\u25C9"   // fisheye (privacy)
        case 4: return "\u2316"   // target (scan)
        case 5: return "\u26A0"   // warning (quarantine)
        case 6: return "\u2261"   // bars (reports)
        case 7: return "\u25CE"   // bullseye (identity)
        }
        return "\u25A0"
    }

    // ----- Nav list -------------------------------------------------------
    ListView {
        id: list
        anchors.top: brand.bottom
        anchors.topMargin: Theme.sp2
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: footer.top
        anchors.leftMargin: Theme.sp2
        anchors.rightMargin: Theme.sp2
        model: navModel
        spacing: 2
        interactive: false
        clip: true

        delegate: Item {
            width: ListView.view.width
            height: 42

            Accessible.role: Accessible.PageTab
            Accessible.name: label

            Rectangle {
                id: pill
                anchors.fill: parent
                radius: Theme.radiusSm
                color: root.selectedIndex === index
                       ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.14)
                       : mouse.containsMouse ? Theme.overlayHover : "transparent"
                Behavior on color { ColorAnimation { duration: Theme.motionFast } }
            }

            // Left accent bar - visible only on selected item.
            Rectangle {
                anchors.left: pill.left
                anchors.verticalCenter: pill.verticalCenter
                anchors.leftMargin: 2
                width: 3
                height: 20
                radius: 1.5
                color: Theme.accent
                visible: root.selectedIndex === index
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.sp4
                anchors.rightMargin: Theme.sp3
                spacing: Theme.sp3

                Text {
                    Layout.preferredWidth: 18
                    horizontalAlignment: Text.AlignHCenter
                    text: root.glyphFor(index)
                    color: root.selectedIndex === index ? Theme.accentAlt : Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: 16
                }
                Text {
                    Layout.fillWidth: true
                    text: label
                    color: root.selectedIndex === index ? Theme.textStrong : Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    font.weight: root.selectedIndex === index ? Font.DemiBold : Font.Normal
                    elide: Text.ElideRight
                }
                // AI badge (appears on Security nav item only).
                Rectangle {
                    visible: badge && badge.length > 0
                    Layout.preferredHeight: 18
                    Layout.preferredWidth: aiLabel.implicitWidth + Theme.sp3
                    radius: 9
                    color: Theme.aiPillBg
                    Text {
                        id: aiLabel
                        anchors.centerIn: parent
                        text: badge
                        color: Theme.aiPillText
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontCaption
                        font.weight: Font.DemiBold
                    }
                }
            }

            MouseArea {
                id: mouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    root.selectedIndex = index
                    root.navigate(index)
                }
            }
        }
    }

    // ----- Footer (engine status + settings) ------------------------------
    Item {
        id: footer
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: 58

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.sp4
            anchors.rightMargin: Theme.sp3
            spacing: Theme.sp3

            // Engine status dot + caption.
            Rectangle {
                Layout.preferredWidth: 8
                Layout.preferredHeight: 8
                radius: 4
                color: root.engineOnline ? Theme.success : Theme.warning
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 0
                Text {
                    text: qsTr("Engine")
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontCaption
                }
                Text {
                    text: root.engineOnline ? qsTr("Online") : qsTr("Reconnecting")
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    font.weight: Font.Medium
                }
            }
            // Settings gear button.
            Rectangle {
                Layout.preferredWidth: 32
                Layout.preferredHeight: 32
                radius: Theme.radiusSm
                color: gearMouse.containsMouse ? Theme.overlayHover : "transparent"
                Behavior on color { ColorAnimation { duration: Theme.motionFast } }
                Text {
                    anchors.centerIn: parent
                    text: "\u2699"
                    color: gearMouse.containsMouse ? Theme.accentAlt : Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: 16
                }
                MouseArea {
                    id: gearMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.openSettings()
                }
            }
        }
    }
}
