import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"

/*
 * Sidebar
 * -------
 * Left navigation rail for the Home product. Emits `navigate(index)`
 * when the user activates an item. Selection is driven externally so
 * the page stack remains the source of truth.
 *
 * Design:
 *   - Brand block at the top: accent glyph + name / product tier.
 *   - Nav items below: icon + label with an accent bar on the left
 *     when selected, soft hover tint otherwise.
 *   - Footer surfaces the connected-service state so the user can see
 *     at a glance whether the backend engine is live.
 */
Rectangle {
    id: root
    color:        Theme.bg1
    implicitWidth: Theme.sidebarWidth

    Accessible.role: Accessible.PageTabList
    Accessible.name: qsTr("Navigation")

    property int selectedIndex: 0
    signal navigate(int index)

    // Right-edge hairline to separate the sidebar from the page content.
    Rectangle {
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.right: parent.right
        width: 1
        color: Theme.stroke
    }

    // ----- Brand block ----------------------------------------------------
    Rectangle {
        id: brand
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        height: 76
        color: "transparent"

        Row {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.sp4
            spacing: Theme.sp3

            // Square brand mark (accent gradient).
            Rectangle {
                width: 40; height: 40
                radius: Theme.radiusSm
                anchors.verticalCenter: parent.verticalCenter
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Theme.accent }
                    GradientStop { position: 1.0; color: Theme.accentDeep }
                }
                border.color: Qt.rgba(1, 1, 1, 0.18)
                border.width: 1
                Text {
                    anchors.centerIn: parent
                    text: "\u2726"        // sparkle-like glyph
                    color: "#FFFFFF"
                    font.pixelSize: 20
                    font.bold: true
                }
            }
            Column {
                anchors.verticalCenter: parent.verticalCenter
                spacing: 0
                Text {
                    text: "ShadowStrike"
                    color: Theme.textStrong
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontHeading
                    font.weight: Font.DemiBold
                }
                Text {
                    text: "Phantom \u00B7 Home"
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                }
            }
        }

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.leftMargin: Theme.sp4
            anchors.rightMargin: Theme.sp4
            height: 1
            color: Theme.strokeSoft
        }
    }

    // ----- Nav model ------------------------------------------------------
    ListModel {
        id: navModel
        ListElement { label: "Home";        icon: "\uE80F" }   // home
        ListElement { label: "Security";    icon: "\uE72E" }   // shield
        ListElement { label: "Performance"; icon: "\uE9D9" }   // speed
        ListElement { label: "Privacy";     icon: "\uE72E" }   // lock-ish
        ListElement { label: "Scan";        icon: "\uE773" }   // search
        ListElement { label: "Quarantine";  icon: "\uE7BA" }   // alert
        ListElement { label: "Reports";     icon: "\uE9F9" }   // chart
        ListElement { label: "Settings";    icon: "\uE713" }   // gear
    }

    // Fallback text glyphs when Segoe MDL2 / Fluent isn't available.
    function glyphFor(i) {
        switch (i) {
        case 0: return "\u2302"            // house
        case 1: return "\u2749"            // sparkle / shield-ish
        case 2: return "\u25B2"            // up triangle (perf)
        case 3: return "\u25CF"            // filled circle (privacy)
        case 4: return "\u2316"            // target (scan)
        case 5: return "\u26A0"            // warning (quarantine)
        case 6: return "\u2261"            // bars (reports)
        case 7: return "\u2699"            // gear (settings)
        }
        return "\u25A0"
    }

    // ----- Nav list -------------------------------------------------------
    ListView {
        id: list
        anchors.top: brand.bottom
        anchors.topMargin: Theme.sp3
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
            height: 40

            Accessible.role: Accessible.PageTab
            Accessible.name: label
            Accessible.description: qsTr("Open %1 page").arg(label)

            Rectangle {
                id: pill
                anchors.fill: parent
                anchors.leftMargin: 4
                anchors.rightMargin: 4
                radius: Theme.radiusSm
                color: root.selectedIndex === index
                       ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
                       : mouse.containsMouse
                         ? Theme.overlayHover
                         : "transparent"
                border.color: root.selectedIndex === index ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.55) : "transparent"
                border.width: 1
                Behavior on color { ColorAnimation { duration: Theme.motionFast } }
            }

            // Left accent bar - visible only on selected item.
            Rectangle {
                anchors.left: pill.left
                anchors.verticalCenter: pill.verticalCenter
                width: 3
                height: 18
                radius: 1.5
                color: Theme.accent
                visible: root.selectedIndex === index
            }

            Row {
                anchors.verticalCenter: parent.verticalCenter
                anchors.left: parent.left
                anchors.leftMargin: Theme.sp4
                spacing: Theme.sp3

                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.glyphFor(index)
                    color: root.selectedIndex === index ? Theme.accentAlt : Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: 16
                    width: 18
                    horizontalAlignment: Text.AlignHCenter
                }
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    text: label
                    color: root.selectedIndex === index ? Theme.textStrong : Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    font.weight: root.selectedIndex === index ? Font.DemiBold : Font.Normal
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

            Keys.onReturnPressed: {
                root.selectedIndex = index
                root.navigate(index)
            }
        }
    }

    // ----- Footer (connection status) -------------------------------------
    Rectangle {
        id: footer
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        height: 48
        color: "transparent"

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.leftMargin: Theme.sp4
            anchors.rightMargin: Theme.sp4
            height: 1
            color: Theme.strokeSoft
        }

        Row {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: Theme.sp4
            spacing: Theme.sp2

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 8; height: 8; radius: 4
                color: Theme.success
            }
            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: "Engine online"
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
            }
        }
    }
}
