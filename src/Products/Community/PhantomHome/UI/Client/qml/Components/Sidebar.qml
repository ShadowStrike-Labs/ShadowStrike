import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility
import ShadowStrike.Components.Icons

Item {
    id: root

    property bool collapsed:      false

    // THE ROUTE CURRENTLY SHOWN, supplied by Main.qml. Single source of truth.
    //
    // The highlight used to be local mutable state written by the click
    // handler, so it only ever tracked clicks ON THIS BAR. Every other way of
    // reaching a page - an in-page card, a recommendation, the tray verb, the
    // -route command line - left the bar pointing at whatever was last
    // clicked. Main.qml's d.currentRoute is updated by BOTH navigation paths
    // (navigateTo for a route and navigateToUrl for a stack push, which
    // resolves the url back to its route key), so binding to it is what makes
    // the highlight follow the page instead of the pointer.
    property string currentRoute: "dashboard"

    // NAVIGATION MODEL - ONE list, and that is the point.
    //
    // This was two parallel arrays: a navRoutes list of route keys and an
    // inline Repeater model of label/icon pairs, joined only by a shared
    // index. Nothing checked that they stayed the same length or the same
    // order, so adding an entry to one and not the other would silently
    // navigate to the wrong page - and adding to the model alone would index
    // past the end of navRoutes and navigate nowhere at all. Merging them
    // makes that class of mistake unrepresentable rather than merely unlikely.
    //
    // navRoutes had no reader outside this file (measured), so nothing
    // depended on the split shape.
    readonly property var navItems: [
        { route: "dashboard", label: qsTr("Main"),     icon: "qrc:/icons/shield.svg"  },
        { route: "security",  label: qsTr("Security"), icon: "qrc:/icons/lock.svg"    },
        { route: "privacy",   label: qsTr("Privacy"),  icon: "qrc:/icons/eye.svg"     },
        { route: "reports",   label: qsTr("Reports"),  icon: "qrc:/icons/reports.svg" }
    ]

    // WHICH ENTRY IS LIT, derived rather than stored.
    //
    // -1 IS A REAL ANSWER AND IS DELIBERATE: Settings, Quarantine, Threat
    // Intelligence, Zero Trust and the module detail pages have no entry in
    // this bar, and on those pages NOTHING should be lit. Falling back to 0
    // would light "Main" while the user is somewhere else, which is a nav bar
    // reporting a location it does not have.
    readonly property int selectedIndex: {
        for (var i = 0; i < root.navItems.length; ++i) {
            if (root.navItems[i].route === root.currentRoute) {
                return i
            }
        }
        return -1
    }

    // Legacy numeric signal — retained so any existing listeners keep working.
    signal selectionChanged(int index)

    // High-level navigation signal consumed by Main.qml.  Emitted whenever the
    // user picks a sidebar item or the settings button; carries the route key
    // that Main.qml's routeMap understands.
    signal navigate(string route)

    signal settingsClicked()

    width: root.collapsed ? Theme.sidebarWidthCollapsed : Theme.sidebarWidthExpanded
    Behavior on width { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

    implicitHeight: 600

    Rectangle {
        anchors.fill:  parent
        color:         Theme.bgSurface
        border.color:  Theme.strokeSubtle
        border.width:  1

        Column {
            anchors {
                top:    parent.top
                left:   parent.left
                right:  parent.right
            }

            // Brand header — product logo + wordmark
            Item {
                width:  parent.width
                height: 72

                // Collapse toggle (chevron)
                IconButton {
                    id: collapseBtn
                    anchors {
                        right:         parent.right
                        rightMargin:   Theme.spacingXS
                        verticalCenter: parent.verticalCenter
                    }
                    iconSource: root.collapsed ? "qrc:/icons/chevron_right.svg" : "qrc:/icons/chevron_left.svg"
                    tooltip:    root.collapsed ? qsTr("Expand sidebar") : qsTr("Collapse sidebar")
                    onClicked: {
                        root.collapsed = !root.collapsed
                        if (typeof configBridge !== "undefined" && configBridge !== null) {
                            configBridge.setSidebarCollapsed(root.collapsed)
                        }
                    }
                }

                // Brand logo
                Image {
                    id: logoMark
                    width:  34; height: 34
                    fillMode: Image.PreserveAspectFit
                    smooth:  true
                    mipmap:  true
                    source:  "qrc:/qml/assets/logo.png"
                    sourceSize.width: 68; sourceSize.height: 68
                    anchors {
                        left:           parent.left
                        leftMargin:     root.collapsed
                                        ? (parent.width - width) / 2
                                        : Theme.spacingM
                        verticalCenter: parent.verticalCenter
                    }
                    Behavior on anchors.leftMargin { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
                }

                // Wordmark: vendor + product edition (hidden when collapsed)
                Column {
                    id: wordmark
                    visible: !root.collapsed
                    spacing: 1
                    anchors {
                        left:           logoMark.right
                        leftMargin:     Theme.spacingS
                        right:          collapseBtn.left
                        rightMargin:    Theme.spacingXS
                        verticalCenter: parent.verticalCenter
                    }
                    opacity: root.collapsed ? 0 : 1
                    Behavior on opacity { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

                    Text {
                        width: parent.width
                        text:  qsTr("ShadowStrike-Labs")
                        color: Theme.textPrimary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        font.weight:    Theme.fontWeightBold
                        elide: Text.ElideRight
                    }
                    Text {
                        width: parent.width
                        text:  qsTr("Phantom Home")
                        color: Theme.textMuted
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeMicro
                        font.weight:    Theme.fontWeightRegular
                        elide: Text.ElideRight
                    }
                }
            }

            // Navigation items
            Repeater {
                id: navRepeater
                model: root.navItems

                SidebarItem {
                    required property var modelData
                    required property int index
                    label:      modelData.label
                    iconSource: modelData.icon
                    selected:   root.selectedIndex === index
                    collapsed:  root.collapsed
                    onActivated: {
                        // The route travels WITH the entry, so there is no
                        // index to keep aligned with a second list and no
                        // bounds check to get wrong. selectedIndex updates
                        // when Main.qml reflects the new route back.
                        root.selectionChanged(index)
                        root.navigate(modelData.route)
                    }
                }
            }
        }

        // Settings button at bottom
        IconButton {
            id: settingsBtn
            anchors {
                bottom:          parent.bottom
                bottomMargin:    Theme.spacingL
                horizontalCenter: parent.horizontalCenter
            }
            iconSource: "qrc:/icons/gear.svg"
            tooltip:    qsTr("Settings")
            onClicked: {
                root.settingsClicked()
                root.navigate("settings")
            }
        }
    }

    Accessible.role: Accessible.ToolBar
    Accessible.name: qsTr("Navigation sidebar")
}
