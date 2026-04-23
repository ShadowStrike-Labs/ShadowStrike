import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Accessibility
import ShadowStrike.Components.Icons

Item {
    id: root

    property bool collapsed:      false
    property int  selectedIndex:  0

    // Ordered route keys aligned 1:1 with the nav model below.  Kept as a
    // property so Main.qml's route map and this file remain in sync without
    // duplicating the strings in two places.
    readonly property var navRoutes: [
        "dashboard",
        "security",
        "performance",
        "privacy"
    ]

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

            // Logo area
            Item {
                width:  parent.width
                height: Theme.topBarHeight + Theme.spacingS

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
                        // TODO: wire configBridge from main.cpp
                        if (typeof configBridge !== "undefined" && configBridge !== null) {
                            configBridge.setSidebarCollapsed(root.collapsed)
                        }
                    }
                }

                // Logo mark
                Rectangle {
                    id: logoMark
                    width:  32; height: 32
                    radius: 16
                    anchors {
                        left:           parent.left
                        leftMargin:     root.collapsed
                                        ? (parent.width - width) / 2
                                        : Theme.spacingM
                        verticalCenter: parent.verticalCenter
                    }
                    Behavior on anchors.leftMargin { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

                    color: Theme.bgSurfaceAlt
                    border.color: Theme.accentCyan
                    border.width: 2

                    // Outer glow
                    Rectangle {
                        anchors.fill:    parent
                        anchors.margins: -4
                        radius:          parent.radius + 4
                        color:           Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.18)
                        z: -1
                    }

                    Text {
                        anchors.centerIn: parent
                        text:  "S"
                        color: Theme.accentCyan
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        font.weight:    Theme.fontWeightBold
                    }
                    // TODO: assets-logo-embed — replace with actual logo raster from qml.qrc once available.
                }

                // Product name (hidden when collapsed)
                Text {
                    visible: !root.collapsed
                    anchors {
                        left:           logoMark.right
                        leftMargin:     Theme.spacingS
                        verticalCenter: parent.verticalCenter
                    }
                    text:  qsTr("ShadowStrike")
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    font.weight:    Theme.fontWeightBold
                    opacity: root.collapsed ? 0 : 1
                    Behavior on opacity { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
                }
            }

            // Navigation items
            Repeater {
                id: navRepeater
                model: [
                    { label: qsTr("Main"),        icon: "qrc:/icons/shield.svg"  },
                    { label: qsTr("Security"),    icon: "qrc:/icons/lock.svg"    },
                    { label: qsTr("Performance"), icon: "qrc:/icons/gauge.svg"   },
                    { label: qsTr("Privacy"),     icon: "qrc:/icons/eye.svg"     }
                ]

                SidebarItem {
                    required property var modelData
                    required property int index
                    label:     modelData.label
                    iconSource: modelData.icon
                    selected:   root.selectedIndex === index
                    collapsed:  root.collapsed
                    onActivated: {
                        root.selectedIndex = index
                        root.selectionChanged(index)
                        if (index >= 0 && index < root.navRoutes.length) {
                            root.navigate(root.navRoutes[index])
                        }
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
