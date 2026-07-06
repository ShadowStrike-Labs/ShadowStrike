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
                model: [
                    { label: qsTr("Main"),     icon: "qrc:/icons/shield.svg" },
                    { label: qsTr("Security"), icon: "qrc:/icons/lock.svg"   },
                    { label: qsTr("Privacy"),  icon: "qrc:/icons/eye.svg"    }
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
