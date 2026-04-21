import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../Theming"
import "../components"

/*
 * MainPage
 * --------
 * At-a-glance protection hub. HeroCard, conditional sensor/cortex
 * banners, recommendation promo row, quick-action grid, and a compact
 * activity timeline.
 */
Item {
    id: page

    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Protection status")

    property string protectionState:  "green"
    property string stateCopy:        "You are protected"
    property string stateSubCopy:     "Real-time protection is active."
    property string lastScan:         "\u2014"
    property int    threatsBlocked7d: 0
    property string updateStatus:     "Up to date"

    property bool   sensorOk:         true
    property string sensorReason:     ""
    property int    cortexActive:     0
    property int    cortexTotal:      0

    property var    modules:          []
    property var    recentEvents:     []

    signal startFastScan()
    signal openScanTab()
    signal openUpdateTab()
    signal openSecurityTab()
    signal openReportsTab()

    ScrollView {
        anchors.fill: parent
        clip: true

        ColumnLayout {
            width: page.width - 2
            spacing: Theme.sp5

            // --------------------------------------------------------
            //  HERO
            // --------------------------------------------------------
            HeroCard {
                Layout.fillWidth: true
                Layout.topMargin: Theme.sp6
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                protectionState:  page.protectionState
                stateCopy:        page.stateCopy
                stateSubCopy:     page.stateSubCopy
                lastScan:         page.lastScan
                threatsBlocked7d: page.threatsBlocked7d
                onDetailsRequested:  page.openSecurityTab()
                onFastScanRequested: page.startFastScan()
            }

            // --------------------------------------------------------
            //  Conditional banners — honest reporting of degraded
            //  sub-systems. Kernel sensor and Cortex are optional, so
            //  the user-mode engines still run without them; the
            //  banners are a call to action, not an error splash.
            // --------------------------------------------------------
            Banner {
                visible: !page.sensorOk
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                barColor: Theme.danger
                iconName: "bolt"
                message: page.sensorReason.length > 0
                         ? qsTr("Kernel sensor offline: %1").arg(page.sensorReason)
                         : qsTr("Kernel sensor is offline. Behavioural telemetry is limited.")
                ctaText: qsTr("Review security")
                onActivated: page.openSecurityTab()
            }
            Banner {
                visible: page.cortexTotal > 0 && page.cortexActive < page.cortexTotal
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                barColor: Theme.warning
                iconName: "radar"
                message: qsTr("%1 of %2 Cortex modules are running. Heuristic depth is reduced.")
                            .arg(page.cortexActive).arg(page.cortexTotal)
                ctaText: qsTr("Open details")
                onActivated: page.openSecurityTab()
            }

            // --------------------------------------------------------
            //  Recommendations
            // --------------------------------------------------------
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp4

                RecommendationCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 180
                    title: qsTr("Speed up your PC")
                    subtitle: qsTr("Run a quick tune-up to free disk space and disable unused startup items.")
                    iconName: "bolt"
                    ctaText: qsTr("Tune up now")
                    gradientStartColor: Theme.accent
                    gradientEndColor:   Theme.accentDeep
                    onActivated: page.openScanTab()
                }
                RecommendationCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 180
                    title: qsTr("Review privacy settings")
                    subtitle: qsTr("Check which apps have access to your camera, microphone, and location.")
                    iconName: "eye"
                    ctaText: qsTr("Open privacy")
                    gradientStartColor: Theme.bg3
                    gradientEndColor:   Theme.bg2
                    onActivated: page.openSecurityTab()
                }
            }

            // --------------------------------------------------------
            //  Quick actions
            // --------------------------------------------------------
            SectionHeader {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                sectionTitle: qsTr("Quick actions")
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                spacing: Theme.sp3

                QuickActionTile {
                    title: qsTr("Fast scan")
                    subtitle: qsTr("Quick sweep of hot paths")
                    iconName: "radar"
                    onActivated: page.startFastScan()
                }
                QuickActionTile {
                    title: qsTr("Full scan")
                    subtitle: qsTr("Comprehensive deep scan")
                    iconName: "shield"
                    onActivated: page.openScanTab()
                }
                QuickActionTile {
                    title: qsTr("Check updates")
                    subtitle: page.updateStatus
                    iconName: "bolt"
                    onActivated: page.openUpdateTab()
                }
                QuickActionTile {
                    title: qsTr("Reports")
                    subtitle: qsTr("View activity log")
                    iconName: "radar"
                    onActivated: page.openReportsTab()
                }
            }

            // --------------------------------------------------------
            //  Activity timeline
            // --------------------------------------------------------
            SectionHeader {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                sectionTitle: qsTr("Recent activity")
                count: page.recentEvents.length
            }
            CardFrame {
                Layout.fillWidth: true
                Layout.leftMargin: Theme.sp8
                Layout.rightMargin: Theme.sp8
                Layout.bottomMargin: Theme.sp8

                ActivityTimeline {
                    Layout.fillWidth: true
                    model: page.recentEvents
                    maxItems: 8
                }
            }
        }
    }
}
