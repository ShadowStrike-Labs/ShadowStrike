// ShadowStrike - Enterprise NGAV/EDR Platform
// Main.qml — Top-level application window for ShadowStrike Phantom Home UI.
//
// Layout:
//   ┌─────────┬─────────────────────────────────┐
//   │         │        TopBar                    │
//   │ Sidebar ├─────────────────────────────────┤
//   │         │                                 │
//   │         │       StackView (pages)          │
//   │         │                                 │
//   └─────────┴─────────────────────────────────┘
//
// Single-instance activation:
//   windowActivator.activate → raise() + requestActivate()
//
// Route navigation:
//   initialRoute (context property, string) → StackView.replace(page)

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ShadowStrike.Theming 1.0
import ShadowStrike.Accessibility 1.0
import ShadowStrike.Components 1.0

ApplicationWindow {
    id: root

    title:   qsTr("ShadowStrike Phantom Home")
    width:   1100
    height:  680
    minimumWidth:  860
    minimumHeight: 540
    visible: true

    // Theme-driven background — zero white flash on startup.
    color: Theme.bgDeep

    // ── Single-instance activation ─────────────────────────────────────────
    Connections {
        target: windowActivator
        function onActivate() {
            root.show();
            root.raise();
            root.requestActivate();
        }
    }

    // ── Window active ↔ animation budget ──────────────────────────────────
    onActiveChanged: perfBudget.onWindowActiveChanged(active)

    // ── Root layout ────────────────────────────────────────────────────────
    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Sidebar navigation
        Sidebar {
            id: sidebar
            Layout.fillHeight: true
            Layout.preferredWidth: Theme.sidebarWidthExpanded

            onNavigate: function(route) {
                d.navigateTo(route);
            }
        }

        // Right pane: TopBar + page content
        ColumnLayout {
            Layout.fillWidth:  true
            Layout.fillHeight: true
            spacing: 0

            TopBar {
                id:     topBar
                Layout.fillWidth: true
                Layout.preferredHeight: Theme.topBarHeight
                pageTitle: d.currentTitle
            }

            // Page host — holds the StackView
            PageHost {
                id:     pageHost
                Layout.fillWidth:  true
                Layout.fillHeight: true
            }
        }
    }

    // ── Private navigation logic ───────────────────────────────────────────
    QtObject {
        id: d

        // Current route key (mirrors what was last requested via navigateTo).
        property string currentRoute: "dashboard"

        // Human-readable title for the TopBar.  Derived from currentRoute via
        // a small lookup so TopBar and the routeMap stay in sync in one place.
        readonly property var titleMap: ({
            "dashboard":   qsTr("Dashboard"),
            "security":    qsTr("Security"),
            "performance": qsTr("Performance"),
            "privacy":     qsTr("Privacy"),
            "zerotrust":   qsTr("Zero Trust"),
            "pgti":        qsTr("Threat Intelligence"),
            "quarantine":  qsTr("Quarantine"),
            "reports":     qsTr("Reports"),
            "settings":    qsTr("Settings")
        })
        readonly property string currentTitle:
            (titleMap[currentRoute] !== undefined) ? titleMap[currentRoute] : ""

        // Maps route string → QML component URL.
        readonly property var routeMap: ({
            "dashboard":     "qrc:/qml/Pages/MainPage.qml",
            "security":      "qrc:/qml/Pages/SecurityPage.qml",
            "performance":   "qrc:/qml/Pages/PerformancePage.qml",
            "privacy":       "qrc:/qml/Pages/PrivacyPage.qml",
            "zerotrust":     "qrc:/qml/Pages/ZeroTrustDetailPage.qml",
            "pgti":          "qrc:/qml/Pages/PgtiDetailPage.qml",
            "quarantine":    "qrc:/qml/Pages/QuarantineSubroute.qml",
            "reports":       "qrc:/qml/Pages/ReportsSubroute.qml"
        })

        function navigateTo(route) {
            const url = routeMap[route];
            if (url !== undefined) {
                currentRoute = route;
                pageHost.navigateTo(url);
            }
        }
    }

    // ── Apply initial route from C++ ───────────────────────────────────────
    Component.onCompleted: {
        const route = initialRoute;
        if (route && route !== "") {
            d.navigateTo(route);
        }
    }
}
