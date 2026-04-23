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

        // Maps route string → QML component URL.
        readonly property var routeMap: ({
            "performance":   "qrc:/qml/Pages/PerformancePage.qml",
            "privacy":       "qrc:/qml/Pages/PrivacyPage.qml",
            "zerotrust":     "qrc:/qml/Pages/ZeroTrustDetailPage.qml"
        })

        function navigateTo(route) {
            const url = routeMap[route];
            if (url !== undefined) {
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
