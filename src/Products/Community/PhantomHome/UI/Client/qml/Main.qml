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
    // PerfBudgetContext exposes only the read-only `animationsPaused` property;
    // the PerfBudget::OnWindowActiveChanged static is called from the C++ side
    // (wired into ApplicationWindow::activeChanged after engine.load in main.cpp).
    // No-op here — kept as a hook point for future QML-side reaction.

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

            // Page host — Loader that swaps the current page QML on navigate.
            // Wrapped in an Item so the outer sizing is governed by the
            // RowLayout attached properties (Layout.fill*), while the Loader
            // inside uses anchors to fill that Item; the loaded page (whose
            // root is a PageHost) then fills the Loader via its own
            // anchors.fill: parent.  This keeps the layout contract clean:
            // no anchors on a Layout-managed item, no Layout.* on anchored
            // children.
            Item {
                id: pageHostContainer
                Layout.fillWidth:  true
                Layout.fillHeight: true

                Loader {
                    id: pageLoader
                    anchors.fill: parent
                    asynchronous: false
                    onStatusChanged: {
                        if (status === Loader.Error) {
                            console.warn("PageLoader failed to load source: " +
                                         source + " — " + sourceComponent);
                        }
                    }
                }

                function navigateTo(url) {
                    if (pageLoader.source !== url) {
                        pageLoader.source = url;
                    }
                }
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
                pageHostContainer.navigateTo(url);
            }
        }
    }

    // ── Apply initial route from C++ ───────────────────────────────────────
    Component.onCompleted: {
        const route = (initialRoute && initialRoute !== "") ? initialRoute : "dashboard";
        d.navigateTo(route);
    }
}
