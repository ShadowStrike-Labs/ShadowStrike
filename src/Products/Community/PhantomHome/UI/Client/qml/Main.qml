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
//   windowActivator.activate(commandLine) → raise() + requestActivate()
//
// Route navigation:
//   initialRoute (context property, string) → StackView.replace(page)

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import ShadowStrike.Theming 1.0
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

    property string serviceAuthFailureReason: ""
    readonly property int serviceState:
        (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.state : 0
    readonly property bool serviceConnected:
        (typeof pipeClient !== "undefined" && pipeClient !== null) ? pipeClient.connected : false
    readonly property bool serviceBannerVisible: !serviceConnected

    function serviceStateLabel(state) {
        switch (state) {
        case 1:  return qsTr("Connecting to the ShadowStrike service…")
        case 2:  return qsTr("Authenticating the service session…")
        case 4:  return qsTr("Service connection interrupted; reconnecting…")
        case 5:  return root.serviceAuthFailureReason.length > 0
                    ? qsTr("Service authentication failed: %1").arg(root.serviceAuthFailureReason)
                    : qsTr("Service authentication failed.")
        default: return qsTr("ShadowStrike service is offline. Protection status may be stale.")
        }
    }

    function navigateToRoute(route) {
        d.navigateTo(route)
    }

    // ── Single-instance activation ─────────────────────────────────────────
    Connections {
        target: windowActivator
        function onActivate(commandLine) {
            root.show();
            root.raise();
            root.requestActivate();
        }
    }

    Connections {
        target: pipeClient
        function onAuthRejected(reason) {
            root.serviceAuthFailureReason = reason || qsTr("AUTH_REJECTED")
        }
        function onStateChanged() {
            if (pipeClient.connected) {
                root.serviceAuthFailureReason = ""
            }
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

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: root.serviceBannerVisible ? 42 : 0
                visible: root.serviceBannerVisible
                color: root.serviceState === 5
                       ? Qt.rgba(Theme.crit.r, Theme.crit.g, Theme.crit.b, 0.14)
                       : Qt.rgba(Theme.warn.r, Theme.warn.g, Theme.warn.b, 0.12)
                border.color: root.serviceState === 5 ? Theme.crit : Theme.warn
                border.width: 1

                Text {
                    anchors {
                        left: parent.left
                        leftMargin: Theme.spacingM
                        right: parent.right
                        rightMargin: Theme.spacingM
                        verticalCenter: parent.verticalCenter
                    }
                    text: root.serviceStateLabel(root.serviceState)
                    color: Theme.textPrimary
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeLabel
                    elide: Text.ElideRight
                }
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
                    onLoaded: {
                        if (item && "stack" in item) {
                            item.stack = stack
                        }
                    }
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

    // Compatibility navigation facade for pages that were originally authored
    // against StackView. It preserves push/pop semantics while keeping the
    // current lightweight Loader-based page host.
    QtObject {
        id: stack

        property var history: []

        function push(url) {
            d.navigateToUrl(url, true)
        }

        function replace(url) {
            d.navigateToUrl(url, false)
        }

        function pop() {
            if (history.length === 0) {
                d.navigateTo("security")
                return
            }

            var nextHistory = history.slice()
            var previousUrl = nextHistory.pop()
            history = nextHistory
            d.navigateToUrl(previousUrl, false)
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
            "reports":       "qrc:/qml/Pages/ReportsSubroute.qml",
            "settings":      "qrc:/qml/Pages/SettingsPage.qml"
        })

        function routeForUrl(url) {
            for (var key in routeMap) {
                if (routeMap[key] === url) {
                    return key
                }
            }
            return currentRoute
        }

        function navigateToUrl(url, pushHistory) {
            if (!url || url === "") {
                return
            }

            if (pushHistory && pageLoader.source !== "" && pageLoader.source !== url) {
                var nextHistory = stack.history.slice()
                nextHistory.push(pageLoader.source)
                stack.history = nextHistory
            }

            currentRoute = routeForUrl(url)
            pageHostContainer.navigateTo(url)
        }

        function navigateTo(route) {
            const url = routeMap[route];
            if (url !== undefined) {
                stack.history = []
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
