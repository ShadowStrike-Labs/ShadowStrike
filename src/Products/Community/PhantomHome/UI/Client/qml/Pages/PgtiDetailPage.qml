/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PgtiDetailPage.qml — PGTI (PhantomGuard Threat Intelligence) feed management.
 *
 * Displays all PGTI feeds with health status, IOC counts, last-sync time,
 * latency, and individual enable/refresh controls.  A manual single-feed
 * refresh section sits at the bottom.
 *
 * Bound to pgtiViewModel (context property) — page renders safely when absent.
 *
 * Context properties consumed (gated):
 *   pgtiViewModel — exposes:
 *     feeds      — model with roles: feedId, displayName, health, lastSuccessTs,
 *                  latencyMs, entryCount, enabled
 *     refreshAll()      Q_INVOKABLE
 *     refreshFeed(id)   Q_INVOKABLE
 *     loading           bool property
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function relativeTime(ts) {
        if (!ts || ts <= 0) return qsTr("never")
        var diff = (Date.now() / 1000) - ts
        if (diff < 60)    return qsTr("just now")
        if (diff < 3600)  return qsTr("%1m ago").arg(Math.floor(diff / 60))
        if (diff < 86400) return qsTr("%1h ago").arg(Math.floor(diff / 3600))
        return qsTr("%1d ago").arg(Math.floor(diff / 86400))
    }

    /// Map health string to StatusChip state.
    function healthChipState(health) {
        switch ((health || "").toLowerCase()) {
        case "healthy":  return "on"
        case "degraded": return "warning"
        case "failed":   return "critical"
        default:         return "off"        // "disabled" or unknown
        }
    }

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /// Currently selected feed id for single-feed refresh.
    property string _selectedFeedId: ""
    property bool   _refreshAllBusy: false

    // -------------------------------------------------------------------------
    // Layout
    // -------------------------------------------------------------------------

    Column {
        id:      pageColumn
        anchors.fill: parent
        spacing: 0

        TopBar {
            id:        topBar
            pageTitle: qsTr("PGTI")
            showBack:  true
            width:     parent.width
            onBackClicked: {
                if (typeof stack !== "undefined") stack.pop()
            }

            PrimaryButton {
                text:      qsTr("Refresh all")
                busy:      root._refreshAllBusy
                onClicked: {
                    if (typeof pgtiViewModel !== "undefined") {
                        root._refreshAllBusy = true
                        pgtiViewModel.refreshAll()
                    }
                }
            }
        }

        ScrollView {
            id:          scroll
            width:       parent.width
            height:      parent.height - topBar.implicitHeight
            contentWidth: parent.width
            clip:        true

            Column {
                id:      bodyColumn
                width:   scroll.width
                spacing: Theme.spacingL
                padding: Theme.spacingL

                SectionTitle {
                    text:  qsTr("PGTI Feeds")
                    width: parent.width - Theme.spacingL * 2
                    subtitle: {
                        if (typeof pgtiViewModel === "undefined") return qsTr("Intelligence service unavailable")
                        var cnt = (pgtiViewModel.feeds !== null) ? pgtiViewModel.feeds.rowCount() : 0
                        return qsTr("%1 feed(s) configured").arg(cnt)
                    }
                }

                // Feed list — or empty state
                Loader {
                    id:    feedLoader
                    width: parent.width - Theme.spacingL * 2
                    sourceComponent: {
                        if (typeof pgtiViewModel === "undefined" || pgtiViewModel === null)
                            return pgtiUnavailableComp
                        if (pgtiViewModel.feeds === null || pgtiViewModel.feeds.rowCount() === 0)
                            return pgtiEmptyComp
                        return pgtiListComp
                    }
                }

                Component {
                    id: pgtiUnavailableComp
                    EmptyState {
                        width:   parent ? parent.width : 400
                        height:  80
                        title:   qsTr("PGTI service unavailable")
                        message: qsTr("The threat intelligence service is not connected.")
                    }
                }

                Component {
                    id: pgtiEmptyComp
                    EmptyState {
                        width:   parent ? parent.width : 400
                        height:  80
                        title:   qsTr("No feeds configured")
                        message: qsTr("No PGTI feeds are currently active.")
                    }
                }

                Component {
                    id: pgtiListComp
                    Card {
                        width: parent ? parent.width : 400

                        ListView {
                            id:             feedList
                            width:          parent.width
                            height:         contentHeight
                            spacing:        0
                            clip:           true
                            model:          (typeof pgtiViewModel !== "undefined") ? pgtiViewModel.feeds : null
                            boundsBehavior: Flickable.StopAtBounds
                            interactive:    false

                            delegate: Column {
                                id:    feedDelegate
                                width: feedList.width
                                spacing: 0
                                required property string feedId
                                required property string displayName
                                required property string health
                                required property var    lastSuccessTs
                                required property int    latencyMs
                                required property int    entryCount
                                required property bool   enabled
                                required property int    index

                                PGTIFeedRow {
                                    id:              feedRow
                                    width:           parent.width
                                    feedName:        feedDelegate.displayName.length > 0
                                                     ? feedDelegate.displayName : feedDelegate.feedId
                                    enabled:         feedDelegate.enabled
                                    lastSyncDisplay: root.relativeTime(feedDelegate.lastSuccessTs)
                                    iocCount:        feedDelegate.entryCount

                                    onToggled: (v) => {
                                        if (typeof pgtiViewModel !== "undefined")
                                            pgtiViewModel.setFeedEnabled(feedDelegate.feedId, v)
                                    }
                                    onRefreshClicked: {
                                        if (typeof pgtiViewModel !== "undefined")
                                            pgtiViewModel.refreshFeed(feedDelegate.feedId)
                                    }
                                }

                                // Extra detail row (health chip + latency)
                                Row {
                                    leftPadding:  Theme.spacingL
                                    bottomPadding: Theme.spacingS
                                    spacing:      Theme.spacingM

                                    StatusChip {
                                        state: root.healthChipState(feedDelegate.health)
                                        label: {
                                            var h = (feedDelegate.health || "").toLowerCase()
                                            if (h === "healthy")  return qsTr("Healthy")
                                            if (h === "degraded") return qsTr("Degraded")
                                            if (h === "failed")   return qsTr("Failed")
                                            return qsTr("Disabled")
                                        }
                                    }

                                    Text {
                                        visible: feedDelegate.latencyMs > 0
                                        text:    qsTr("%1 ms").arg(feedDelegate.latencyMs)
                                        color:   feedDelegate.latencyMs > 2000 ? Theme.warn : Theme.textMuted
                                        font.family:    Theme.fontFamily
                                        font.pixelSize: Theme.fontSizeLabel
                                        anchors.verticalCenter: parent.verticalCenter
                                    }

                                    Text {
                                        text:    qsTr("%1 entries").arg(feedDelegate.entryCount.toLocaleString())
                                        color:   Theme.textMuted
                                        font.family:    Theme.fontFamily
                                        font.pixelSize: Theme.fontSizeLabel
                                        anchors.verticalCenter: parent.verticalCenter
                                    }
                                }

                                // Divider
                                Rectangle {
                                    width:  feedList.width
                                    height: 1
                                    color:  Theme.strokeSubtle
                                    visible: feedDelegate.index < feedList.count - 1
                                }
                            }
                        }
                    }
                }

                // -------------------------------------------------------------
                // Manual single-feed refresh
                // -------------------------------------------------------------
                SectionTitle {
                    text:  qsTr("Manual refresh")
                    width: parent.width - Theme.spacingL * 2
                    visible: typeof pgtiViewModel !== "undefined" &&
                             pgtiViewModel !== null &&
                             pgtiViewModel.feeds !== null &&
                             pgtiViewModel.feeds.rowCount() > 0
                }

                Card {
                    width:   parent.width - Theme.spacingL * 2
                    visible: typeof pgtiViewModel !== "undefined" &&
                             pgtiViewModel !== null &&
                             pgtiViewModel.feeds !== null &&
                             pgtiViewModel.feeds.rowCount() > 0

                    Row {
                        width:   parent.width
                        spacing: Theme.spacingM

                        ComboBox {
                            id:      feedSelector
                            width:   parent.width - refreshSingleBtn.implicitWidth - parent.spacing
                            height:  36
                            model:   {
                                if (typeof pgtiViewModel === "undefined" || pgtiViewModel.feeds === null)
                                    return []
                                var ids = []
                                var feeds = pgtiViewModel.feeds
                                for (var i = 0; i < feeds.rowCount(); i++) {
                                    var dn = feeds.data(feeds.index(i, 0), Qt.UserRole + 2) ?? ""
                                    var fi = feeds.data(feeds.index(i, 0), Qt.UserRole + 1) ?? ""
                                    ids.push(dn.length > 0 ? dn : fi)
                                }
                                return ids
                            }

                            background: Rectangle {
                                radius:       Theme.radiusMedium
                                color:        Theme.bgSurface
                                border.color: feedSelector.activeFocus ? Theme.accentCyan : Theme.strokeSubtle
                                border.width: feedSelector.activeFocus ? 2 : 1
                            }
                            contentItem: Text {
                                leftPadding: Theme.spacingM
                                text:        feedSelector.displayText
                                color:       Theme.textPrimary
                                font.family: Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                verticalAlignment: Text.AlignVCenter
                            }

                            onCurrentIndexChanged: {
                                if (typeof pgtiViewModel === "undefined" || pgtiViewModel.feeds === null) return
                                var feeds = pgtiViewModel.feeds
                                if (currentIndex >= 0 && currentIndex < feeds.rowCount()) {
                                    root._selectedFeedId = feeds.data(feeds.index(currentIndex, 0), Qt.UserRole + 1) ?? ""
                                }
                            }
                        }

                        PrimaryButton {
                            id:        refreshSingleBtn
                            text:      qsTr("Refresh")
                            enabled:   root._selectedFeedId.length > 0
                            onClicked: {
                                if (typeof pgtiViewModel !== "undefined" &&
                                    root._selectedFeedId.length > 0) {
                                    pgtiViewModel.refreshFeed(root._selectedFeedId)
                                }
                            }
                        }
                    }
                }

                // Bottom spacing
                Item { width: 1; height: Theme.spacingL }
            }
        }
    }

    // Reset busy flag when pgtiViewModel notifies completion (if signal exists)
    Connections {
        target:  (typeof pgtiViewModel !== "undefined") ? pgtiViewModel : null
        ignoreUnknownSignals: true
        function onRefreshAllCompleted() { root._refreshAllBusy = false }
        function onRequestError()        { root._refreshAllBusy = false }
    }
}
