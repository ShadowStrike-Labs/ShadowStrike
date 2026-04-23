/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ReportsSubroute.qml — Full paginated threat/detection report viewer.
 *
 * Features:
 *   - TopBar with back button and "Export CSV" action
 *   - SearchBar (client-side text filter) + category ComboBox
 *   - reportsModel.setFilter() on category/date change
 *   - Paginated ThreatRow ListView; next page loaded on atYEnd
 *   - EmptyState when no results
 *
 * Surfaced via Main → "View all" GhostButton.
 *
 * Context properties consumed (gated):
 *   reportsModel — ReportsModel* (loading, hasMore, loadMore(), setFilter(), exportCsv())
 *
 * ReportsModel role names (for required property binding):
 *   id, type, severity, title, summary, timestamp, actor, detailsJson
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Filter state
    // -------------------------------------------------------------------------

    property string _searchText:    ""
    property int    _categoryIndex: 0
    property bool   _exportBusy:    false

    readonly property var _categories: [
        qsTr("All"),
        qsTr("Detection"),
        qsTr("Block"),
        qsTr("Quarantine"),
        qsTr("Scan"),
        qsTr("PGTI"),
    ]
    readonly property var _categoryKeys: ["", "Detection", "Block", "Quarantine", "Scan", "PGTI"]

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function relativeTime(ts) {
        if (!ts || ts <= 0) return qsTr("unknown")
        var diff = (Date.now() / 1000) - ts
        if (diff < 60)    return qsTr("just now")
        if (diff < 3600)  return qsTr("%1m ago").arg(Math.floor(diff / 60))
        if (diff < 86400) return qsTr("%1h ago").arg(Math.floor(diff / 3600))
        return qsTr("%1d ago").arg(Math.floor(diff / 86400))
    }

    function _applyFilter() {
        if (typeof reportsModel !== "undefined")
            reportsModel.setFilter(_categoryKeys[_categoryIndex], null, null)
    }

    function _buildExportPath() {
        // Attempt a platform-appropriate path.  The C++ side validates the URL
        // and falls back to a safe location if this path is not writable.
        var base = "shadowstrike-reports-" +
                   Qt.formatDateTime(new Date(), "yyyyMMdd-HHmmss") + ".csv"
        // Use a relative path; C++ resolves this against the application writable dir.
        return Qt.resolvedUrl(base)
    }

    // -------------------------------------------------------------------------
    // Initial load & feedback connections
    // -------------------------------------------------------------------------

    Component.onCompleted: {
        if (typeof reportsModel !== "undefined")
            reportsModel.setFilter("", null, null)
    }

    Connections {
        target: (typeof reportsModel !== "undefined") ? reportsModel : null
        ignoreUnknownSignals: true
        function onExportCompleted() { root._exportBusy = false }
        function onExportFailed()    { root._exportBusy = false }
        function onRequestError()    { root._exportBusy = false }
    }

    // -------------------------------------------------------------------------
    // Layout
    // -------------------------------------------------------------------------

    Column {
        id:      pageColumn
        anchors.fill: parent
        spacing: 0

        // TopBar
        TopBar {
            id:        topBar
            pageTitle: qsTr("Reports")
            showBack:  true
            width:     parent.width
            onBackClicked: {
                if (typeof stack !== "undefined") stack.pop()
            }

            GhostButton {
                text:    qsTr("Export CSV")
                busy:    root._exportBusy
                enabled: (typeof reportsModel !== "undefined") &&
                         reportsModel.rowCount() > 0 &&
                         !root._exportBusy
                onClicked: {
                    if (typeof reportsModel === "undefined") return
                    root._exportBusy = true
                    reportsModel.exportCsv(root._buildExportPath())
                }
            }
        }

        // Filter bar
        Rectangle {
            id:     filterBar
            width:  parent.width
            height: filterRow.implicitHeight + Theme.spacingM * 2
            color:  Theme.bgSurface

            Rectangle {
                anchors.left:   parent.left
                anchors.right:  parent.right
                anchors.bottom: parent.bottom
                height: 1
                color:  Theme.strokeSubtle
            }

            Row {
                id:              filterRow
                anchors.margins: Theme.spacingM
                anchors.left:    parent.left
                anchors.right:   parent.right
                anchors.verticalCenter: parent.verticalCenter
                spacing:         Theme.spacingM

                SearchBar {
                    id:              filterSearch
                    width:           parent.width - categoryBox.width - parent.spacing
                    placeholderText: qsTr("Search threats…")
                    onSearchChanged: (q) => { root._searchText = q }
                }

                ComboBox {
                    id:     categoryBox
                    width:  160
                    height: 36
                    model:  root._categories

                    background: Rectangle {
                        radius:       Theme.radiusMedium
                        color:        Theme.bgSurface
                        border.color: categoryBox.activeFocus ? Theme.accentCyan : Theme.strokeSubtle
                        border.width: categoryBox.activeFocus ? 2 : 1
                        Behavior on border.color {
                            ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType }
                        }
                    }
                    contentItem: Text {
                        leftPadding: Theme.spacingM
                        text:        categoryBox.displayText
                        color:       Theme.textPrimary
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        verticalAlignment: Text.AlignVCenter
                    }

                    onCurrentIndexChanged: {
                        root._categoryIndex = currentIndex
                        root._applyFilter()
                    }

                    Accessible.role:        Accessible.ComboBox
                    Accessible.name:        qsTr("Report category filter")
                    Accessible.description: displayText
                }
            }
        }

        // Reports list area
        Item {
            id:     listHost
            width:  parent.width
            height: parent.height - topBar.implicitHeight - filterBar.height

            ListView {
                id:             reportsList
                anchors.fill:   parent
                clip:           true
                spacing:        0
                boundsBehavior: Flickable.StopAtBounds
                model:          (typeof reportsModel !== "undefined") ? reportsModel : null

                // Load next page when scrolled to the bottom
                onAtYEndChanged: {
                    if (atYEnd &&
                        typeof reportsModel !== "undefined" &&
                        reportsModel.hasMore &&
                        !reportsModel.loading) {
                        reportsModel.loadMore()
                    }
                }

                // Empty / unavailable state in the list header
                header: Loader {
                    width: reportsList.width
                    sourceComponent: {
                        if (typeof reportsModel === "undefined" || reportsModel === null)
                            return rptUnavailableComp
                        if (reportsList.count === 0 && !reportsModel.loading)
                            return rptEmptyComp
                        return null
                    }

                    Component {
                        id: rptUnavailableComp
                        EmptyState {
                            width:   parent ? parent.width : 400
                            height:  120
                            title:   qsTr("Reports unavailable")
                            message: qsTr("The reporting service is not connected.")
                        }
                    }

                    Component {
                        id: rptEmptyComp
                        EmptyState {
                            width:   parent ? parent.width : 400
                            height:  120
                            title:   qsTr("No results")
                            message: qsTr("No reports match the current filter.")
                        }
                    }
                }

                delegate: Item {
                    id:    rptRow
                    width: reportsList.width

                    required property int    index
                    required property string title
                    required property string summary
                    required property var    timestamp
                    required property string type

                    // Client-side text filter
                    readonly property bool _matches: {
                        var q = root._searchText.trim().toLowerCase()
                        if (q.length === 0) return true
                        return (rptRow.title   || "").toLowerCase().indexOf(q) >= 0 ||
                               (rptRow.summary || "").toLowerCase().indexOf(q) >= 0
                    }

                    visible: _matches
                    height:  _matches ? (rptRowContent.implicitHeight) : 0

                    ThreatRow {
                        id:               rptRowContent
                        width:            rptRow.width
                        alternate:        rptRow.index % 2 === 1
                        threatName:       rptRow.title   ?? qsTr("Unknown threat")
                        filePath:         rptRow.summary ?? ""
                        action:           {
                            var t = (rptRow.type || "").toLowerCase()
                            if (t === "block")      return "blocked"
                            if (t === "quarantine") return "quarantined"
                            return "deleted"
                        }
                        timestampDisplay: root.relativeTime(rptRow.timestamp)
                        onRowClicked: {}
                    }
                }

                // Loading spinner footer
                footer: Item {
                    width:   reportsList.width
                    height:  (typeof reportsModel !== "undefined" && reportsModel.loading)
                             ? 52 : 0
                    visible: typeof reportsModel !== "undefined" && reportsModel.loading

                    Row {
                        anchors.centerIn: parent
                        spacing:          Theme.spacingS

                        BusyIndicator {
                            width:   24; height: 24
                            running: typeof reportsModel !== "undefined" && reportsModel.loading
                            palette.dark: Theme.accentCyan
                        }

                        Text {
                            text:           qsTr("Loading…")
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeBody
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }
                }

                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AsNeeded
                    contentItem: Rectangle {
                        implicitWidth: 6
                        radius:        3
                        color:         Theme.strokeSubtle
                    }
                }
            }
        }
    }
}
