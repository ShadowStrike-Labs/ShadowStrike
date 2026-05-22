/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * QuarantineSubroute.qml — Quarantine vault management page.
 *
 * Features:
 *   - TopBar with back button and "Delete all" (confirmation modal)
 *   - ListView of quarantined items with Restore / Delete trailing actions
 *   - Multi-select mode: long-press or Ctrl+click; bulk action bar
 *   - EmptyState when vault is empty
 *
 * Surfaced via Security → "Quarantine" GhostButton.
 *
 * Context properties consumed (gated):
 *   quarantineModel — QuarantineModel*
 *     roles: itemId, name, path, threat, size, quarantinedAt, source
 *     Q_INVOKABLEs: refresh(), restore(id), deletePermanently(id), deleteAll()
 *     signals: actionCompleted(id, action), requestError(code, message)
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Multi-select state
    // -------------------------------------------------------------------------

    /// Set of selected item ids in multi-select mode.
    property var _selectedIds: ({})
    property int _selectedCount: 0

    function _isSelected(itemId) {
        return root._selectedIds[itemId] === true
    }

    function _toggleSelect(itemId) {
        var copy = Object.assign({}, root._selectedIds)
        if (copy[itemId]) {
            delete copy[itemId]
        } else {
            copy[itemId] = true
        }
        root._selectedIds = copy
        root._selectedCount = Object.keys(copy).length
    }

    function _clearSelection() {
        root._selectedIds = {}
        root._selectedCount = 0
    }

    // -------------------------------------------------------------------------
    // Confirmation modal state
    // -------------------------------------------------------------------------

    /// "none" | "deleteAll" | "bulkDelete"
    property string _confirmAction: "none"

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

    function formatSize(bytes) {
        if (!bytes || bytes <= 0) return "0 B"
        if (bytes < 1024)        return bytes + " B"
        if (bytes < 1048576)     return Math.round(bytes / 1024) + " KB"
        if (bytes < 1073741824)  return (bytes / 1048576).toFixed(1) + " MB"
        return (bytes / 1073741824).toFixed(2) + " GB"
    }

    // -------------------------------------------------------------------------
    // Initial load
    // -------------------------------------------------------------------------

    Component.onCompleted: {
        if (typeof quarantineModel !== "undefined")
            quarantineModel.refresh()
    }

    // -------------------------------------------------------------------------
    // Action feedback
    // -------------------------------------------------------------------------

    Connections {
        target: (typeof quarantineModel !== "undefined") ? quarantineModel : null
        ignoreUnknownSignals: true
        function onActionCompleted(itemId, action) {
            root._clearSelection()
        }
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
            pageTitle: qsTr("Quarantine")
            showBack:  true
            width:     parent.width
            onBackClicked: {
                if (typeof stack !== "undefined") stack.pop()
            }

            PrimaryButton {
                text:    qsTr("Delete all")
                enabled: (typeof quarantineModel !== "undefined") &&
                         quarantineModel.rowCount() > 0
                onClicked: root._confirmAction = "deleteAll"
            }
        }

        // Quarantine list
        Item {
            id:     listHost
            width:  parent.width
            height: parent.height - topBar.implicitHeight -
                    (root._selectedCount > 0 ? bulkBar.height : 0)

            // Empty state
            Loader {
                anchors.centerIn: parent
                sourceComponent: {
                    if (typeof quarantineModel === "undefined" || quarantineModel === null)
                        return qUnavailableComp
                    if (quarantineModel.rowCount() === 0)
                        return qEmptyComp
                    return null
                }
            }

            Component {
                id: qUnavailableComp
                EmptyState {
                    title:   qsTr("Quarantine unavailable")
                    message: qsTr("The quarantine service is not connected.")
                }
            }

            Component {
                id: qEmptyComp
                EmptyState {
                    title:   qsTr("Quarantine is empty")
                    message: qsTr("No items are quarantined. Your device is clean.")
                }
            }

            ListView {
                id:             quarantineList
                anchors.fill:   parent
                clip:           true
                spacing:        0
                boundsBehavior: Flickable.StopAtBounds
                model:          (typeof quarantineModel !== "undefined") ? quarantineModel : null

                delegate: Item {
                    id:     qRow
                    width:  quarantineList.width
                    height: rowContent.implicitHeight + 1   // +1 for divider

                    required property string itemId
                    required property string name
                    required property string path
                    required property string threat
                    required property var    size
                    required property var    quarantinedAt
                    required property int    index

                    readonly property bool _selected: root._isSelected(qRow.itemId)

                    // Row background — highlights on hover or selection
                    Rectangle {
                        anchors.fill: parent
                        color: qRow._selected
                               ? Qt.rgba(Theme.accentCyan.r, Theme.accentCyan.g, Theme.accentCyan.b, 0.12)
                               : (rowHover.containsMouse
                                  ? Theme.bgSurfaceAlt
                                  : (qRow.index % 2 === 1
                                     ? Qt.rgba(Theme.bgSurfaceAlt.r, Theme.bgSurfaceAlt.g, Theme.bgSurfaceAlt.b, 0.40)
                                     : "transparent"))
                        Behavior on color { ColorAnimation { duration: Theme.motionFast; easing.type: Theme.easingType } }
                    }

                    // Left selection indicator bar
                    Rectangle {
                        width:   3
                        height:  rowContent.implicitHeight
                        radius:  1
                        color:   Theme.accentCyan
                        opacity: qRow._selected ? 1 : 0
                        Behavior on opacity { NumberAnimation { duration: Theme.motionFast } }
                    }

                    Column {
                        id:      rowContent
                        anchors {
                            left:       parent.left
                            leftMargin: Theme.spacingL
                            right:      trailingActions.left
                            rightMargin: Theme.spacingS
                        }
                        spacing: 2
                        topPadding:    Theme.spacingM
                        bottomPadding: Theme.spacingM

                        // Name + threat label row
                        Row {
                            width:   parent.width
                            spacing: Theme.spacingS

                            Text {
                                id:    nameText
                                text:  qRow.name.length > 0 ? qRow.name : qsTr("(unknown)")
                                color: Theme.textPrimary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                                elide: Text.ElideRight
                                width: parent.width - threatChip.implicitWidth - parent.spacing
                            }

                            StatusChip {
                                id:    threatChip
                                state: "critical"
                                label: qRow.threat.length > 0 ? qRow.threat : qsTr("Threat")
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }

                        // Path
                        Text {
                            text:  qRow.path.length > 0 ? qRow.path : qsTr("(path unavailable)")
                            color: Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeMicro
                            elide: Text.ElideMiddle
                            width: parent.width
                        }

                        // Size + quarantined time
                        Row {
                            spacing: Theme.spacingM

                            Text {
                                text:  root.formatSize(qRow.size)
                                color: Theme.textMuted
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeMicro
                            }

                            Text {
                                text:  qsTr("Quarantined %1").arg(root.relativeTime(qRow.quarantinedAt))
                                color: Theme.textMuted
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeMicro
                            }
                        }
                    }

                    // Trailing action buttons
                    Row {
                        id:    trailingActions
                        anchors {
                            right:          parent.right
                            rightMargin:    Theme.spacingM
                            verticalCenter: parent.verticalCenter
                        }
                        spacing: Theme.spacingXS

                        GhostButton {
                            text:   qsTr("Restore")
                            height: 30
                            onClicked: {
                                if (typeof quarantineModel !== "undefined")
                                    quarantineModel.restore(qRow.itemId)
                            }
                        }

                        IconButton {
                            iconSource: "qrc:/icons/close.svg"
                            tooltip:    qsTr("Delete permanently")
                            onClicked:  {
                                // Use confirmation modal for single item deletion
                                root._confirmAction = "deleteSingle"
                                root._pendingDeleteId = qRow.itemId
                            }
                        }
                    }

                    // Divider
                    Rectangle {
                        anchors.left:   parent.left
                        anchors.right:  parent.right
                        anchors.bottom: parent.bottom
                        height:         1
                        color:          Theme.strokeSubtle
                    }

                    // Hover detection + click handling (select / Ctrl+click)
                    MouseArea {
                        id:           rowHover
                        anchors.fill: parent
                        hoverEnabled: true
                        propagateComposedEvents: true
                        acceptedButtons: Qt.LeftButton | Qt.RightButton

                        onClicked: (mouse) => {
                            if (mouse.modifiers & Qt.ControlModifier || root._selectedCount > 0) {
                                root._toggleSelect(qRow.itemId)
                                mouse.accepted = true
                            } else {
                                mouse.accepted = false
                            }
                        }
                        onPressAndHold: {
                            root._toggleSelect(qRow.itemId)
                        }
                    }

                    activeFocusOnTab: true
                    Keys.onSpacePressed: root._toggleSelect(qRow.itemId)

                    FocusRing { target: qRow }

                    Accessible.role:        Accessible.ListItem
                    Accessible.name:        qRow.name
                    Accessible.description: qsTr("%1 — %2 — quarantined %3").arg(qRow.threat).arg(qRow.path).arg(root.relativeTime(qRow.quarantinedAt))
                    Accessible.checkable:   true
                    Accessible.checked:     qRow._selected
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

        // Bulk action bar — slides in when items are selected
        Rectangle {
            id:      bulkBar
            width:   parent.width
            height:  root._selectedCount > 0 ? 52 : 0
            color:   Theme.bgSurfaceAlt
            clip:    true
            visible: root._selectedCount > 0

            Behavior on height {
                enabled: !(typeof perfBudget !== "undefined" &&
                           perfBudget !== null && perfBudget.animationsPaused)
                NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType }
            }

            // Top border
            Rectangle {
                anchors.top:   parent.top
                anchors.left:  parent.left
                anchors.right: parent.right
                height: 1
                color:  Theme.accentCyan
                opacity: 0.5
            }

            Row {
                anchors {
                    left:           parent.left
                    leftMargin:     Theme.spacingM
                    right:          parent.right
                    rightMargin:    Theme.spacingM
                    verticalCenter: parent.verticalCenter
                }
                spacing: Theme.spacingM

                Text {
                    text:           qsTr("%1 item(s) selected").arg(root._selectedCount)
                    color:          Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    anchors.verticalCenter: parent.verticalCenter
                }

                GhostButton {
                    text: qsTr("Restore selected")
                    onClicked: {
                        if (typeof quarantineModel === "undefined") return
                        var ids = Object.keys(root._selectedIds)
                        for (var i = 0; i < ids.length; i++)
                            quarantineModel.restore(ids[i])
                        root._clearSelection()
                    }
                }

                PrimaryButton {
                    text: qsTr("Delete selected")
                    onClicked: root._confirmAction = "bulkDelete"
                }

                GhostButton {
                    text: qsTr("Cancel")
                    onClicked: root._clearSelection()
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Pending single-item delete id (used by confirmation modal)
    // -------------------------------------------------------------------------

    property string _pendingDeleteId: ""

    // -------------------------------------------------------------------------
    // Confirmation modal overlay
    // -------------------------------------------------------------------------

    Rectangle {
        id:      modalOverlay
        anchors.fill: parent
        color:   Qt.rgba(0, 0, 0, 0.55)
        visible: root._confirmAction !== "none"
        z:       100

        Behavior on opacity {
            enabled: !(typeof perfBudget !== "undefined" &&
                       perfBudget !== null && perfBudget.animationsPaused)
            NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType }
        }

        // Dismiss on backdrop click
        MouseArea {
            anchors.fill: parent
            onClicked:    root._confirmAction = "none"
        }

        Card {
            id:                    modalCard
            anchors.centerIn:      parent
            width:                 Math.min(360, parent.width - Theme.spacingXL * 2)
            accent:                Theme.crit
            glow:                  true

            MouseArea {
                anchors.fill:            parent
                propagateComposedEvents: true
                onClicked: (mouse) => { mouse.accepted = true }   // block backdrop dismiss
            }

            Column {
                width:   parent.width
                spacing: Theme.spacingM

                Text {
                    text:           {
                        switch (root._confirmAction) {
                        case "deleteAll":   return qsTr("Delete all quarantined items?")
                        case "bulkDelete":  return qsTr("Delete %1 selected item(s)?").arg(root._selectedCount)
                        case "deleteSingle": return qsTr("Permanently delete this item?")
                        default:            return ""
                        }
                    }
                    color:          Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeTitle
                    font.weight:    Theme.fontWeightBold
                    wrapMode:       Text.WordWrap
                    width:          parent.width
                }

                Text {
                    text:           qsTr("This action cannot be undone. Deleted files are permanently removed from the vault.")
                    color:          Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    wrapMode:       Text.WordWrap
                    width:          parent.width
                }

                Row {
                    width:           parent.width
                    spacing:         Theme.spacingM
                    layoutDirection: Qt.RightToLeft

                    PrimaryButton {
                        text: qsTr("Delete")
                        onClicked: {
                            if (typeof quarantineModel === "undefined") {
                                root._confirmAction = "none"
                                return
                            }
                            switch (root._confirmAction) {
                            case "deleteAll":
                                quarantineModel.deleteAll()
                                break
                            case "bulkDelete": {
                                var ids = Object.keys(root._selectedIds)
                                for (var i = 0; i < ids.length; i++)
                                    quarantineModel.deletePermanently(ids[i])
                                root._clearSelection()
                                break
                            }
                            case "deleteSingle":
                                if (root._pendingDeleteId.length > 0)
                                    quarantineModel.deletePermanently(root._pendingDeleteId)
                                root._pendingDeleteId = ""
                                break
                            }
                            root._confirmAction = "none"
                        }
                    }

                    GhostButton {
                        text:      qsTr("Cancel")
                        onClicked: {
                            root._confirmAction = "none"
                            root._pendingDeleteId = ""
                        }
                    }
                }
            }
        }
    }
}
