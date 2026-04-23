/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * HeadlineTicker.qml — Animated headline status display for the hero card.
 * Displays a leading state dot and cross-fades between a list of status
 * strings every 6 seconds.  State → colour mapping drives both the dot and
 * the text.  Respects perfBudget.animationsPaused.
 *
 * Enriched: primaryText / secondaryText override; "unknown" state; 6s cadence;
 * accessible state-change announcement via Accessible.description.
 */

import QtQuick
import ShadowStrike.Theming

Item {
    id: root

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// "healthy" | "atRisk" | "critical" | "unknown"
    required property string state

    /// When non-empty, overrides the Theme-driven rotating strings.
    /// primaryText is always shown first; secondaryText (if non-empty) rotates
    /// second at the 6-second cadence.
    property string primaryText:   ""
    property string secondaryText: ""

    // -------------------------------------------------------------------------
    // Geometry
    // -------------------------------------------------------------------------

    implicitWidth:  320
    implicitHeight: Theme.fontSizeDisplay + Theme.spacingM

    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    readonly property color _stateColor: {
        switch (root.state) {
        case "healthy":  return Theme.ok
        case "atRisk":   return Theme.warn
        case "critical": return Theme.crit
        default:         return Theme.textMuted   // "unknown" and any unrecognised state
        }
    }

    property int  _stringIndex: 0
    property bool _showA:       true

    /// Effective rotation list.  primaryText / secondaryText take priority; if
    /// absent, the per-state Theme strings are used.  Guarantees at least one
    /// non-empty entry so the timer guard logic is always safe.
    readonly property var _strings: {
        if (root.primaryText.length > 0) {
            var arr = [root.primaryText]
            if (root.secondaryText.length > 0) arr.push(root.secondaryText)
            return arr
        }
        var list = Theme.headlineStrings[root.state]
        return (list && list.length > 0) ? list : [qsTr("Monitoring your device.")]
    }

    // -------------------------------------------------------------------------
    // String rotation
    // -------------------------------------------------------------------------

    function _nextString() {
        _stringIndex = (_stringIndex + 1) % _strings.length
        _showA = !_showA
        if (_showA) {
            textA.text    = _strings[_stringIndex]
            textA.opacity = 1; textA.y = 0
            textB.opacity = 0; textB.y = 8
        } else {
            textB.text    = _strings[_stringIndex]
            textB.opacity = 1; textB.y = 0
            textA.opacity = 0; textA.y = 8
        }
    }

    // On state change: snap to first string immediately and restart cadence.
    onStateChanged: {
        _stringIndex = 0
        var s = _strings.length > 0 ? _strings[0] : ""
        if (_showA) {
            textA.text = s; textA.opacity = 1; textA.y = 0
            textB.opacity = 0
        } else {
            textB.text = s; textB.opacity = 1; textB.y = 0
            textA.opacity = 0
        }
        rotationTimer.restart()
    }

    // -------------------------------------------------------------------------
    // Leading state dot
    // -------------------------------------------------------------------------

    Rectangle {
        id: stateDot
        width:  10; height: 10
        radius: 5
        anchors.left: parent.left
        y: (root.implicitHeight - height) / 2
        color: root._stateColor
        Behavior on color { ColorAnimation { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
    }

    // -------------------------------------------------------------------------
    // Cross-fading texts (overlap, anchored beside dot)
    // -------------------------------------------------------------------------

    Text {
        id: textA
        anchors.left:       stateDot.right
        anchors.leftMargin: Theme.spacingS
        anchors.right:      parent.right
        text:  root._strings.length > 0 ? root._strings[0] : ""
        color: root._stateColor
        font.family:    Theme.fontFamily
        font.pixelSize: Theme.fontSizeDisplay
        font.weight:    Theme.fontWeightBold
        wrapMode: Text.WordWrap

        Behavior on opacity { NumberAnimation { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
        Behavior on y       { NumberAnimation { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
        Behavior on color   { ColorAnimation  { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
    }

    Text {
        id: textB
        anchors.left:       stateDot.right
        anchors.leftMargin: Theme.spacingS
        anchors.right:      parent.right
        text:   ""
        color:  root._stateColor
        font.family:    Theme.fontFamily
        font.pixelSize: Theme.fontSizeDisplay
        font.weight:    Theme.fontWeightBold
        wrapMode: Text.WordWrap
        opacity: 0
        y: 8

        Behavior on opacity { NumberAnimation { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
        Behavior on y       { NumberAnimation { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
        Behavior on color   { ColorAnimation  { duration: Theme.motionHeadline; easing.type: Theme.easingType } }
    }

    // -------------------------------------------------------------------------
    // Rotation timer — 6 s cadence; suspended when animationsPaused or only
    // one string is available.
    // -------------------------------------------------------------------------

    Timer {
        id: rotationTimer
        interval: 6000
        repeat:   true
        running: {
            if (typeof perfBudget !== "undefined" && perfBudget !== null && perfBudget.animationsPaused)
                return false
            return root._strings.length > 1
        }
        onTriggered: root._nextString()
    }

    // -------------------------------------------------------------------------
    // Accessibility — live region: screen readers announce state changes.
    // -------------------------------------------------------------------------

    Accessible.role: Accessible.StaticText
    Accessible.name: _showA ? textA.text : textB.text
    // Announces both the current headline string and device state so assistive
    // technologies report state transitions (e.g. "Device status: critical").
    Accessible.description: qsTr("Device status: %1").arg(root.state)
}
