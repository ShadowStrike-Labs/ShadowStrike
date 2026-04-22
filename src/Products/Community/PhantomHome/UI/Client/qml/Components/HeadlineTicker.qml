import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming

Item {
    id: root

    required property string state  // "healthy"|"atRisk"|"critical"

    implicitWidth:  320
    implicitHeight: Theme.fontSizeDisplay + Theme.spacingM

    readonly property color _stateColor: {
        switch (root.state) {
        case "healthy":  return Theme.ok
        case "atRisk":   return Theme.warn
        case "critical": return Theme.crit
        default:         return Theme.textMuted
        }
    }

    property int  _stringIndex: 0
    property bool _showA:       true

    readonly property var _strings: {
        var list = Theme.headlineStrings[root.state]
        return list ? list : [qsTr("Monitoring your device.")]
    }

    function _nextString() {
        _stringIndex = (_stringIndex + 1) % _strings.length
        _showA = !_showA
        if (_showA) {
            textA.text      = _strings[_stringIndex]
            textA.opacity   = 1; textA.y = 0
            textB.opacity   = 0; textB.y = 8
        } else {
            textB.text      = _strings[_stringIndex]
            textB.opacity   = 1; textB.y = 0
            textA.opacity   = 0; textA.y = 8
        }
    }

    // When state changes: reset to first string immediately
    onStateChanged: {
        _stringIndex = 0
        var s = _strings[0]
        if (_showA) {
            textA.text = s; textA.opacity = 1; textA.y = 0
            textB.opacity = 0
        } else {
            textB.text = s; textB.opacity = 1; textB.y = 0
            textA.opacity = 0
        }
        rotationTimer.restart()
    }

    Text {
        id: textA
        anchors.left:  parent.left
        anchors.right: parent.right
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
        anchors.left:  parent.left
        anchors.right: parent.right
        text:  ""
        color: root._stateColor
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

    Timer {
        id: rotationTimer
        interval: 4000
        repeat:   true
        running: {
            if (typeof perfBudget !== "undefined" && perfBudget !== null && perfBudget.animationsPaused)
                return false
            return root._strings.length > 1
        }
        onTriggered: root._nextString()
    }

    Accessible.role: Accessible.StaticText
    Accessible.name: _showA ? textA.text : textB.text
    // liveRegion polite so screen readers announce new headlines
    Accessible.description: qsTr("Status headline")
}
