import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming

Item {
    id: root

    required property string title
    required property string message
    property url iconSource
    property string variant: "empty"   // "empty"|"loading"|"error"|"offline"|"success"
    property bool busy: variant === "loading"
    property bool framed: false
    property string primaryActionText: ""
    property string secondaryActionText: ""
    signal primaryActionTriggered()
    signal secondaryActionTriggered()

    readonly property bool compact: height > 0 && height <= 96
    readonly property color _tone: {
        switch (root.variant) {
        case "loading": return Theme.stateColor("loading")
        case "error":   return Theme.stateColor("critical")
        case "offline": return Theme.stateColor("offline")
        case "success": return Theme.stateColor("healthy")
        default:        return Theme.stateColor("info")
        }
    }

    implicitWidth:  Theme.statePanelMaxWidth
    implicitHeight: col.implicitHeight + (root.framed ? Theme.spacingL * 2 : 0)

    Rectangle {
        visible: root.framed
        anchors.fill: parent
        radius: Theme.radiusLarge
        color: Theme.surfaceColor(false, false)
        border.color: Theme.interactiveBorder(false, false, root.variant)
        border.width: Theme.highContrast ? 2 : 1
    }

    Column {
        id: col
        anchors.centerIn: parent
        spacing:          root.compact ? Theme.spacingXS : Theme.spacingM
        width:            Math.min(Math.max(220, parent.width - (root.framed ? Theme.spacingL * 2 : 0)),
                                   Theme.statePanelMaxWidth)

        BusyIndicator {
            visible: root.busy
            running: root.busy
            width: root.compact ? 22 : 32
            height: width
            anchors.horizontalCenter: parent.horizontalCenter
            palette.dark: root._tone
        }

        Image {
            visible:  !root.busy && !root.compact && root.iconSource.toString().length > 0
            source:   root.iconSource
            width:    48; height: 48
            fillMode: Image.PreserveAspectFit
            sourceSize.width: 96; sourceSize.height: 96
            anchors.horizontalCenter: parent.horizontalCenter
            opacity: Theme.highContrast ? 1.0 : 0.62
        }

        Rectangle {
            visible: !root.busy && !root.compact && root.iconSource.toString().length === 0
            width: 36
            height: 36
            radius: 18
            anchors.horizontalCenter: parent.horizontalCenter
            color: Theme.stateFill(root.variant)
            border.color: root._tone
            border.width: Theme.highContrast ? 2 : 1

            Text {
                anchors.centerIn: parent
                text: {
                    switch (root.variant) {
                    case "error":   return "!"
                    case "offline": return "-"
                    case "success": return "OK"
                    default:        return "i"
                    }
                }
                color: root._tone
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeTitle
                font.weight: Theme.fontWeightBold
            }
        }

        Text {
            width:               parent.width
            horizontalAlignment: Text.AlignHCenter
            text:   root.title
            color:  Theme.textPrimary
            font.family:    Theme.fontFamily
            font.pixelSize: root.compact ? Theme.fontSizeBody : Theme.fontSizeTitle
            font.weight:    Theme.fontWeightMedium
            elide: Text.ElideRight
            maximumLineCount: 2
        }

        Text {
            width:               parent.width
            horizontalAlignment: Text.AlignHCenter
            text:    root.message
            color:   Theme.textSecondary
            font.family:    Theme.fontFamily
            font.pixelSize: root.compact ? Theme.fontSizeLabel : Theme.fontSizeBody
            wrapMode: Text.WordWrap
            maximumLineCount: root.compact ? 2 : 4
            elide: Text.ElideRight
        }

        Row {
            visible: root.primaryActionText.length > 0 || root.secondaryActionText.length > 0
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Theme.spacingS

            PrimaryButton {
                visible: root.primaryActionText.length > 0
                text: root.primaryActionText
                onClicked: root.primaryActionTriggered()
            }

            GhostButton {
                visible: root.secondaryActionText.length > 0
                text: root.secondaryActionText
                onClicked: root.secondaryActionTriggered()
            }
        }
    }

    Accessible.role:        Accessible.StaticText
    Accessible.name:        root.title
    Accessible.description: root.busy ? qsTr("Loading. %1").arg(root.message) : root.message
}
