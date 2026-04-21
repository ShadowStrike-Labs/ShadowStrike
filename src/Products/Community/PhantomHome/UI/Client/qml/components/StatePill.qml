import QtQuick
import "../Theming"

/*
 * StatePill
 * ---------
 * Small rounded badge used to display protection-state text like
 * "Running" / "Paused" / "Degraded". The tint shifts with severity.
 */
Rectangle {
    id: root
    property string label: ""
    property string severity: "info"   // "ok"|"warn"|"bad"|"info"|"muted"

    implicitHeight: 22
    implicitWidth: labelItem.implicitWidth + Theme.sp4
    radius: height / 2

    color: {
        switch (severity) {
        case "ok":   return Qt.rgba(0.18, 0.89, 0.50, 0.14)
        case "warn": return Qt.rgba(1.00, 0.76, 0.28, 0.16)
        case "bad":  return Qt.rgba(1.00, 0.31, 0.43, 0.16)
        case "info": return Qt.rgba(0.17, 0.48, 1.00, 0.18)
        }
        return Qt.rgba(1, 1, 1, 0.06)
    }
    border.color: {
        switch (severity) {
        case "ok":   return Qt.rgba(0.18, 0.89, 0.50, 0.45)
        case "warn": return Qt.rgba(1.00, 0.76, 0.28, 0.45)
        case "bad":  return Qt.rgba(1.00, 0.31, 0.43, 0.45)
        case "info": return Qt.rgba(0.17, 0.48, 1.00, 0.55)
        }
        return Qt.rgba(1, 1, 1, 0.14)
    }
    border.width: 1

    Text {
        id: labelItem
        anchors.centerIn: parent
        text: root.label
        color: {
            switch (root.severity) {
            case "ok":   return Theme.success
            case "warn": return Theme.warning
            case "bad":  return Theme.danger
            case "info": return Theme.accentAlt
            }
            return Theme.textMuted
        }
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontSmall
        font.weight: Font.DemiBold
    }
}
