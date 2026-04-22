import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming

Item {
    id: root

    required property string text
    property string subtitle: ""

    implicitWidth:  title.implicitWidth
    implicitHeight: col.implicitHeight

    Column {
        id: col
        spacing: Theme.spacingXS

        Text {
            id: title
            text:  root.text
            color: Theme.textPrimary
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeTitle
            font.weight:    Theme.fontWeightBold
        }

        // Gradient underline accent bar
        Rectangle {
            width:  56
            height: 3
            radius: 2
            gradient: Gradient {
                orientation: Gradient.Horizontal
                GradientStop { position: 0.0; color: Theme.accentBlue }
                GradientStop { position: 1.0; color: Theme.accentCyan  }
            }
        }

        Text {
            visible: root.subtitle.length > 0
            text:    root.subtitle
            color:   Theme.textSecondary
            font.family:    Theme.fontFamily
            font.pixelSize: Theme.fontSizeBody
            font.weight:    Theme.fontWeightRegular
        }
    }
}
