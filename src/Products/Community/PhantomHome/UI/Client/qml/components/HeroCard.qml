import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import "../Theming"

/*
 * HeroCard
 * --------
 * Protection hero row: ShieldAnimator + copy + metrics + CTA buttons.
 * The state-tinted halo behind the shield shifts color with
 * `protectionState`.
 */
Item {
    id: root

    property string protectionState: "green"
    property string stateCopy:       "We are protecting you"
    property string stateSubCopy:    "Real-time protection is active."
    property string lastScan:        "\u2014"
    property int    threatsBlocked7d: 0

    signal detailsRequested()
    signal fastScanRequested()

    implicitHeight: heroRow.implicitHeight + Theme.sp8 * 2
    Layout.fillWidth: true

    Rectangle {
        anchors.fill: parent
        radius: Theme.radiusLg
        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: Theme.bg1 }
            GradientStop { position: 1.0; color: Theme.bg2 }
        }

        Rectangle {
            anchors.left: parent.left
            anchors.leftMargin: 60
            anchors.verticalCenter: parent.verticalCenter
            width: 260; height: 260
            radius: 130
            color: {
                if (root.protectionState === "green") return Qt.rgba(0.13, 0.76, 0.37, 0.07)
                if (root.protectionState === "amber") return Qt.rgba(0.96, 0.62, 0.04, 0.08)
                if (root.protectionState === "red")   return Qt.rgba(0.94, 0.27, 0.27, 0.08)
                return Qt.rgba(0.5, 0.5, 0.5, 0.05)
            }
            Behavior on color { ColorAnimation { duration: Theme.motionNormal } }
        }

        RowLayout {
            id: heroRow
            anchors.fill: parent
            anchors.margins: Theme.sp8
            spacing: Theme.sp6

            ShieldAnimator {
                protectionState: root.protectionState
                size: 180
                breathe: true
                Layout.alignment: Qt.AlignVCenter
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignVCenter
                spacing: Theme.sp3

                Text {
                    text: root.stateCopy
                    color: Theme.textStrong
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontTitle
                    font.weight: Font.Bold
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    text: root.stateSubCopy
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                RowLayout {
                    spacing: Theme.sp5
                    Layout.topMargin: Theme.sp2

                    Column {
                        spacing: 2
                        Text {
                            text: qsTr("Last scan")
                            color: Theme.textDim
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontCaption
                        }
                        Text {
                            text: root.lastScan
                            color: Theme.text
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            font.weight: Font.Medium
                        }
                    }
                    Rectangle { width: 1; height: 28; color: Qt.rgba(1, 1, 1, 0.08) }
                    Column {
                        spacing: 2
                        Text {
                            text: qsTr("Threats blocked (7d)")
                            color: Theme.textDim
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontCaption
                        }
                        Text {
                            text: root.threatsBlocked7d
                            color: Theme.text
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            font.weight: Font.Medium
                        }
                    }
                }

                RowLayout {
                    spacing: Theme.sp3
                    Layout.topMargin: Theme.sp3
                    PrimaryButton   { text: qsTr("Security details"); onClicked: root.detailsRequested() }
                    SecondaryButton { text: qsTr("Fast scan");        onClicked: root.fastScanRequested() }
                }
            }
        }
    }
}
