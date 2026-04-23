import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Shapes
import ShadowStrike.Theming
import ShadowStrike.Accessibility

Item {
    id: root

    required property string scanState      // "idle"|"running"|"complete"
    property int  progressPercent:  0
    property int  threatsFound:     0
    signal startRequested()
    signal stopRequested()
    signal openResults()

    implicitWidth:  340
    implicitHeight: 180

    Rectangle {
        anchors.fill: parent
        radius:       Theme.radiusLarge
        color:        Theme.bgSurface
        border.color: Theme.strokeSubtle
        border.width: 1

        Column {
            anchors.centerIn: parent
            spacing:          Theme.spacingM

            // Idle state
            Column {
                visible:  root.scanState === "idle"
                spacing:  Theme.spacingS
                anchors.horizontalCenter: parent.horizontalCenter

                Text {
                    horizontalAlignment: Text.AlignHCenter
                    text:  qsTr("Quick Scan")
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeTitle
                    font.weight:    Theme.fontWeightBold
                }
                Text {
                    horizontalAlignment: Text.AlignHCenter
                    text:  qsTr("Scan common infection points in under a minute.")
                    color: Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    wrapMode: Text.WordWrap
                    width: 260
                }
                PrimaryButton {
                    text:      qsTr("Run Quick Scan")
                    onClicked: root.startRequested()
                }
            }

            // Running state
            Item {
                visible:  root.scanState === "running"
                width:    220
                height:   120

                // Circular progress using Shape arc
                Shape {
                    anchors.centerIn: parent
                    width:  100; height: 100

                    ShapePath {
                        strokeColor: Qt.rgba(Theme.strokeSubtle.r, Theme.strokeSubtle.g, Theme.strokeSubtle.b, 0.6)
                        strokeWidth: 6
                        fillColor:   "transparent"
                        PathAngleArc {
                            centerX: 50; centerY: 50
                            radiusX: 44; radiusY: 44
                            startAngle: 0
                            sweepAngle: 360
                        }
                    }

                    ShapePath {
                        strokeColor: Theme.accentCyan
                        strokeWidth: 6
                        fillColor:   "transparent"
                        capStyle:    ShapePath.RoundCap
                        PathAngleArc {
                            centerX: 50; centerY: 50
                            radiusX: 44; radiusY: 44
                            startAngle: -90
                            sweepAngle: 3.6 * root.progressPercent
                        }
                    }
                }

                Text {
                    anchors.centerIn: parent
                    anchors.verticalCenterOffset: -10
                    text:  root.progressPercent + "%"
                    color: Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeTitle
                    font.weight:    Theme.fontWeightBold
                    horizontalAlignment: Text.AlignHCenter
                }

                GhostButton {
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.bottom:           parent.bottom
                    text:      qsTr("Stop")
                    onClicked: root.stopRequested()
                }
            }

            // Complete state
            Column {
                visible:  root.scanState === "complete"
                spacing:  Theme.spacingS
                anchors.horizontalCenter: parent.horizontalCenter

                Text {
                    horizontalAlignment: Text.AlignHCenter
                    text:  root.threatsFound > 0
                           ? qsTr("%1 threat(s) found").arg(root.threatsFound)
                           : qsTr("Your device is clean.")
                    color: root.threatsFound > 0 ? Theme.crit : Theme.ok
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeTitle
                    font.weight:    Theme.fontWeightBold
                }

                PrimaryButton {
                    visible:   root.threatsFound > 0
                    text:      qsTr("View Results")
                    onClicked: root.openResults()
                }

                GhostButton {
                    text:      qsTr("Scan Again")
                    onClicked: root.startRequested()
                }
            }
        }
    }

    Accessible.role:        Accessible.Pane
    Accessible.name:        qsTr("Quick Scan")
    Accessible.description: {
        switch (root.scanState) {
        case "idle":     return qsTr("Ready to scan.")
        case "running":  return qsTr("Scanning, %1 percent complete.").arg(root.progressPercent)
        case "complete": return root.threatsFound > 0 ? qsTr("%1 threats found.").arg(root.threatsFound) : qsTr("Clean.")
        default:         return ""
        }
    }
}
