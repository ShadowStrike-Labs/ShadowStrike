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

    // WHAT IS RUNNING, supplied by the page rather than assumed here.
    //
    // This tile is the only progress surface in the product, so a scan
    // started from the Explorer "Scan with ShadowStrike" verb arrives here
    // as well - and with nothing to name it, the running state showed a bare
    // percentage while the accessible name and the completed heading both
    // said "Quick Scan". A single-file right-click scan is neither quick-scan
    // scope nor machine-wide, so that was wrong in both directions.
    //
    // BOTH DEFAULT TO EMPTY AND ARE HIDDEN WHEN EMPTY. A page that does not
    // supply them shows exactly what it did before rather than a blank line,
    // and the idle state is untouched because its heading is correct: the
    // button below it does start a quick scan.
    property string activeScanLabel:  ""
    property string activeScanDetail: ""

    signal startRequested()
    signal stopRequested()
    signal openResults()

    implicitWidth:  340

    // The running state carries two extra lines the other states do not, so
    // the tile grows for it instead of clipping them.
    implicitHeight: root.scanState === "running" ? 250 : 180

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
            Column {
                visible:  root.scanState === "running"
                spacing:  Theme.spacingS
                anchors.horizontalCenter: parent.horizontalCenter

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    horizontalAlignment: Text.AlignHCenter
                    visible: root.activeScanLabel !== ""
                    text:    root.activeScanLabel
                    color:   Theme.textPrimary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    font.weight:    Theme.fontWeightBold
                    // Elided in the MIDDLE so a long path keeps both its
                    // volume and its file name, which are the two parts a
                    // user needs to recognise what is being scanned.
                    elide:            Text.ElideMiddle
                    maximumLineCount: 1
                    width:            260
                }

                Item {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width:    220
                    height:   110

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
                        // The offset that used to sit here reserved space for
                        // the Stop button, which now lives in the surrounding
                        // Column instead of overlapping the ring.
                        anchors.centerIn: parent
                        text:  root.progressPercent + "%"
                        color: Theme.textPrimary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeTitle
                        font.weight:    Theme.fontWeightBold
                        horizontalAlignment: Text.AlignHCenter
                    }
                }

                // The engine's own figures. EMPTY RATHER THAN ZEROED: the
                // page omits any part the service has not reported, because
                // "0 files/s" reads as a stalled scan rather than as an
                // unknown value.
                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    horizontalAlignment: Text.AlignHCenter
                    visible: root.activeScanDetail !== ""
                    text:    root.activeScanDetail
                    color:   Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    wrapMode: Text.WordWrap
                    width:    260
                }

                GhostButton {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text:      qsTr("Stop")
                    onClicked: root.stopRequested()
                }
            }

            // Complete state
            Column {
                visible:  root.scanState === "complete"
                spacing:  Theme.spacingS
                anchors.horizontalCenter: parent.horizontalCenter

                // WHICH scan finished. A verdict with no subject was the same
                // defect the running state carried: a machine-wide claim after
                // scanning one file states far more than was checked.
                Text {
                    horizontalAlignment: Text.AlignHCenter
                    visible: root.activeScanLabel !== ""
                    text:    root.activeScanLabel
                    color:   Theme.textSecondary
                    font.family:    Theme.fontFamily
                    font.pixelSize: Theme.fontSizeBody
                    elide:            Text.ElideMiddle
                    maximumLineCount: 1
                    width:            260
                }

                // WHAT WAS ESTABLISHED, NOT WHAT WOULD BE REASSURING.
                //
                // This heading read "Your device is clean." for every
                // completed scan, so checking a single folder - or one file
                // through the Explorer verb - announced a machine-wide
                // verdict. The label directly above already states the real
                // scope, and a heading that contradicts it is worse than no
                // heading at all: the user has no way to tell which of the
                // two lines to believe.
                //
                // THERE IS DELIBERATELY NO FULL-SCAN SPECIAL CASE, for two
                // independent reasons.
                //
                // First, the only scope signal this tile receives is
                // activeScanLabel, and MainPage builds it with qsTr() - so
                // keying a security claim on it would compare a TRANSLATED
                // string and stop matching, silently, in every language but
                // one. A claim about coverage must never depend on the
                // display locale.
                //
                // Second, and this is the substantive reason: a full scan
                // finding nothing does not establish a clean device. A create
                // the kernel circuit breaker admitted without scanning, a
                // cloud placeholder that cannot be read, and anything outside
                // the detection content we ship are all absent from this
                // count by construction. Reporting their absence as proof of
                // cleanliness is the same over-claim as counting a block that
                // was requested and never performed.
                //
                // "No threats found" is exactly what a zero count supports:
                // the stated scope was examined and nothing matched.
                Text {
                    horizontalAlignment: Text.AlignHCenter
                    text:  root.threatsFound > 0
                           ? qsTr("%1 threat(s) found").arg(root.threatsFound)
                           : qsTr("No threats found.")
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
    // Named after what is running when something is, so a screen reader is
    // not told "Quick Scan" during a custom scan.
    Accessible.name:        root.activeScanLabel !== ""
                            ? root.activeScanLabel
                            : qsTr("Quick Scan")
    Accessible.description: {
        switch (root.scanState) {
        case "idle":     return qsTr("Ready to scan.")
        case "running":  return qsTr("Scanning, %1 percent complete.").arg(root.progressPercent)
        // Scoped for the same reason as the visible heading. Accessible.name
        // above already carries the scan label, so a screen reader hears the
        // scope and then the verdict; a bare "Clean." here would put the
        // machine-wide claim back into the accessibility tree only.
        case "complete": return root.threatsFound > 0 ? qsTr("%1 threats found.").arg(root.threatsFound) : qsTr("No threats found.")
        default:         return ""
        }
    }
}
