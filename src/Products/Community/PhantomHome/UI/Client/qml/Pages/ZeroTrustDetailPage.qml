/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * ZeroTrustDetailPage.qml — Deep-dive Zero-Trust policy configuration page.
 * Surfaced via Security → Zero-Trust → "Details".
 *
 * Binds to zeroTrustViewModel context property (gates gracefully if absent).
 */

import QtQuick
import QtQuick.Controls.Basic
import ShadowStrike.Theming
import ShadowStrike.Components
import ShadowStrike.Accessibility

PageHost {
    id: root

    // -------------------------------------------------------------------------
    // Local state (mirrored from VM if available)
    // -------------------------------------------------------------------------

    // Trust threshold [0.0, 1.0].
    property real  threshold:           0.75
    // Zero-Trust mode: when true, pins threshold=0.999 and disables all gates.
    property bool  zeroTrustModeActive: false
    // Gate toggles
    property bool  requirePublisherSigned: true
    property bool  requireWhitelist:       false
    // Numeric gate sliders [0.0, 1.0]
    property real  minReputation:          0.60
    property real  minStaticBenign:        0.70
    // Uncertain behavior: 0=SilentAllow, 1=Prompt, 2=SilentBlock
    property int   uncertainBehavior:      1
    // Pending prompts list (populated from zeroTrustViewModel.prompts)
    property var   pendingPrompts:         []
    // Recent decisions list
    property var   recentDecisions:        []

    // -------------------------------------------------------------------------
    // VM synchronization helpers
    // -------------------------------------------------------------------------

    function vmAvailable() {
        return typeof zeroTrustViewModel !== 'undefined' && zeroTrustViewModel !== null
    }

    function syncConfigFromVm() {
        if (!root.vmAvailable())
            return

        root.threshold              = zeroTrustViewModel.threshold
        root.zeroTrustModeActive    = zeroTrustViewModel.zeroTrustModeActive
        root.requirePublisherSigned = zeroTrustViewModel.requirePublisherSigned
        root.requireWhitelist       = zeroTrustViewModel.requireWhitelist
        root.minReputation          = zeroTrustViewModel.minReputation
        root.minStaticBenign        = zeroTrustViewModel.minStaticBenign
        root.uncertainBehavior      = zeroTrustViewModel.uncertainBehavior
    }

    function syncPromptsFromVm() {
        root.pendingPrompts = root.vmAvailable() ? zeroTrustViewModel.prompts : []
    }

    Component.onCompleted: {
        root.syncConfigFromVm()
        root.syncPromptsFromVm()
    }

    function vmSet(prop, val) {
        if (root.vmAvailable()) {
            zeroTrustViewModel[prop] = val;
        }
    }

    Connections {
        target: root.vmAvailable() ? zeroTrustViewModel : null
        function onThresholdChanged() {
            root.threshold = zeroTrustViewModel.threshold
        }
        function onZeroTrustModeActiveChanged() {
            root.zeroTrustModeActive = zeroTrustViewModel.zeroTrustModeActive
        }
        function onRequirePublisherSignedChanged() {
            root.requirePublisherSigned = zeroTrustViewModel.requirePublisherSigned
        }
        function onRequireWhitelistChanged() {
            root.requireWhitelist = zeroTrustViewModel.requireWhitelist
        }
        function onMinReputationChanged() {
            root.minReputation = zeroTrustViewModel.minReputation
        }
        function onMinStaticBenignChanged() {
            root.minStaticBenign = zeroTrustViewModel.minStaticBenign
        }
        function onUncertainBehaviorChanged() {
            root.uncertainBehavior = zeroTrustViewModel.uncertainBehavior
        }
        function onPromptsChanged() {
            root.syncPromptsFromVm()
        }
    }

    // -------------------------------------------------------------------------
    // Scroll container
    // -------------------------------------------------------------------------

    ScrollView {
        id:           scroll
        anchors.fill: parent
        contentWidth: parent.width
        clip:         true

        Column {
            id:      pageColumn
            width:   scroll.width
            spacing: Theme.spacingL
            padding: Theme.spacingL

            // -----------------------------------------------------------------
            // Page header
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Zero-Trust")
                width: parent.width - Theme.spacingL * 2
            }

            // -----------------------------------------------------------------
            // 1. Hero: TrustSlider
            // -----------------------------------------------------------------
            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    Text {
                        text:           qsTr("Trust threshold")
                        color:          Theme.textPrimary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeTitle
                        font.weight:    Theme.fontWeightBold
                    }

                    Text {
                        text:           qsTr("Files scoring below this threshold are blocked or prompted.")
                        color:          Theme.textSecondary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }

                    TrustSlider {
                        id:       heroSlider
                        width:    parent.width
                        value:    root.zeroTrustModeActive ? 0.999 : root.threshold
                        enabled:  !root.zeroTrustModeActive
                        opacity:  root.zeroTrustModeActive ? 0.40 : 1.0

                        Behavior on opacity { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

                        onValueChanged: {
                            if (!root.zeroTrustModeActive) {
                                root.threshold = value;
                                root.vmSet("threshold", value);
                            }
                        }

                        // Keyboard: Up/Down = ±0.01, PgUp/PgDn = ±0.10
                        Keys.onUpPressed:       { if (!root.zeroTrustModeActive) { root.threshold = Math.min(1.0, root.threshold + 0.01); root.vmSet("threshold", root.threshold); } }
                        Keys.onDownPressed:     { if (!root.zeroTrustModeActive) { root.threshold = Math.max(0.0, root.threshold - 0.01); root.vmSet("threshold", root.threshold); } }
                        Keys.onPageUpPressed:   { if (!root.zeroTrustModeActive) { root.threshold = Math.min(1.0, root.threshold + 0.10); root.vmSet("threshold", root.threshold); } }
                        Keys.onPageDownPressed: { if (!root.zeroTrustModeActive) { root.threshold = Math.max(0.0, root.threshold - 0.10); root.vmSet("threshold", root.threshold); } }

                        FocusRing      { target: heroSlider }
                        activeFocusOnTab: true
                        Accessible.role:        Accessible.Slider
                        Accessible.name:        qsTr("Trust threshold")
                        Accessible.description: qsTr("Use Up/Down to adjust by 0.01, Page Up/Down to adjust by 0.10")
                    }

                    // Threshold readout
                    Row {
                        spacing: Theme.spacingS

                        Text {
                            text:           qsTr("Threshold:")
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                            anchors.verticalCenter: parent.verticalCenter
                        }

                        Text {
                            text:           root.zeroTrustModeActive
                                            ? qsTr("0.999 (Zero-Trust mode)")
                                            : Number(root.threshold).toFixed(2)
                            color:          root.zeroTrustModeActive ? Theme.accentCyan : Theme.textPrimary
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeBody
                            font.weight:    Theme.fontWeightMedium
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 2. Trust gates
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Trust gates")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width:   parent.width - Theme.spacingL * 2
                opacity: root.zeroTrustModeActive ? 0.40 : 1.0
                Behavior on opacity { NumberAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    // Gate toggle: requirePublisherSigned
                    Row {
                        width:   parent.width
                        spacing: Theme.spacingM

                        Column {
                            width: parent.width - pubSignedSwitch.width - Theme.spacingM
                            spacing: 2

                            Text {
                                text:           qsTr("Require publisher signature")
                                color:          Theme.textPrimary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                            }
                            Text {
                                text:           qsTr("Block executables without a valid Authenticode signature.")
                                color:          Theme.textMuted
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeLabel
                                wrapMode:       Text.WordWrap
                                width:          parent.width
                            }
                        }

                        ToggleSwitch {
                            id:      pubSignedSwitch
                            checked: root.requirePublisherSigned
                            enabled: !root.zeroTrustModeActive
                            anchors.verticalCenter: parent.verticalCenter
                            onToggled: {
                                root.requirePublisherSigned = checked;
                                root.vmSet("requirePublisherSigned", checked);
                            }
                            FocusRing { target: pubSignedSwitch }
                            activeFocusOnTab: true
                            Accessible.role: Accessible.CheckBox
                            Accessible.name: qsTr("Require publisher signature")
                        }
                    }

                    Rectangle { width: parent.width; height: 1; color: Theme.strokeSubtle }

                    // Gate toggle: requireWhitelist
                    Row {
                        width:   parent.width
                        spacing: Theme.spacingM

                        Column {
                            width: parent.width - whitelistSwitch.width - Theme.spacingM
                            spacing: 2

                            Text {
                                text:           qsTr("Require whitelist entry")
                                color:          Theme.textPrimary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                            }
                            Text {
                                text:           qsTr("Only allow executables explicitly listed in the whitelist.")
                                color:          Theme.textMuted
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeLabel
                                wrapMode:       Text.WordWrap
                                width:          parent.width
                            }
                        }

                        ToggleSwitch {
                            id:      whitelistSwitch
                            checked: root.requireWhitelist
                            enabled: !root.zeroTrustModeActive
                            anchors.verticalCenter: parent.verticalCenter
                            onToggled: {
                                root.requireWhitelist = checked;
                                root.vmSet("requireWhitelist", checked);
                            }
                            FocusRing { target: whitelistSwitch }
                            activeFocusOnTab: true
                            Accessible.role: Accessible.CheckBox
                            Accessible.name: qsTr("Require whitelist entry")
                        }
                    }

                    Rectangle { width: parent.width; height: 1; color: Theme.strokeSubtle }

                    // Numeric slider: minReputation
                    Column {
                        width:   parent.width
                        spacing: Theme.spacingXS
                        enabled: !root.zeroTrustModeActive

                        Row {
                            width: parent.width

                            Text {
                                text:           qsTr("Minimum reputation score")
                                color:          Theme.textPrimary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                                width:          parent.width - reputationValue.width
                            }

                            Text {
                                id:             reputationValue
                                text:           Number(root.minReputation).toFixed(2)
                                color:          Theme.accentCyan
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                            }
                        }

                        Text {
                            text:           qsTr("Files with cloud reputation below this score are blocked.")
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                            wrapMode:       Text.WordWrap
                            width:          parent.width
                        }

                        Slider {
                            id:        reputationSlider
                            width:     parent.width
                            from:      0.0
                            to:        1.0
                            stepSize:  0.01
                            value:     root.minReputation
                            enabled:   !root.zeroTrustModeActive

                            background: Rectangle {
                                x:      reputationSlider.leftPadding
                                y:      reputationSlider.topPadding + reputationSlider.availableHeight / 2 - height / 2
                                width:  reputationSlider.availableWidth
                                height: 4
                                radius: 2
                                color:  Theme.strokeSubtle

                                Rectangle {
                                    width:  reputationSlider.visualPosition * parent.width
                                    height: parent.height
                                    radius: parent.radius
                                    color:  Theme.accentBlue
                                }
                            }

                            handle: Rectangle {
                                x:      reputationSlider.leftPadding + reputationSlider.visualPosition * reputationSlider.availableWidth - width / 2
                                y:      reputationSlider.topPadding + reputationSlider.availableHeight / 2 - height / 2
                                width:  16
                                height: 16
                                radius: 8
                                color:  reputationSlider.pressed ? Theme.accentCyan : Theme.textPrimary
                                border.color: Theme.accentBlue
                                border.width: 2
                            }

                            onValueChanged: {
                                root.minReputation = value;
                                root.vmSet("minReputation", value);
                            }

                            FocusRing { target: reputationSlider }
                            activeFocusOnTab: true
                            Accessible.role:         Accessible.Slider
                            Accessible.name:         qsTr("Minimum reputation score")
                        }
                    }

                    Rectangle { width: parent.width; height: 1; color: Theme.strokeSubtle }

                    // Numeric slider: minStaticBenign
                    Column {
                        width:   parent.width
                        spacing: Theme.spacingXS
                        enabled: !root.zeroTrustModeActive

                        Row {
                            width: parent.width

                            Text {
                                text:           qsTr("Minimum static benign score")
                                color:          Theme.textPrimary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                                width:          parent.width - staticBenignValue.width
                            }

                            Text {
                                id:             staticBenignValue
                                text:           Number(root.minStaticBenign).toFixed(2)
                                color:          Theme.accentCyan
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightMedium
                            }
                        }

                        Text {
                            text:           qsTr("Files scoring below this static analysis score are blocked.")
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                            wrapMode:       Text.WordWrap
                            width:          parent.width
                        }

                        Slider {
                            id:        staticBenignSlider
                            width:     parent.width
                            from:      0.0
                            to:        1.0
                            stepSize:  0.01
                            value:     root.minStaticBenign
                            enabled:   !root.zeroTrustModeActive

                            background: Rectangle {
                                x:      staticBenignSlider.leftPadding
                                y:      staticBenignSlider.topPadding + staticBenignSlider.availableHeight / 2 - height / 2
                                width:  staticBenignSlider.availableWidth
                                height: 4
                                radius: 2
                                color:  Theme.strokeSubtle

                                Rectangle {
                                    width:  staticBenignSlider.visualPosition * parent.width
                                    height: parent.height
                                    radius: parent.radius
                                    color:  Theme.accentBlue
                                }
                            }

                            handle: Rectangle {
                                x:      staticBenignSlider.leftPadding + staticBenignSlider.visualPosition * staticBenignSlider.availableWidth - width / 2
                                y:      staticBenignSlider.topPadding + staticBenignSlider.availableHeight / 2 - height / 2
                                width:  16
                                height: 16
                                radius: 8
                                color:  staticBenignSlider.pressed ? Theme.accentCyan : Theme.textPrimary
                                border.color: Theme.accentBlue
                                border.width: 2
                            }

                            onValueChanged: {
                                root.minStaticBenign = value;
                                root.vmSet("minStaticBenign", value);
                            }

                            FocusRing { target: staticBenignSlider }
                            activeFocusOnTab: true
                            Accessible.role:         Accessible.Slider
                            Accessible.name:         qsTr("Minimum static benign score")
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 3. Uncertain behavior
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Uncertain behavior")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    Text {
                        text:           qsTr("What happens when a file's trust score is inconclusive.")
                        color:          Theme.textSecondary
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeBody
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }

                    // ModePillRow: Off=SilentAllow, Passive=Prompt, Balanced=SilentBlock
                    // Aggressive (3) is hidden — supportedModesMask = 0b0111.
                    ModePillRow {
                        id:                 uncertainPillRow
                        currentMode:        root.uncertainBehavior
                        supportedModesMask: 0b0111
                        onModeChosen: function(mode) {
                            root.uncertainBehavior = mode;
                            root.vmSet("uncertainBehavior", mode);
                        }
                        FocusRing { target: uncertainPillRow }
                        activeFocusOnTab: true
                        Accessible.role: Accessible.ComboBox
                        Accessible.name: qsTr("Uncertain behavior policy")
                    }

                    // Mode description
                    Text {
                        text: {
                            switch (root.uncertainBehavior) {
                            case 0: return qsTr("Silent Allow — Inconclusive files run without interruption.")
                            case 1: return qsTr("Prompt — Ask before allowing inconclusive files to run.")
                            case 2: return qsTr("Silent Block — Inconclusive files are blocked automatically.")
                            default: return ""
                            }
                        }
                        color:          Theme.textMuted
                        font.family:    Theme.fontFamily
                        font.pixelSize: Theme.fontSizeLabel
                        wrapMode:       Text.WordWrap
                        width:          parent.width
                    }
                }
            }

            // -----------------------------------------------------------------
            // 4. Zero-Trust mode master switch
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Zero-Trust mode")
                width: parent.width - Theme.spacingL * 2
            }

            Card {
                width: parent.width - Theme.spacingL * 2
                accent: root.zeroTrustModeActive ? Theme.crit : Theme.strokeSubtle
                glow:   root.zeroTrustModeActive

                Column {
                    width:   parent.width
                    spacing: Theme.spacingM

                    Row {
                        width:   parent.width
                        spacing: Theme.spacingM

                        Column {
                            width: parent.width - ztSwitch.width - Theme.spacingM
                            spacing: Theme.spacingXS

                            Text {
                                text:           qsTr("Zero-Trust mode")
                                color:          root.zeroTrustModeActive ? Theme.crit : Theme.textPrimary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeBody
                                font.weight:    Theme.fontWeightBold
                                Behavior on color { ColorAnimation { duration: Theme.motionBase; easing.type: Theme.easingType } }
                            }

                            Text {
                                text:           qsTr("Forces threshold to 0.999 and disables all individual trust gates. "
                                                     + "Only files with near-perfect scores are permitted. "
                                                     + "Expect frequent prompts in this mode.")
                                color:          Theme.textSecondary
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeLabel
                                wrapMode:       Text.WordWrap
                                width:          parent.width
                            }
                        }

                        ToggleSwitch {
                            id:      ztSwitch
                            checked: root.zeroTrustModeActive
                            anchors.verticalCenter: parent.verticalCenter
                            onToggled: {
                                root.zeroTrustModeActive = checked;
                                if (checked) {
                                    root.threshold = 0.999;
                                }
                                root.vmSet("zeroTrustModeActive", checked);
                                if (checked) root.vmSet("threshold", 0.999);
                            }
                            FocusRing { target: ztSwitch }
                            activeFocusOnTab: true
                            Accessible.role: Accessible.CheckBox
                            Accessible.name: qsTr("Zero-Trust mode")
                            Accessible.description: qsTr("When enabled, pins threshold to 0.999 and disables all individual trust gates")
                        }
                    }

                    // Warning banner when active
                    Rectangle {
                        width:   parent.width
                        height:  warningRow.implicitHeight + Theme.spacingM * 2
                        radius:  Theme.radiusMedium
                        color:   Qt.rgba(Theme.crit.r, Theme.crit.g, Theme.crit.b, 0.12)
                        border.color: Qt.rgba(Theme.crit.r, Theme.crit.g, Theme.crit.b, 0.40)
                        border.width: 1
                        visible: root.zeroTrustModeActive

                        Row {
                            id:            warningRow
                            anchors {
                                verticalCenter: parent.verticalCenter
                                left:           parent.left
                                right:          parent.right
                                margins:        Theme.spacingM
                            }
                            spacing: Theme.spacingS

                            Text {
                                text:           "⚠"
                                color:          Theme.crit
                                font.pixelSize: Theme.fontSizeBody
                                anchors.verticalCenter: parent.verticalCenter
                            }

                            Text {
                                text:           qsTr("Zero-Trust mode is active. Individual gate settings are disabled and will be restored when mode is deactivated.")
                                color:          Theme.crit
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeLabel
                                wrapMode:       Text.WordWrap
                                width:          parent.width - 24 - Theme.spacingS
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 5. Pending prompts
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Pending prompts")
                width: parent.width - Theme.spacingL * 2
            }

            Loader {
                width:  parent.width - Theme.spacingL * 2
                active: root.pendingPrompts.length === 0
                sourceComponent: EmptyState {
                    title:   qsTr("No pending prompts")
                    message: qsTr("All recent execution decisions have been resolved.")
                }
            }

            Repeater {
                model: root.pendingPrompts
                delegate: Card {
                    width: parent.width - Theme.spacingL * 2

                    Column {
                        width:   parent.width
                        spacing: Theme.spacingS

                        Text {
                            text:           modelData.fileName || qsTr("Unknown file")
                            color:          Theme.textPrimary
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeBody
                            font.weight:    Theme.fontWeightMedium
                            elide:          Text.ElideLeft
                            width:          parent.width
                        }

                        Text {
                            text:           modelData.filePath || ""
                            color:          Theme.textMuted
                            font.family:    Theme.fontFamily
                            font.pixelSize: Theme.fontSizeLabel
                            elide:          Text.ElideLeft
                            width:          parent.width
                        }

                        Row {
                            Text {
                                text:           modelData.trustScore !== undefined
                                                ? qsTr("Trust score: %1").arg(Number(modelData.trustScore).toFixed(3))
                                                : ""
                                color:          Theme.warn
                                font.family:    Theme.fontFamily
                                font.pixelSize: Theme.fontSizeLabel
                            }
                        }

                        // Action buttons row
                        Row {
                            spacing: Theme.spacingS
                            width:   parent.width

                            PrimaryButton {
                                id:     allowBtn
                                text:   qsTr("Allow")
                                onClicked: {
                                    if (typeof zeroTrustViewModel !== 'undefined') {
                                        zeroTrustViewModel.answerPrompt(modelData.promptId, "allow");
                                    }
                                }
                                FocusRing { target: allowBtn }
                                activeFocusOnTab: true
                            }

                            GhostButton {
                                id:     blockBtn
                                text:   qsTr("Block")
                                onClicked: {
                                    if (typeof zeroTrustViewModel !== 'undefined') {
                                        zeroTrustViewModel.answerPrompt(modelData.promptId, "block");
                                    }
                                }
                                FocusRing { target: blockBtn }
                                activeFocusOnTab: true
                            }

                            GhostButton {
                                id:     alwaysAllowBtn
                                text:   qsTr("Always allow")
                                onClicked: {
                                    if (typeof zeroTrustViewModel !== 'undefined') {
                                        zeroTrustViewModel.answerPrompt(modelData.promptId, "alwaysAllow");
                                    }
                                }
                                FocusRing { target: alwaysAllowBtn }
                                activeFocusOnTab: true
                            }

                            GhostButton {
                                id:     alwaysBlockBtn
                                text:   qsTr("Always block")
                                onClicked: {
                                    if (typeof zeroTrustViewModel !== 'undefined') {
                                        zeroTrustViewModel.answerPrompt(modelData.promptId, "alwaysBlock");
                                    }
                                }
                                FocusRing { target: alwaysBlockBtn }
                                activeFocusOnTab: true
                            }
                        }
                    }
                }
            }

            // -----------------------------------------------------------------
            // 6. Recent decisions
            // -----------------------------------------------------------------
            SectionTitle {
                text:  qsTr("Recent decisions")
                width: parent.width - Theme.spacingL * 2
            }

            Loader {
                width:  parent.width - Theme.spacingL * 2
                active: root.recentDecisions.length === 0
                sourceComponent: EmptyState {
                    iconSource: "qrc:/icons/shield.svg"
                    title:   qsTr("No recent decisions")
                    message: qsTr("Zero-Trust decisions will appear here as executables are evaluated.")
                }
            }

            Repeater {
                model: root.recentDecisions
                delegate: ThreatRow {
                    required property var modelData
                    width:            parent.width - Theme.spacingL * 2
                    threatName:       modelData.fileName     || ""
                    filePath:         modelData.filePath     || ""
                    action:           modelData.decision     || "blocked"
                    timestampDisplay: modelData.timestamp    || ""
                }
            }

            // Bottom spacer
            Item { width: 1; height: Theme.spacingXL }
        }
    }
}
