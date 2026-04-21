import QtQuick
import QtQuick.Shapes
import "../Theming"

/*
 * ShieldAnimator
 * --------------
 * Hero protection-state visual. A large hexagonal shield with a soft
 * radial halo behind it. The whole thing breathes subtly at rest and
 * radiates attention when state is amber or red.
 *
 * The shape is drawn with a Canvas (deterministic sizing) and the halo
 * is a stack of concentric transparent circles, which renders fine on
 * every Qt 6.5+ backend without requiring QtGraphicalEffects or
 * GraphicsInfo.api checks.
 */
Item {
    id: root

    // --- API -------------------------------------------------------------
    // NOTE: uses `protectionState` (not `state`) - `state` is a reserved
    // Item property that drives the QML state machine and must not be
    // shadowed by an arbitrary string value.
    property string protectionState: "green"   // green | amber | red | paused
    property int    size:    240              // hero size; pages may scale down
    property bool   breathe: true              // disable when rendering off-screen

    implicitWidth:  size
    implicitHeight: size

    // Resolve a color for the current state.
    function _stateColor() {
        switch (protectionState) {
        case "green":  return Theme.success
        case "amber":  return Theme.warning
        case "red":    return Theme.danger
        case "paused": return Theme.textMuted
        }
        return Theme.accent
    }

    readonly property color currentColor: _stateColor()

    // Pulsation amplitude - larger for attention states.
    readonly property real _breatheTarget: (protectionState === "green" || protectionState === "paused") ? 1.0 : 1.05

    // ---------------------------------------------------------------------
    // Halo (stack of radial rings). Drawn first so the shield floats on it.
    // ---------------------------------------------------------------------
    Item {
        id: halo
        anchors.centerIn: parent
        width:  root.size * 1.35
        height: root.size * 1.35

        // Outer soft ring
        Rectangle {
            anchors.centerIn: parent
            width:  parent.width
            height: parent.height
            radius: width / 2
            color:  "transparent"
            border.color: Qt.rgba(root.currentColor.r, root.currentColor.g, root.currentColor.b, 0.05)
            border.width: 1
        }
        Rectangle {
            anchors.centerIn: parent
            width:  parent.width * 0.82
            height: parent.height * 0.82
            radius: width / 2
            color:  Qt.rgba(root.currentColor.r, root.currentColor.g, root.currentColor.b, 0.06)
        }
        Rectangle {
            anchors.centerIn: parent
            width:  parent.width * 0.64
            height: parent.height * 0.64
            radius: width / 2
            color:  Qt.rgba(root.currentColor.r, root.currentColor.g, root.currentColor.b, 0.10)
        }
        Rectangle {
            anchors.centerIn: parent
            width:  parent.width * 0.48
            height: parent.height * 0.48
            radius: width / 2
            color:  Qt.rgba(root.currentColor.r, root.currentColor.g, root.currentColor.b, 0.16)
        }

        // Slow breathing: scales the whole halo.
        scale: 1.0
        SequentialAnimation on scale {
            running: root.breathe
            loops: Animation.Infinite
            NumberAnimation { to: root._breatheTarget; duration: Theme.motionBreath; easing.type: Easing.InOutSine }
            NumberAnimation { to: 1.0;                 duration: Theme.motionBreath; easing.type: Easing.InOutSine }
        }
    }

    // ---------------------------------------------------------------------
    // Hexagonal shield body with inner gradient face. Drawn via Canvas so
    // we don't depend on QtQuick.Shapes availability at runtime (it ships
    // with Qt 6 Core but is an optional module on some Conan builds).
    // ---------------------------------------------------------------------
    Canvas {
        id: shieldCanvas
        anchors.centerIn: parent
        width:  root.size
        height: root.size
        antialiasing: true

        property color fillStrong: Qt.lighter(root.currentColor, 1.12)
        property color fillDeep:   Qt.darker(root.currentColor, 1.35)

        onPaint: {
            const ctx = getContext("2d");
            ctx.reset();

            const w = width;
            const h = height;
            const cx = w / 2;
            const cy = h / 2;
            const r  = Math.min(w, h) * 0.42;

            // Hexagonal path (flat-top).
            const pts = [];
            for (let i = 0; i < 6; ++i) {
                const a = Math.PI / 3 * i + Math.PI / 6;
                pts.push({ x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) });
            }

            // Outer stroke layer (subtle)
            ctx.beginPath();
            ctx.moveTo(pts[0].x, pts[0].y);
            for (let i = 1; i < 6; ++i) ctx.lineTo(pts[i].x, pts[i].y);
            ctx.closePath();

            const grad = ctx.createLinearGradient(cx, cy - r, cx, cy + r);
            grad.addColorStop(0.0, fillStrong);
            grad.addColorStop(1.0, fillDeep);
            ctx.fillStyle = grad;
            ctx.fill();

            ctx.lineWidth   = 1;
            ctx.strokeStyle = Qt.rgba(1, 1, 1, 0.08);
            ctx.stroke();

            // Inner glyph: a smaller concentric hex for depth.
            ctx.beginPath();
            for (let i = 0; i < 6; ++i) {
                const a = Math.PI / 3 * i + Math.PI / 6;
                const px = cx + (r * 0.70) * Math.cos(a);
                const py = cy + (r * 0.70) * Math.sin(a);
                if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
            }
            ctx.closePath();
            ctx.fillStyle = Qt.rgba(1, 1, 1, 0.08);
            ctx.fill();
        }

        // Repaint when state (color) changes.
        Connections {
            target: root
            function onCurrentColorChanged() { shieldCanvas.requestPaint() }
        }
        Component.onCompleted: requestPaint()
    }

    // State-dependent glyph drawn on top of the shield (check / ! / x).
    Text {
        anchors.centerIn: parent
        color: "#FFFFFF"
        font.family: Theme.fontFamily
        font.pixelSize: root.size * 0.28
        font.weight: Font.DemiBold
        text: {
            switch (root.protectionState) {
            case "green":  return "\u2713"   // check
            case "amber":  return "!"
            case "red":    return "\u2715"   // cross
            case "paused": return "\u25A0"   // square
            }
            return "\u2013"
        }
    }
}
