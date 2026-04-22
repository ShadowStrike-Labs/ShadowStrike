/*
 * ============================================================================
 * ShadowStrike PhantomHome — Accessibility How-To Reference
 * ============================================================================
 *
 * PURPOSE
 * -------
 * This file is documentation only.  It does not contribute runtime logic.
 * Read it before authoring any new QML page or component in PhantomHome.
 *
 * ============================================================================
 * 1. ACCESSIBLE PROPERTIES  (NVDA / JAWS / Windows Narrator)
 * ============================================================================
 *
 * Every interactive control MUST declare:
 *
 *   Accessible.role        — one of the QAccessible::Role enum values exposed
 *                            to QML, e.g.:
 *                              Accessible.Button
 *                              Accessible.CheckBox
 *                              Accessible.RadioButton
 *                              Accessible.MenuItem
 *                              Accessible.Link
 *                              Accessible.StaticText
 *                              Accessible.Grouping      (sections / panels)
 *                              Accessible.List
 *                              Accessible.ListItem
 *
 *   Accessible.name        — Short label the screen reader announces.
 *                            Must be wrapped in qsTr() for i18n:
 *                              Accessible.name: qsTr("Scan Now")
 *
 *   Accessible.description — Longer description for complex controls:
 *                              Accessible.description: qsTr("Starts a full system scan.")
 *
 * State-bearing controls additionally need:
 *
 *   Accessible.checkState  — Qt.Checked / Qt.Unchecked / Qt.PartiallyChecked
 *   Accessible.checked     — bool alias (for radio / toggle)
 *   Accessible.pressed     — true while pointer/Enter is down
 *
 * Example — accessible icon button:
 *
 *   Rectangle {
 *       id: scanBtn
 *       focus: true
 *       Keys.onSpacePressed: scan()
 *       Keys.onReturnPressed: scan()
 *
 *       Accessible.role:        Accessible.Button
 *       Accessible.name:        qsTr("Quick Scan")
 *       Accessible.description: qsTr("Scans the most likely threat locations.")
 *       Accessible.onPressAction: scan()
 *
 *       FocusRing { target: scanBtn }
 *   }
 *
 * ============================================================================
 * 2. FOCUSRING USAGE
 * ============================================================================
 *
 * FocusRing is provided by ShadowStrike.Accessibility 1.0.
 * It renders the cyan 2 px outline around the target when activeFocus is true.
 *
 * Rules:
 *   - Add FocusRing as a CHILD of the focusable item (it uses anchors.fill).
 *   - Set `target: <parent id>`.
 *   - The FocusRing is invisible when the item does not have keyboard focus —
 *     no performance impact during pointer-only navigation.
 *   - Never hard-code a focus color; always let FocusRing read Theme.accentCyan
 *     so it automatically adjusts in High-Contrast mode.
 *
 * Example:
 *
 *   Button {
 *       id: closeBtn
 *       text: qsTr("Close")
 *       FocusRing { target: closeBtn }
 *   }
 *
 * ============================================================================
 * 3. KEYBOARD NAVIGATION — TAB ORDER
 * ============================================================================
 *
 * Tab order within a page is controlled by:
 *
 *   KeyNavigation.tab        — explicit next item
 *   KeyNavigation.backtab    — explicit previous item (Shift+Tab)
 *   KeyNavigation.priority   — KeyNavigation.BeforeItem if needed
 *
 * Recommended pattern for a page:
 *
 *   Item {
 *       id: page
 *       KeyNavigation.tab:    firstFocusable
 *       // Individual controls chain through KeyNavigation.tab
 *   }
 *
 * For lists/grids use activeFocusOnTab: true on the ListView and handle
 * Up/Down inside the delegate via Keys.onUpPressed / Keys.onDownPressed.
 *
 * ============================================================================
 * 4. GLOBAL KEYBOARD SHORTCUTS
 * ============================================================================
 *
 * The following application-wide shortcuts are registered in main.cpp via
 * QShortcut / Translator.cpp (see the comment block at the top of that file).
 * Do NOT re-register them in QML to avoid double-firing.
 *
 *   Ctrl+1     Navigate to Main (Overview) page
 *   Ctrl+2     Navigate to Security page
 *   Ctrl+3     Navigate to Performance page
 *   Ctrl+4     Navigate to Privacy page
 *   Ctrl+,     Open Settings page
 *   Ctrl+Shift+S  Start Quick Scan
 *   Ctrl+Q     Quit the application
 *   F1         Open in-app help / documentation
 *   Escape     Collapse open panel / close modal dialog
 *
 * QML pages may define additional LOCAL shortcuts (e.g., Delete on Quarantine
 * page to remove a selected item) but must not shadow the global set above.
 *
 * ============================================================================
 * 5. HIGH-CONTRAST MODE
 * ============================================================================
 *
 * The HighContrast singleton (ShadowStrike.Accessibility 1.0) exposes:
 *
 *   HighContrast.enabled  — bool, true when Windows HCM is active
 *
 * Pages should override fill colors and border colors when enabled:
 *
 *   color: HighContrast.enabled ? "black"          : Theme.surfaceDark
 *   border.color: HighContrast.enabled ? "white"   : Theme.borderSubtle
 *
 * The FocusRing already reads Theme.accentCyan which is expected to be set
 * to a high-contrast-safe value by the theming layer in HCM mode.
 *
 * ============================================================================
 * 6. INTERNATIONALISATION
 * ============================================================================
 *
 * - ALL user-visible strings must be wrapped in qsTr().
 * - Plurals: use qsTrId() with CLDR plural rules when count varies.
 * - Do NOT concatenate translated strings — use %1/%2 placeholders with arg():
 *
 *   text: qsTr("Scan completed in %1 seconds").arg(elapsed)
 *
 * - The active locale is set at startup by Translator::LoadFromConfigOrSystem().
 *   Runtime locale switch is available via Translator::SetLocale(localeName).
 *
 * Supported locales (translation skeleton .ts files exist for all):
 *   en_US  de_DE  tr_TR  ja_JP  es_ES  fr_FR  pt_BR  ru_RU
 *
 * ============================================================================
 */

import QtQuick

// Documentation-only stub — no runtime behaviour.
Item {}
