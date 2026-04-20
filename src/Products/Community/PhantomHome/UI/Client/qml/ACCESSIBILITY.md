# PhantomHome UI Accessibility (a11y)

Baseline accessibility for the QML shell. Targets keyboard-only operation
and Windows screen reader compatibility (Narrator, NVDA, JAWS) via Qt's
QAccessible bridge.

## What is set

* **Window**: `Accessible.role = Window`, name and description on the root
  `ApplicationWindow`.
* **Pages**: every page in `qml/pages/` declares `Accessible.role = Pane`
  with a `name` matching the sidebar label so screen readers announce the
  page on activation.
* **Sidebar**: `Accessible.role = PageTabList` on the sidebar; each nav
  delegate is `PageTab`, focusable via Tab, and reacts to Return / Space /
  PressAction.
* **Buttons** (Fast scan, title-bar Minimize, title-bar Close): `role =
  Button`, `name`, `description`, `focusPolicy = StrongFocus`.
* **Toggles** (per-module Switch on Security page): `role = CheckBox`,
  `name = "<module> enabled"`.
* **Radio group** (When a threat is detected): each `RadioButton` carries
  `role = RadioButton` and a localized `name`.

## Tab order

The implicit tab order follows declaration order in QML, which already
matches reading order: title-bar buttons -> sidebar entries -> page
content. No explicit `KeyNavigation` chain is required at this scale.

## Strings

All accessible strings go through `qsTr(...)` so the future i18n pass
picks them up without touching the visual hierarchy.

## What is intentionally out of scope for v1

* WCAG AA contrast audit of the dark theme palette - tracked separately.
* Magnifier / DPI scaling beyond Qt 6 defaults.
* RTL layout pass.
* Screen reader announcements for protection state transitions
  (Green/Amber/Red). The `ProtectionViewModel` will emit these as
  `Accessible.announcement` once Qt 6.8 ships the API stably; today we
  rely on the user re-focusing the status text.

## Verification checklist for QA

1. Tab from the title bar -> sidebar -> page content with Narrator on;
   confirm every focused element is announced with a meaningful name.
2. Activate every sidebar entry with Return and Space.
3. Toggle a Security switch with Space; Narrator should announce the new
   state.
4. Resize Windows display scaling to 200%; confirm no clipping in the
   sidebar or status copy.
