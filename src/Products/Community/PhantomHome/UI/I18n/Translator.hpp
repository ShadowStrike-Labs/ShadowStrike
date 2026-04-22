#pragma once
// ShadowStrikePhantomUI — Translator
//
// Keyboard shortcut reference (registered by main.cpp via QShortcut):
//
//   Ctrl+1          Navigate to Main (Overview) page
//   Ctrl+2          Navigate to Security page
//   Ctrl+3          Navigate to Performance page
//   Ctrl+4          Navigate to Privacy page
//   Ctrl+,          Open Settings page
//   Ctrl+Shift+S    Start Quick Scan
//   Ctrl+Q          Quit the application
//   F1              Open in-app help / documentation
//   Escape          Collapse open panel / close modal dialog
//
// Translator loads the matching .qm file from the embedded RCC resource
// (:/i18n/phantomhome_<locale>.qm) and installs it on QCoreApplication.
// The locale is resolved in this priority order:
//   1. ConfigManager key "Home/UI/Locale"
//   2. QLocale::system().name()
//   3. Hard fallback: en_US

#include <QString>
#include <QStringView>

namespace ShadowStrike::PhantomHome::UI {

class Translator final {
public:
    // Loads the .qm that matches ConfigManager key "Home/UI/Locale",
    // falling back to the system UI language, then to en_US.
    // Installs a QTranslator on QCoreApplication::instance().
    // Returns the effective locale string (e.g. "de_DE").
    [[nodiscard]] static QString LoadFromConfigOrSystem();

    // Switch locale at runtime.  Removes any previously installed translator
    // and installs the new one.  Returns true on success.
    [[nodiscard]] static bool SetLocale(QStringView localeName);

    // Currently active locale string (empty string before first load).
    [[nodiscard]] static QString CurrentLocale();

private:
    Translator()  = delete;
    ~Translator() = delete;
};

} // namespace ShadowStrike::PhantomHome::UI
