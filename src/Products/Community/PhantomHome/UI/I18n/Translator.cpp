// ShadowStrikePhantomUI — Translator implementation
//
// Global keyboard shortcut reference (for main.cpp wiring):
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

// <format> before Logger.hpp — Logger templates depend on std::format_string;
// Qt headers we include here (QTranslator, QLocale) don't pull it in.
#include <format>
// Logger before Windows.h to avoid macro conflicts.
#include <PhantomCore/Utils/Logger.hpp>

#include "Translator.hpp"

#include <PhantomCore/Config/ConfigManager.hpp>

#include <mutex>
#include <memory>

#include <QCoreApplication>
#include <QLocale>
#include <QTranslator>

namespace ShadowStrike::PhantomHome::UI {

namespace {

constexpr const wchar_t* kLogCat = L"Translator";

// Guards s_translator and s_currentLocale.
std::mutex                     s_mutex;
std::unique_ptr<QTranslator>   s_translator;
QString                        s_currentLocale;

// Attempt to load the .qm for localeName from the RCC resource path.
// Returns true and populates *out on success; logs and returns false otherwise.
[[nodiscard]] bool TryLoadQm(const QString& localeName,
                              std::unique_ptr<QTranslator>& out) noexcept
{
    const QString path = QStringLiteral(":/i18n/phantomhome_%1.qm").arg(localeName);

    auto translator = std::make_unique<QTranslator>();
    if (!translator->load(path)) {
        SS_LOG_WARN(kLogCat,
            L"Failed to load translation resource '%ls'.",
            reinterpret_cast<const wchar_t*>(path.utf16()));
        return false;
    }

    out = std::move(translator);
    return true;
}

// Install translator and update the stored locale string.
// Caller must hold s_mutex.
void InstallLocked(std::unique_ptr<QTranslator> newTranslator,
                   const QString&               localeName) noexcept
{
    // Remove and discard the old translator (if any).
    if (s_translator) {
        QCoreApplication::removeTranslator(s_translator.get());
    }

    s_translator    = std::move(newTranslator);
    s_currentLocale = localeName;

    QCoreApplication::installTranslator(s_translator.get());

    SS_LOG_INFO(kLogCat,
        L"Locale set to '%ls'.",
        reinterpret_cast<const wchar_t*>(localeName.utf16()));
}

} // namespace

// ---------------------------------------------------------------------------
// Translator::LoadFromConfigOrSystem
// ---------------------------------------------------------------------------
QString Translator::LoadFromConfigOrSystem()
{
    // 1. Try ConfigManager key "Home/UI/Locale".
    QString configLocale;
    {
        auto& cfg = ShadowStrike::Config::ConfigManager::Instance();
        if (cfg.IsInitialized()) {
            const std::string raw =
                cfg.GetValue<std::string>("Home/UI/Locale", std::string{});
            if (!raw.empty()) {
                configLocale = QString::fromStdString(raw);
            }
        }
    }

    // Ordered candidate list: config → system → en_US.
    QStringList candidates;
    if (!configLocale.isEmpty()) {
        candidates << configLocale;
    }
    const QString sysLocale = QLocale::system().name(); // e.g. "de_DE"
    if (!sysLocale.isEmpty() && sysLocale != configLocale) {
        candidates << sysLocale;
    }
    candidates << QStringLiteral("en_US");

    std::unique_ptr<QTranslator> loaded;
    QString                      effective;

    for (const QString& locale : candidates) {
        if (TryLoadQm(locale, loaded)) {
            effective = locale;
            break;
        }
    }

    if (!loaded) {
        // All candidates failed — operate without a translator (en_US source strings).
        SS_LOG_WARN(kLogCat,
            L"No translation resource could be loaded; falling back to source strings.");

        std::lock_guard lock(s_mutex);
        if (s_translator) {
            QCoreApplication::removeTranslator(s_translator.get());
            s_translator.reset();
        }
        s_currentLocale = QStringLiteral("en_US");
        return s_currentLocale;
    }

    {
        std::lock_guard lock(s_mutex);
        InstallLocked(std::move(loaded), effective);
    }

    return effective;
}

// ---------------------------------------------------------------------------
// Translator::SetLocale
// ---------------------------------------------------------------------------
bool Translator::SetLocale(QStringView localeName)
{
    if (localeName.isEmpty()) {
        SS_LOG_WARN(kLogCat, L"SetLocale called with empty locale name.");
        return false;
    }

    const QString name = localeName.toString();
    std::unique_ptr<QTranslator> loaded;

    if (!TryLoadQm(name, loaded)) {
        SS_LOG_ERROR(kLogCat,
            L"SetLocale: translation resource for '%ls' is unavailable.",
            reinterpret_cast<const wchar_t*>(name.utf16()));
        return false;
    }

    {
        std::lock_guard lock(s_mutex);
        InstallLocked(std::move(loaded), name);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Translator::CurrentLocale
// ---------------------------------------------------------------------------
QString Translator::CurrentLocale()
{
    std::lock_guard lock(s_mutex);
    return s_currentLocale;
}

} // namespace ShadowStrike::PhantomHome::UI
