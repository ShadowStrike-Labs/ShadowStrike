/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "PrivacyViewModel.hpp"

#include <QDesktopServices>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QPointer>
#include <QUrl>
#include <QVariantMap>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {
namespace {

constexpr int kPrivacyCategory = 4;

[[nodiscard]] bool IsPrivacyRelevantModule(const QString& id, int category) noexcept
{
    if (category == kPrivacyCategory) {
        return true;
    }

    return id == QLatin1String("DataLeakProtection")
        || id == QLatin1String("DNSLeakProtection")
        || id == QLatin1String("PrivacyIPLeakProtection")
        || id == QLatin1String("TrackerBlocker");
}

[[nodiscard]] QString DisplayNameForId(const QString& id)
{
    if (id == QLatin1String("WebcamProtector")) return QStringLiteral("Webcam Protector");
    if (id == QLatin1String("MicrophoneGuard")) return QStringLiteral("Microphone Guard");
    if (id == QLatin1String("LocationPrivacy")) return QStringLiteral("Location Privacy");
    if (id == QLatin1String("CookieManager")) return QStringLiteral("Cookie Manager");
    if (id == QLatin1String("PrivacyCleaner")) return QStringLiteral("Privacy Cleaner");
    if (id == QLatin1String("DataLeakProtection")) return QStringLiteral("Data Leak Protection");
    if (id == QLatin1String("DNSLeakProtection")) return QStringLiteral("DNS Leak Protection");
    if (id == QLatin1String("PrivacyIPLeakProtection")) return QStringLiteral("IP Leak Protection");
    if (id == QLatin1String("TrackerBlocker")) return QStringLiteral("Tracker Blocker");
    return id;
}

[[nodiscard]] QString DescriptionForId(const QString& id)
{
    if (id == QLatin1String("WebcamProtector")) return QStringLiteral("Blocks unauthorized webcam access");
    if (id == QLatin1String("MicrophoneGuard")) return QStringLiteral("Prevents silent microphone capture");
    if (id == QLatin1String("LocationPrivacy")) return QStringLiteral("Masks precise location from apps");
    if (id == QLatin1String("CookieManager")) return QStringLiteral("Manages and cleans tracking cookies");
    if (id == QLatin1String("PrivacyCleaner")) return QStringLiteral("Erases browsing artifacts on demand");
    if (id == QLatin1String("DataLeakProtection")) return QStringLiteral("Monitors sensitive clipboard and file transfers");
    if (id == QLatin1String("DNSLeakProtection")) return QStringLiteral("Routes DNS through secure resolver policy");
    if (id == QLatin1String("PrivacyIPLeakProtection")) return QStringLiteral("Prevents real IP exposure via WebRTC");
    if (id == QLatin1String("TrackerBlocker")) return QStringLiteral("Blocks cross-site tracking domains");
    return {};
}

[[nodiscard]] QString StateFromModule(int currentMode, int statusHealth)
{
    if (statusHealth == 2) return QStringLiteral("critical");
    if (statusHealth == 1) return QStringLiteral("warning");
    if (statusHealth < 0 || currentMode == 0) return QStringLiteral("off");
    return QStringLiteral("on");
}

[[nodiscard]] int SafeIntFromValues(const QJsonObject& values, QLatin1String key, int fallback) noexcept
{
    const QJsonValue value = values.value(key);
    if (!value.isDouble()) {
        return fallback;
    }
    const int parsed = value.toInt(fallback);
    return parsed < 0 ? fallback : parsed;
}

} // namespace

struct PrivacyViewModel::Impl {
    int webcamAccessBlocked{0};
    int micAccessBlocked{0};
    int locationAccessBlocked{0};
    int cookiesBlocked{0};
    QVariantList recentPrivacyEvents;
    QVariantList modules;
    bool loading{false};
};

PrivacyViewModel::PrivacyViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
    refresh();
}

PrivacyViewModel::~PrivacyViewModel() = default;

int PrivacyViewModel::webcamAccessBlocked() const noexcept { return m_impl->webcamAccessBlocked; }
int PrivacyViewModel::micAccessBlocked() const noexcept { return m_impl->micAccessBlocked; }
int PrivacyViewModel::locationAccessBlocked() const noexcept { return m_impl->locationAccessBlocked; }
int PrivacyViewModel::cookiesBlocked() const noexcept { return m_impl->cookiesBlocked; }
QVariantList PrivacyViewModel::recentPrivacyEvents() const { return m_impl->recentPrivacyEvents; }
QVariantList PrivacyViewModel::modules() const { return m_impl->modules; }
bool PrivacyViewModel::isLoading() const noexcept { return m_impl->loading; }

void PrivacyViewModel::setLoading(bool loading)
{
    if (m_impl->loading == loading) {
        return;
    }
    m_impl->loading = loading;
    emit loadingChanged();
}

void PrivacyViewModel::applyConfigPayload(const QJsonObject& payload)
{
    const QJsonObject values = payload.value(QLatin1String("values")).toObject();

    const int webcam = SafeIntFromValues(values, QLatin1String("Home/Privacy/WebcamAccessBlocked"), 0);
    const int mic = SafeIntFromValues(values, QLatin1String("Home/Privacy/MicrophoneAccessBlocked"), 0);
    const int location = SafeIntFromValues(values, QLatin1String("Home/Privacy/LocationAccessBlocked"), 0);
    const int cookies = SafeIntFromValues(values, QLatin1String("Home/Privacy/CookiesBlocked"), 0);

    if (webcam != m_impl->webcamAccessBlocked
        || mic != m_impl->micAccessBlocked
        || location != m_impl->locationAccessBlocked
        || cookies != m_impl->cookiesBlocked) {
        m_impl->webcamAccessBlocked = webcam;
        m_impl->micAccessBlocked = mic;
        m_impl->locationAccessBlocked = location;
        m_impl->cookiesBlocked = cookies;
        emit dashboardChanged();
    }
}

void PrivacyViewModel::applyModulesPayload(const QJsonObject& payload)
{
    const QJsonArray items = payload.value(QLatin1String("modules")).toArray();
    QVariantList next;
    next.reserve(items.size());

    for (const QJsonValue& item : items) {
        const QJsonObject obj = item.toObject();
        const QString id = obj.value(QLatin1String("id")).toString();
        if (id.isEmpty()) {
            continue;
        }

        const int category = obj.value(QLatin1String("category")).toInt(-1);
        if (!IsPrivacyRelevantModule(id, category)) {
            continue;
        }

        const int currentMode = obj.value(QLatin1String("currentMode")).toInt(0);
        const int statusHealth = obj.value(QLatin1String("statusHealth")).toInt(0);
        const int supportedModesMask = obj.value(QLatin1String("supportedModesMask")).toInt(0x05);

        QVariantMap row;
        row.insert(QStringLiteral("moduleId"), id);
        row.insert(QStringLiteral("displayName"),
                   obj.value(QLatin1String("displayName")).toString(DisplayNameForId(id)));
        row.insert(QStringLiteral("description"), DescriptionForId(id));
        row.insert(QStringLiteral("iconSource"), QStringLiteral("qrc:/icons/shield.svg"));
        row.insert(QStringLiteral("state"), StateFromModule(currentMode, statusHealth));
        row.insert(QStringLiteral("enabled"), currentMode != 0 && statusHealth >= 0);
        row.insert(QStringLiteral("currentMode"), currentMode);
        row.insert(QStringLiteral("supportedModesMask"), supportedModesMask);
        next.append(std::move(row));
    }

    m_impl->modules = std::move(next);
    emit modulesChanged();
}

void PrivacyViewModel::refresh()
{
    setLoading(true);
    auto& pipe = PipeClient::Instance();

    (void)pipe.SendAndExpect(
        CommandType::GetConfig,
        QJsonObject{{QLatin1String("prefix"), QStringLiteral("Home/Privacy")}},
        [self = QPointer<PrivacyViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->applyConfigPayload(r.payload);
        });

    (void)pipe.SendAndExpect(
        CommandType::ListModules,
        {},
        [self = QPointer<PrivacyViewModel>(this)](const Response& r) {
            if (!self) return;
            self->setLoading(false);
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->applyModulesPayload(r.payload);
        });
}

void PrivacyViewModel::setModuleEnabled(const QString& moduleId, bool enabled)
{
    if (moduleId.isEmpty()) {
        emit requestError(QStringLiteral("invalid_module"), QStringLiteral("Module id is required"));
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetModuleEnabled,
        QJsonObject{{QLatin1String("id"), moduleId}, {QLatin1String("enabled"), enabled}},
        [self = QPointer<PrivacyViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->refresh();
        });
}

void PrivacyViewModel::setModuleMode(const QString& moduleId, int mode)
{
    if (moduleId.isEmpty() || mode < 0 || mode > 3) {
        emit requestError(QStringLiteral("invalid_module_mode"),
                          QStringLiteral("Module id and mode 0-3 are required"));
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetModuleMode,
        QJsonObject{{QLatin1String("id"), moduleId}, {QLatin1String("mode"), mode}},
        [self = QPointer<PrivacyViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->refresh();
        });
}

void PrivacyViewModel::runPrivacyCleanup()
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetModuleMode,
        QJsonObject{{QLatin1String("id"), QStringLiteral("PrivacyCleaner")},
                    {QLatin1String("mode"), 2}},
        [self = QPointer<PrivacyViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            emit self->privacyActionCompleted(QStringLiteral("privacyCleanup"));
            self->refresh();
        });
}

void PrivacyViewModel::auditPermissions()
{
    refresh();
    if (!QDesktopServices::openUrl(QUrl(QStringLiteral("ms-settings:privacy")))) {
        emit requestError(QStringLiteral("open_privacy_settings_failed"),
                          QStringLiteral("Windows privacy settings could not be opened"));
    }
}

void PrivacyViewModel::openBrowserPrivacy()
{
    if (!QDesktopServices::openUrl(QUrl(QStringLiteral("ms-settings:privacy-webcam")))) {
        emit requestError(QStringLiteral("open_browser_privacy_failed"),
                          QStringLiteral("Windows browser/privacy settings could not be opened"));
    }
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels

