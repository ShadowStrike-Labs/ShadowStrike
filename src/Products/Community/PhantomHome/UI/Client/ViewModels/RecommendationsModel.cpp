/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "RecommendationsModel.hpp"

#include <utility>

#include <QDesktopServices>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QPointer>
#include <QUrl>
#include <QVector>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

namespace {

constexpr qsizetype kMaxActionArgsBytes = 16 * 1024;

enum class ActionKind : int {
    NavigateToRoute = 0,
    SetModuleMode   = 1,
    RunCommand      = 2,
    ExternalUrl     = 3,
    Dismiss         = 4,
};

[[nodiscard]] QString SeverityFromWire(int severity) noexcept
{
    switch (severity) {
    case 2:  return QStringLiteral("crit");
    case 1:  return QStringLiteral("warn");
    default: return QStringLiteral("info");
    }
}

[[nodiscard]] QString TextForKey(const QString& key)
{
    if (key == QLatin1String("rec.pending_quarantine.title")) {
        return QStringLiteral("Review quarantined threats");
    }
    if (key == QLatin1String("rec.pending_quarantine.detail")) {
        return QStringLiteral("Quarantined items are waiting for review.");
    }
    if (key == QLatin1String("rec.zerotrust_unconfigured.title")) {
        return QStringLiteral("Review Zero Trust policy");
    }
    if (key == QLatin1String("rec.zerotrust_unconfigured.detail")) {
        return QStringLiteral("Zero Trust protection is available but has not been configured.");
    }
    if (key == QLatin1String("rec.high_block_rate.title")) {
        return QStringLiteral("High block activity detected");
    }
    if (key == QLatin1String("rec.high_block_rate.detail")) {
        return QStringLiteral("Recent detections are elevated. Review security reports.");
    }
    if (key == QLatin1String("rec.protection_paused.title")) {
        return QStringLiteral("Protection is paused");
    }
    if (key == QLatin1String("rec.protection_paused.detail")) {
        return QStringLiteral("Real-time protection is not actively enforcing policy.");
    }
    if (key == QLatin1String("rec.action.review_quarantine")) {
        return QStringLiteral("Review");
    }
    if (key == QLatin1String("rec.action.review_zerotrust")) {
        return QStringLiteral("Configure");
    }
    if (key == QLatin1String("rec.action.view_reports")) {
        return QStringLiteral("View reports");
    }
    if (key == QLatin1String("rec.action.resume_protection")) {
        return QStringLiteral("Resume");
    }
    return key;
}

[[nodiscard]] QJsonObject ParseArgsObject(const QString& argsJson)
{
    const QByteArray utf8 = argsJson.toUtf8();
    if (utf8.size() > kMaxActionArgsBytes) {
        return {};
    }

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(utf8, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        return {};
    }
    return doc.object();
}

[[nodiscard]] int ModeFromJson(const QJsonValue& value) noexcept
{
    if (value.isDouble()) {
        const int mode = value.toInt(-1);
        return (mode >= 0 && mode <= 3) ? mode : -1;
    }

    const QString mode = value.toString().toLower();
    if (mode == QLatin1String("off")) return 0;
    if (mode == QLatin1String("passive")) return 1;
    if (mode == QLatin1String("balanced")) return 2;
    if (mode == QLatin1String("aggressive")) return 3;
    return -1;
}

[[nodiscard]] QString RouteToUrl(const QString& route)
{
    if (route == QLatin1String("QuarantinePage") || route == QLatin1String("quarantine")) {
        return QStringLiteral("qrc:/qml/Pages/QuarantineSubroute.qml");
    }
    if (route == QLatin1String("ZeroTrustDetailPage") || route == QLatin1String("zerotrust")) {
        return QStringLiteral("qrc:/qml/Pages/ZeroTrustDetailPage.qml");
    }
    if (route == QLatin1String("ReportsPage") || route == QLatin1String("reports")) {
        return QStringLiteral("qrc:/qml/Pages/ReportsSubroute.qml");
    }
    return {};
}

[[nodiscard]] bool IsAllowedRunCommand(int commandType) noexcept
{
    switch (static_cast<CommandType>(commandType)) {
    case CommandType::ResumeProtection:
    case CommandType::UpdateSignatures:
        return true;
    default:
        return false;
    }
}

} // namespace

struct RecommendationActionEntry {
    int     kind{-1};
    QString argsJson;
    QString labelKey;
    QString label;
};

struct RecommendationEntry {
    QString id;
    QString displayName;
    QString detail;
    QString severity{QStringLiteral("info")};
    bool    dismissible{true};
    qint64  createdAtMs{0};
    QVector<RecommendationActionEntry> actions;
};

struct RecommendationsModel::Impl {
    QVector<RecommendationEntry> rows;
    bool loading{false};
    std::uint64_t subToken{0};

    [[nodiscard]] int indexOf(const QString& id) const noexcept
    {
        for (int i = 0; i < rows.size(); ++i) {
            if (rows[i].id == id) {
                return i;
            }
        }
        return -1;
    }

    [[nodiscard]] static RecommendationActionEntry ActionFromJson(const QJsonObject& obj)
    {
        RecommendationActionEntry action;
        action.kind = obj.value(QLatin1String("kind")).toInt(-1);
        action.argsJson = obj.value(QLatin1String("argsJson")).toString();
        action.labelKey = obj.value(QLatin1String("labelKey")).toString();
        action.label = TextForKey(action.labelKey);
        return action;
    }

    [[nodiscard]] static RecommendationEntry EntryFromJson(const QJsonObject& obj)
    {
        RecommendationEntry entry;
        entry.id = obj.value(QLatin1String("id")).toString();
        entry.displayName = TextForKey(obj.value(QLatin1String("titleKey")).toString());
        entry.detail = TextForKey(obj.value(QLatin1String("detailKey")).toString());
        entry.severity = SeverityFromWire(obj.value(QLatin1String("severity")).toInt(0));
        entry.dismissible = obj.value(QLatin1String("dismissible")).toBool(true);
        entry.createdAtMs = static_cast<qint64>(
            obj.value(QLatin1String("createdAtMs")).toDouble(0.0));

        const QJsonArray actions = obj.value(QLatin1String("actions")).toArray();
        entry.actions.reserve(actions.size());
        for (const QJsonValue& value : actions) {
            const QJsonObject actionObj = value.toObject();
            RecommendationActionEntry action = ActionFromJson(actionObj);
            if (action.kind >= 0) {
                entry.actions.append(std::move(action));
            }
        }
        return entry;
    }
};

RecommendationsModel::RecommendationsModel(QObject* parent)
    : QAbstractListModel(parent)
    , m_impl(std::make_unique<Impl>())
{
    m_impl->subToken = PipeClient::Instance().Subscribe(
        CommandType::RecommendationsChanged,
        [self = QPointer<RecommendationsModel>(this)](const QJsonObject&) {
            if (self) {
                self->refresh();
            }
        });
    refresh();
}

RecommendationsModel::~RecommendationsModel()
{
    if (m_impl && m_impl->subToken != 0) {
        PipeClient::Instance().Unsubscribe(m_impl->subToken);
    }
}

int RecommendationsModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : m_impl->rows.size();
}

QVariant RecommendationsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_impl->rows.size()) {
        return {};
    }

    const RecommendationEntry& entry = m_impl->rows[index.row()];
    const RecommendationActionEntry* firstAction =
        entry.actions.isEmpty() ? nullptr : &entry.actions.front();

    switch (static_cast<Role>(role)) {
    case IdRole:           return entry.id;
    case DisplayNameRole:  return entry.displayName;
    case DetailRole:       return entry.detail;
    case SeverityRole:     return entry.severity;
    case ActionLabelRole:  return firstAction ? firstAction->label : QString{};
    case DismissibleRole:  return entry.dismissible;
    case CreatedAtMsRole:  return entry.createdAtMs;
    case ActionKindRole:   return firstAction ? firstAction->kind : -1;
    case ActionRouteRole:
        if (!firstAction || firstAction->kind != static_cast<int>(ActionKind::NavigateToRoute)) {
            return QString{};
        }
        return RouteToUrl(ParseArgsObject(firstAction->argsJson).value(QLatin1String("route")).toString());
    }
    return {};
}

QHash<int, QByteArray> RecommendationsModel::roleNames() const
{
    return {
        {IdRole,          "id"},
        {DisplayNameRole, "displayName"},
        {DetailRole,      "detail"},
        {SeverityRole,    "severity"},
        {ActionLabelRole, "actionLabel"},
        {DismissibleRole, "dismissible"},
        {CreatedAtMsRole, "createdAtMs"},
        {ActionKindRole,  "actionKind"},
        {ActionRouteRole, "actionRoute"},
    };
}

bool RecommendationsModel::isLoading() const noexcept
{
    return m_impl->loading;
}

void RecommendationsModel::setLoading(bool loading)
{
    if (m_impl->loading == loading) {
        return;
    }
    m_impl->loading = loading;
    emit loadingChanged();
}

void RecommendationsModel::refresh()
{
    setLoading(true);
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::GetRecommendations,
        {},
        [self = QPointer<RecommendationsModel>(this)](const Response& r) {
            if (!self) {
                return;
            }
            self->setLoading(false);
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }

            QVector<RecommendationEntry> next;
            const QJsonArray items = r.payload.value(QLatin1String("recommendations")).toArray();
            next.reserve(items.size());
            for (const QJsonValue& value : items) {
                RecommendationEntry entry = Impl::EntryFromJson(value.toObject());
                if (!entry.id.isEmpty()) {
                    next.append(std::move(entry));
                }
            }

            self->beginResetModel();
            self->m_impl->rows = std::move(next);
            self->endResetModel();
        });
}

void RecommendationsModel::dismiss(const QString& id)
{
    if (id.isEmpty()) {
        emit requestError(QStringLiteral("invalid_recommendation"),
                          QStringLiteral("Recommendation id is required"));
        return;
    }

    const int idx = m_impl->indexOf(id);
    if (idx >= 0 && !m_impl->rows[idx].dismissible) {
        emit requestError(QStringLiteral("recommendation_not_dismissible"),
                          QStringLiteral("This recommendation cannot be dismissed"));
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::DismissRecommendation,
        QJsonObject{{QLatin1String("id"), id}},
        [self = QPointer<RecommendationsModel>(this)](const Response& r) {
            if (!self) {
                return;
            }
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->refresh();
        });
}

bool RecommendationsModel::executeAction(const QString& id)
{
    if (id.isEmpty()) {
        emit requestError(QStringLiteral("invalid_recommendation"),
                          QStringLiteral("Recommendation id is required"));
        return false;
    }

    const int idx = m_impl->indexOf(id);
    if (idx < 0) {
        emit requestError(QStringLiteral("recommendation_not_found"),
                          QStringLiteral("Recommendation is no longer active"));
        refresh();
        return false;
    }
    if (m_impl->rows[idx].actions.isEmpty()) {
        emit requestError(QStringLiteral("recommendation_no_action"),
                          QStringLiteral("Recommendation has no executable action"));
        return false;
    }

    const RecommendationActionEntry action = m_impl->rows[idx].actions.front();
    const auto kind = static_cast<ActionKind>(action.kind);
    const QJsonObject args = ParseArgsObject(action.argsJson);

    switch (kind) {
    case ActionKind::NavigateToRoute: {
        const QString url = RouteToUrl(args.value(QLatin1String("route")).toString());
        if (url.isEmpty()) {
            emit requestError(QStringLiteral("invalid_route"),
                              QStringLiteral("Recommendation action route is not supported"));
            return false;
        }
        emit navigateToUrl(url);
        return true;
    }
    case ActionKind::SetModuleMode: {
        const QString moduleId = args.value(QLatin1String("moduleId")).toString();
        const int mode = ModeFromJson(args.value(QLatin1String("mode")));
        if (moduleId.isEmpty() || mode < 0) {
            emit requestError(QStringLiteral("invalid_module_action"),
                              QStringLiteral("Recommendation module action is malformed"));
            return false;
        }
        (void)PipeClient::Instance().SendAndExpect(
            CommandType::SetModuleMode,
            QJsonObject{{QLatin1String("id"), moduleId}, {QLatin1String("mode"), mode}},
            [self = QPointer<RecommendationsModel>(this)](const Response& r) {
                if (!self) {
                    return;
                }
                if (!r.ok) {
                    emit self->requestError(r.errorCode, r.errorMessage);
                    return;
                }
                self->refresh();
            });
        return true;
    }
    case ActionKind::RunCommand: {
        const int commandType = args.value(QLatin1String("commandType")).toInt(0);
        if (!IsAllowedRunCommand(commandType)) {
            emit requestError(QStringLiteral("unsupported_command_action"),
                              QStringLiteral("Recommendation command action is not allowed"));
            return false;
        }
        QJsonObject payload;
        const QJsonValue payloadValue = args.value(QLatin1String("payload"));
        if (payloadValue.isObject()) {
            payload = payloadValue.toObject();
        } else if (payloadValue.isString()) {
            payload = ParseArgsObject(payloadValue.toString());
        }
        (void)PipeClient::Instance().SendAndExpect(
            static_cast<CommandType>(commandType),
            payload,
            [self = QPointer<RecommendationsModel>(this)](const Response& r) {
                if (!self) {
                    return;
                }
                if (!r.ok) {
                    emit self->requestError(r.errorCode, r.errorMessage);
                    return;
                }
                self->refresh();
            });
        return true;
    }
    case ActionKind::ExternalUrl: {
        const QUrl url(args.value(QLatin1String("url")).toString());
        if (!url.isValid() || url.scheme() != QLatin1String("https")) {
            emit requestError(QStringLiteral("invalid_external_url"),
                              QStringLiteral("Recommendation URL action is not trusted"));
            return false;
        }
        if (!QDesktopServices::openUrl(url)) {
            emit requestError(QStringLiteral("open_url_failed"),
                              QStringLiteral("Recommendation URL could not be opened"));
            return false;
        }
        return true;
    }
    case ActionKind::Dismiss:
        dismiss(id);
        return true;
    }

    emit requestError(QStringLiteral("unsupported_action"),
                      QStringLiteral("Recommendation action type is not supported"));
    return false;
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
