/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "PgtiViewModel.hpp"

#include <cstdint>
#include <utility>

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QPointer>
#include <QVector>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

namespace {

[[nodiscard]] QString DisplayNameFromId(const QString& id)
{
    QString display = id;
    display.replace(QLatin1Char('_'), QLatin1Char(' '));
    display.replace(QLatin1Char('-'), QLatin1Char(' '));

    bool capitalizeNext = true;
    for (QChar& ch : display) {
        if (ch.isSpace()) {
            capitalizeNext = true;
            continue;
        }
        if (capitalizeNext) {
            ch = ch.toUpper();
            capitalizeNext = false;
        }
    }
    return display;
}

} // namespace

struct PgtiFeedEntry {
    QString feedId;
    QString displayName;
    QString health{QStringLiteral("disabled")};
    qint64  lastSuccessTs{0};
    int     latencyMs{0};
    int     entryCount{0};
    bool    enabled{false};
};

struct PgtiFeedListModel::Impl {
    QVector<PgtiFeedEntry> rows;

    [[nodiscard]] static PgtiFeedEntry EntryFromJson(const QJsonObject& obj)
    {
        PgtiFeedEntry e;
        e.feedId        = obj.value(QLatin1String("id")).toString();
        e.displayName   = obj.value(QLatin1String("displayName")).toString(DisplayNameFromId(e.feedId));
        e.health        = obj.value(QLatin1String("health")).toString(QStringLiteral("disabled"));
        e.lastSuccessTs = static_cast<qint64>(obj.value(QLatin1String("lastSuccessTs")).toDouble(0.0));
        e.latencyMs     = obj.value(QLatin1String("latencyMs")).toInt(0);
        e.entryCount    = obj.value(QLatin1String("entriesLoaded")).toInt(
            obj.value(QLatin1String("entryCount")).toInt(0));
        e.enabled       = obj.value(QLatin1String("enabled")).toBool(
            e.health != QLatin1String("disabled"));
        return e;
    }

    [[nodiscard]] int IndexOf(const QString& feedId) const noexcept
    {
        for (int i = 0; i < rows.size(); ++i) {
            if (rows[i].feedId == feedId) {
                return i;
            }
        }
        return -1;
    }
};

PgtiFeedListModel::PgtiFeedListModel(QObject* parent)
    : QAbstractListModel(parent)
    , m_impl(std::make_unique<Impl>())
{
}

PgtiFeedListModel::~PgtiFeedListModel() = default;

int PgtiFeedListModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : m_impl->rows.size();
}

QVariant PgtiFeedListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_impl->rows.size()) {
        return {};
    }

    const PgtiFeedEntry& e = m_impl->rows[index.row()];
    switch (static_cast<Role>(role)) {
    case FeedIdRole:        return e.feedId;
    case DisplayNameRole:   return e.displayName;
    case HealthRole:        return e.health;
    case LastSuccessTsRole: return e.lastSuccessTs;
    case LatencyMsRole:     return e.latencyMs;
    case EntryCountRole:    return e.entryCount;
    case EnabledRole:       return e.enabled;
    }
    return {};
}

QHash<int, QByteArray> PgtiFeedListModel::roleNames() const
{
    return {
        {FeedIdRole,        "feedId"},
        {DisplayNameRole,   "displayName"},
        {HealthRole,        "health"},
        {LastSuccessTsRole, "lastSuccessTs"},
        {LatencyMsRole,     "latencyMs"},
        {EntryCountRole,    "entryCount"},
        {EnabledRole,       "enabled"},
    };
}

void PgtiFeedListModel::replaceFromJson(const QJsonArray& feeds)
{
    QVector<PgtiFeedEntry> next;
    next.reserve(static_cast<int>(feeds.size()));
    for (const QJsonValue& feed : feeds) {
        PgtiFeedEntry entry = Impl::EntryFromJson(feed.toObject());
        if (!entry.feedId.isEmpty()) {
            next.append(std::move(entry));
        }
    }

    beginResetModel();
    m_impl->rows = std::move(next);
    endResetModel();
}

void PgtiFeedListModel::setEnabledState(const QString& feedId, bool enabled)
{
    const int idx = m_impl->IndexOf(feedId);
    if (idx < 0) {
        return;
    }

    m_impl->rows[idx].enabled = enabled;
    if (!enabled) {
        m_impl->rows[idx].health = QStringLiteral("disabled");
    }

    const QModelIndex changed = index(idx, 0);
    emit dataChanged(changed, changed, {EnabledRole, HealthRole});
}

struct PgtiViewModel::Impl {
    PgtiFeedListModel feeds;
    bool loading{false};
    std::uint64_t subToken{0};
};

PgtiViewModel::PgtiViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
    m_impl->subToken = PipeClient::Instance().Subscribe(
        CommandType::PgtiFeedUpdated,
        [self = QPointer<PgtiViewModel>(this)](const QJsonObject&) {
            if (self) {
                self->loadFeeds();
            }
        });
    loadFeeds();
}

PgtiViewModel::~PgtiViewModel()
{
    if (m_impl && m_impl->subToken != 0) {
        PipeClient::Instance().Unsubscribe(m_impl->subToken);
    }
}

QAbstractListModel* PgtiViewModel::feeds() noexcept
{
    return &m_impl->feeds;
}

bool PgtiViewModel::isLoading() const noexcept
{
    return m_impl->loading;
}

void PgtiViewModel::setLoading(bool loading)
{
    if (m_impl->loading == loading) {
        return;
    }
    m_impl->loading = loading;
    emit loadingChanged();
}

void PgtiViewModel::loadFeeds()
{
    setLoading(true);
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::ListPGTIFeeds,
        {},
        [self = QPointer<PgtiViewModel>(this)](const Response& r) {
            if (!self) {
                return;
            }
            self->setLoading(false);
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->m_impl->feeds.replaceFromJson(r.payload.value(QLatin1String("feeds")).toArray());
        });
}

void PgtiViewModel::refreshAll()
{
    setLoading(true);
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::RefreshPGTIFeeds,
        {},
        [self = QPointer<PgtiViewModel>(this)](const Response& r) {
            if (!self) {
                return;
            }
            self->setLoading(false);
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            emit self->refreshAllCompleted();
            self->loadFeeds();
        });
}

void PgtiViewModel::refreshFeed(const QString& feedId)
{
    if (feedId.isEmpty()) {
        emit requestError(QStringLiteral("invalid_feed"), QStringLiteral("Feed id is required"));
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::RefreshPGTIFeeds,
        QJsonObject{{QLatin1String("id"), feedId}},
        [self = QPointer<PgtiViewModel>(this)](const Response& r) {
            if (!self) {
                return;
            }
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->loadFeeds();
        });
}

void PgtiViewModel::setFeedEnabled(const QString& feedId, bool enabled)
{
    if (feedId.isEmpty()) {
        emit requestError(QStringLiteral("invalid_feed"), QStringLiteral("Feed id is required"));
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetPGTIFeedEnabled,
        QJsonObject{
            {QLatin1String("id"), feedId},
            {QLatin1String("enabled"), enabled}},
        [self = QPointer<PgtiViewModel>(this), feedId, enabled](const Response& r) {
            if (!self) {
                return;
            }
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                self->loadFeeds();
                return;
            }
            self->m_impl->feeds.setEnabledState(feedId, enabled);
        });
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
