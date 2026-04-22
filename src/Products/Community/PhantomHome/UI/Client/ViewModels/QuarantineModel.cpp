/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "QuarantineModel.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QPointer>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

// v2 QuarantineAction dispatch code (legacy is 50; v2 routing is 231).
static constexpr auto kQuarantineActionV2 = static_cast<CommandType>(231);

namespace ShadowStrike::PhantomHome::UI::ViewModels {

// ── Per-row data ─────────────────────────────────────────────────────────────

struct QuarantineEntry {
    QString id;
    QString name;
    QString path;
    QString threat;
    qint64  size{0};           // bytes
    QString quarantinedAt;     // ISO-8601
    QString source;
};

// ── PIMPL ────────────────────────────────────────────────────────────────────

struct QuarantineModel::Impl {
    QVector<QuarantineEntry> rows;

    [[nodiscard]] static QuarantineEntry EntryFromJson(const QJsonObject& obj) noexcept
    {
        QuarantineEntry e;
        e.id            = obj.value(QLatin1String("id")).toString();
        e.name          = obj.value(QLatin1String("name")).toString();
        e.path          = obj.value(QLatin1String("path")).toString();
        e.threat        = obj.value(QLatin1String("threat")).toString();
        e.size          = static_cast<qint64>(obj.value(QLatin1String("size")).toDouble(0.0));
        e.quarantinedAt = obj.value(QLatin1String("quarantinedAt")).toString();
        e.source        = obj.value(QLatin1String("source")).toString();
        return e;
    }

    [[nodiscard]] int IndexOf(const QString& id) const noexcept
    {
        for (int i = 0; i < rows.size(); ++i)
            if (rows[i].id == id) return i;
        return -1;
    }
};

// ── QuarantineModel ───────────────────────────────────────────────────────────

QuarantineModel::QuarantineModel(QObject* parent)
    : QAbstractListModel(parent)
    , m_impl(std::make_unique<Impl>())
{
    refresh();
}

QuarantineModel::~QuarantineModel() = default;

int QuarantineModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) return 0;
    return m_impl->rows.size();
}

QVariant QuarantineModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid()
        || index.row() < 0
        || index.row() >= m_impl->rows.size())
        return {};

    const QuarantineEntry& e = m_impl->rows[index.row()];
    switch (static_cast<Role>(role)) {
    case IdRole:           return e.id;
    case NameRole:         return e.name;
    case PathRole:         return e.path;
    case ThreatRole:       return e.threat;
    case SizeRole:         return e.size;
    case QuarantinedAtRole: return e.quarantinedAt;
    case SourceRole:       return e.source;
    }
    return {};
}

QHash<int, QByteArray> QuarantineModel::roleNames() const
{
    return {
        {IdRole,            "itemId"},
        {NameRole,          "name"},
        {PathRole,          "path"},
        {ThreatRole,        "threat"},
        {SizeRole,          "size"},
        {QuarantinedAtRole, "quarantinedAt"},
        {SourceRole,        "source"},
    };
}

void QuarantineModel::refresh()
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::ListQuarantine,
        {},
        [self = QPointer<QuarantineModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            const QJsonArray arr = r.payload.value(QLatin1String("items")).toArray();
            QVector<QuarantineEntry> newRows;
            newRows.reserve(static_cast<int>(arr.size()));
            for (const auto& item : arr) {
                QuarantineEntry e = Impl::EntryFromJson(item.toObject());
                if (!e.id.isEmpty())
                    newRows.append(std::move(e));
            }
            self->beginResetModel();
            self->m_impl->rows = std::move(newRows);
            self->endResetModel();
        });
}

void QuarantineModel::restore(const QString& id)
{
    sendAction(id, QStringLiteral("restore"));
}

void QuarantineModel::deletePermanently(const QString& id)
{
    sendAction(id, QStringLiteral("delete"));
}

void QuarantineModel::deleteAll()
{
    // Optimistically clear the local model.
    beginResetModel();
    m_impl->rows.clear();
    endResetModel();

    (void)PipeClient::Instance().SendAndExpect(
        kQuarantineActionV2,
        QJsonObject{{QLatin1String("action"), QLatin1String("deleteAll")}},
        [self = QPointer<QuarantineModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                // Optimistic update failed — re-sync from service.
                emit self->requestError(r.errorCode, r.errorMessage);
                self->refresh();
                return;
            }
            emit self->actionCompleted(QString{}, QStringLiteral("deleteAll"));
        });
}

void QuarantineModel::sendAction(const QString& id, const QString& action)
{
    (void)PipeClient::Instance().SendAndExpect(
        kQuarantineActionV2,
        QJsonObject{
            {QLatin1String("id"),     id},
            {QLatin1String("action"), action}},
        [self = QPointer<QuarantineModel>(this), id, action](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            // Remove the confirmed row.
            const int idx = self->m_impl->IndexOf(id);
            if (idx >= 0) {
                self->beginRemoveRows({}, idx, idx);
                self->m_impl->rows.removeAt(idx);
                self->endRemoveRows();
            }
            emit self->actionCompleted(id, action);
        });
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
