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

#include "ReportsModel.hpp"

#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QPointer>
#include <QTextStream>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

// ── Per-row data ─────────────────────────────────────────────────────────────

struct ReportEntry {
    QString id;
    QString type;
    QString severity;
    QString title;
    QString summary;
    qint64  timestamp{0}; // Unix seconds for QML relative-time helpers
    QString actor;
    QString detailsJson;
};

// ── PIMPL ────────────────────────────────────────────────────────────────────

struct ReportsModel::Impl {
    QVector<ReportEntry> rows;
    bool    loading{false};
    bool    hasMore{true};

    // Active filter
    QString   filterCategory;
    QDateTime filterFrom;
    QDateTime filterTo;
    int       filterMinSeverity{-1};   ///< Negative = no severity filter.

    [[nodiscard]] static QString SeverityToString(int severity) noexcept
    {
        switch (severity) {
        case 0:  return QStringLiteral("info");
        case 1:  return QStringLiteral("low");
        case 2:  return QStringLiteral("medium");
        case 3:  return QStringLiteral("high");
        case 4:  return QStringLiteral("critical");
        default: return QStringLiteral("unknown");
        }
    }

    [[nodiscard]] static QString TypeFromKind(int kind) noexcept
    {
        switch (kind) {
        case 1:  return QStringLiteral("scan");
        case 2:  return QStringLiteral("block");
        case 3:  return QStringLiteral("quarantine");
        case 4:  return QStringLiteral("update");
        case 5:  return QStringLiteral("policy");
        case 6:  return QStringLiteral("module");
        default: return QStringLiteral("unknown");
        }
    }

    [[nodiscard]] static QString IdFromJson(const QJsonValue& value) noexcept
    {
        if (value.isString()) {
            return value.toString();
        }
        if (value.isDouble()) {
            return QString::number(static_cast<qulonglong>(value.toDouble(0.0)));
        }
        return {};
    }

    [[nodiscard]] static ReportEntry EntryFromJson(const QJsonObject& obj) noexcept
    {
        ReportEntry e;
        e.id          = IdFromJson(obj.value(QLatin1String("id")));
        e.type        = obj.value(QLatin1String("type")).toString(
            TypeFromKind(obj.value(QLatin1String("kind")).toInt(0)));
        const QJsonValue severityValue = obj.value(QLatin1String("severity"));
        e.severity    = severityValue.isString()
            ? severityValue.toString()
            : SeverityToString(severityValue.toInt(0));
        e.title       = obj.value(QLatin1String("title")).toString();
        e.summary     = obj.value(QLatin1String("summary")).toString(
            obj.value(QLatin1String("description")).toString());
        const QJsonValue legacyTimestamp = obj.value(QLatin1String("timestamp"));
        if (legacyTimestamp.isDouble()) {
            e.timestamp = static_cast<qint64>(legacyTimestamp.toDouble(0.0));
        } else {
            const qint64 timestampMs = static_cast<qint64>(
                obj.value(QLatin1String("timestampMs")).toDouble(0.0));
            e.timestamp = timestampMs > 0 ? timestampMs / 1000 : 0;
        }
        e.actor       = obj.value(QLatin1String("actor")).toString(
            obj.value(QLatin1String("module")).toString());
        // Store the detail sub-object as compact JSON for QML / detail views.
        QJsonObject details = obj.value(QLatin1String("details")).toObject();
        if (details.isEmpty()) {
            details = obj;
        }
        if (!details.isEmpty())
            e.detailsJson = QString::fromUtf8(
                QJsonDocument(details).toJson(QJsonDocument::Compact));
        return e;
    }

    [[nodiscard]] QJsonObject buildFilter() const
    {
        QJsonObject f;
        if (!filterCategory.isEmpty()) {
            const QString c = filterCategory.toLower();
            int kind = 0;
            if (c == QLatin1String("detection")) {
                kind = 2;
            } else if (c == QLatin1String("block")) {
                kind = 2;
            } else if (c == QLatin1String("quarantine")) {
                kind = 3;
            } else if (c == QLatin1String("scan")) {
                kind = 1;
            } else if (c == QLatin1String("pgti")) {
                kind = 0;
            }
            if (kind > 0) {
                f[QLatin1String("category")] = kind;
            }
        }
        // EPOCH MILLISECONDS, AND THE UNIT IS IN THE KEY NAME.
        //
        // These were previously serialised as ISO 8601 under the keys "from"
        // and "to", and the service read neither - so the range was built on
        // every request and discarded on arrival. Sending the same unit the
        // store already keeps (ReportEntry::timestamp_unix_ms) removes both
        // the conversion and the date parser that would otherwise sit on a
        // path taking untrusted input.
        if (filterFrom.isValid())
            f[QLatin1String("fromMs")] =
                static_cast<qint64>(filterFrom.toMSecsSinceEpoch());
        if (filterTo.isValid())
            f[QLatin1String("toMs")] =
                static_cast<qint64>(filterTo.toMSecsSinceEpoch());
        if (filterMinSeverity >= 0)
            f[QLatin1String("minSeverity")] = filterMinSeverity;
        return f;
    }
};

// ── ReportsModel ──────────────────────────────────────────────────────────────

ReportsModel::ReportsModel(QObject* parent)
    : QAbstractListModel(parent)
    , m_impl(std::make_unique<Impl>())
{
    doLoad(0);
}

ReportsModel::~ReportsModel() = default;

int ReportsModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) return 0;
    return m_impl->rows.size();
}

QVariant ReportsModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid()
        || index.row() < 0
        || index.row() >= m_impl->rows.size())
        return {};

    const ReportEntry& e = m_impl->rows[index.row()];
    switch (static_cast<Role>(role)) {
    case IdRole:          return e.id;
    case TypeRole:        return e.type;
    case SeverityRole:    return e.severity;
    case TitleRole:       return e.title;
    case SummaryRole:     return e.summary;
    case TimestampRole:   return e.timestamp;
    case ActorRole:       return e.actor;
    case DetailsJsonRole: return e.detailsJson;
    }
    return {};
}

QHash<int, QByteArray> ReportsModel::roleNames() const
{
    return {
        {IdRole,          "reportId"},
        {TypeRole,        "type"},
        {SeverityRole,    "severity"},
        {TitleRole,       "title"},
        {SummaryRole,     "summary"},
        {TimestampRole,   "timestamp"},
        {ActorRole,       "actor"},
        {DetailsJsonRole, "detailsJson"},
    };
}

bool ReportsModel::isLoading() const noexcept { return m_impl->loading; }
bool ReportsModel::hasMore()   const noexcept { return m_impl->hasMore; }

void ReportsModel::loadMore()
{
    if (m_impl->loading || !m_impl->hasMore) return;
    doLoad(static_cast<int>(m_impl->rows.size()));
}

void ReportsModel::setFilter(const QString& category,
                              const QDateTime& from,
                              const QDateTime& to,
                              int minSeverity)
{
    m_impl->filterCategory    = category;
    m_impl->filterFrom        = from;
    m_impl->filterTo          = to;
    m_impl->filterMinSeverity = minSeverity;

    // Reset the model, then fetch from offset 0.
    beginResetModel();
    m_impl->rows.clear();
    m_impl->hasMore  = true;
    m_impl->loading  = false;
    endResetModel();
    emit hasMoreChanged();

    doLoad(0);
}

void ReportsModel::exportCsv(const QUrl& destination)
{
    const QString path = destination.toLocalFile();
    if (path.isEmpty()) {
        emit exportFailed(QStringLiteral("Invalid destination URL"));
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        emit exportFailed(file.errorString());
        return;
    }

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);

    // CSV header
    out << "ID,Type,Severity,Title,Summary,Timestamp,Actor\n";

    auto csvEscape = [](const QString& s) -> QString {
        QString escaped = s;
        escaped.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        return QLatin1Char('"') + escaped + QLatin1Char('"');
    };

    for (const ReportEntry& e : std::as_const(m_impl->rows)) {
        out << csvEscape(e.id)        << ','
            << csvEscape(e.type)      << ','
            << csvEscape(e.severity)  << ','
            << csvEscape(e.title)     << ','
            << csvEscape(e.summary)   << ','
            << csvEscape(QString::number(e.timestamp)) << ','
            << csvEscape(e.actor)     << '\n';
    }

    file.close();
    emit exportCompleted(destination);
}

void ReportsModel::doLoad(int offset)
{
    if (m_impl->loading) return;

    m_impl->loading = true;
    emit loadingChanged();

    QJsonObject payload{
        {QLatin1String("offset"), offset},
        {QLatin1String("limit"),  kPageSize}};
    const QJsonObject filter = m_impl->buildFilter();
    if (!filter.isEmpty())
        payload[QLatin1String("filter")] = filter;

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::GetReports,
        payload,
        [self = QPointer<ReportsModel>(this), offset](const Response& r) {
            if (!self) return;

            self->m_impl->loading = false;
            emit self->loadingChanged();

            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }

            const QJsonArray arr = r.payload.value(QLatin1String("items")).toArray();
            const bool moreAvail = r.payload.contains(QLatin1String("nextOffset"))
                || (offset + arr.size() < r.payload.value(QLatin1String("total")).toInt(0));

            if (offset == 0) {
                // Full reset (setFilter path or initial load)
                self->beginResetModel();
                self->m_impl->rows.clear();
                for (const auto& item : arr) {
                    ReportEntry e = Impl::EntryFromJson(item.toObject());
                    if (!e.id.isEmpty())
                        self->m_impl->rows.append(std::move(e));
                }
                self->endResetModel();
            } else {
                // Append new page
                const int firstNew = self->m_impl->rows.size();
                QVector<ReportEntry> newRows;
                newRows.reserve(static_cast<int>(arr.size()));
                for (const auto& item : arr) {
                    ReportEntry e = Impl::EntryFromJson(item.toObject());
                    if (!e.id.isEmpty())
                        newRows.append(std::move(e));
                }
                if (!newRows.isEmpty()) {
                    self->beginInsertRows({}, firstNew,
                                          firstNew + static_cast<int>(newRows.size()) - 1);
                    self->m_impl->rows.append(std::move(newRows));
                    self->endInsertRows();
                }
            }

            const bool prevHasMore = self->m_impl->hasMore;
            self->m_impl->hasMore  = moreAvail && (arr.size() >= ReportsModel::kPageSize);
            if (prevHasMore != self->m_impl->hasMore)
                emit self->hasMoreChanged();
        },
        std::chrono::milliseconds{10000});
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
