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

#include "ModulesListModel.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QPointer>

#include "../IPC/PipeClient.hpp"

// ── ModuleCatalog enrichment ────────────────────────────────────────────────
// ModuleCatalog.hpp is built by a sibling agent (module-catalog).  Until that
// header exposes a stable, compilable interface this model operates entirely
// from raw ListModules (200) service responses.  displayName, iconId, category,
// supportedModesMask, detailPage and binary flags all come directly from the
// service JSON.  When ModuleCatalog.hpp is ready, restore the enrichment block
// from git history and define SS_HAVE_MODULE_CATALOG=1 in the project.

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

// ── Per-row data ─────────────────────────────────────────────────────────────

struct ModuleEntry {
    QString id;
    QString displayName;
    QString iconId;
    int     category{0};
    int     currentMode{0};
    int     supportedModesMask{0};
    QString detailPage;
    int     statusHealth{0};
    QString statusDetail;
    bool    isBinary{false};
};

// ── PIMPL ────────────────────────────────────────────────────────────────────

struct ModulesListModel::Impl {
    QVector<ModuleEntry> rows;
    std::uint64_t        subToken{0};

    [[nodiscard]] static int HealthFromJson(const QJsonObject& obj) noexcept
    {
        const QJsonValue explicitHealth = obj.value(QLatin1String("statusHealth"));
        if (explicitHealth.isDouble()) {
            return explicitHealth.toInt(0);
        }

        if (explicitHealth.isString()) {
            const QString h = explicitHealth.toString().toLower();
            if (h == QLatin1String("healthy") || h == QLatin1String("on")) return 0;
            if (h == QLatin1String("atrisk") || h == QLatin1String("warning")) return 1;
            if (h == QLatin1String("critical") || h == QLatin1String("failed")) return 2;
            if (h == QLatin1String("off") || h == QLatin1String("disabled")) return -1;
        }

        switch (obj.value(QLatin1String("state")).toInt(0)) {
        case 3:
        case 4:  return 0;
        case 5:  return 2;
        case 2:
        case 6:  return -1;
        default: return 1;
        }
    }

    [[nodiscard]] static ModuleEntry EntryFromJson(const QJsonObject& obj) noexcept
    {
        ModuleEntry e;
        e.id                 = obj.value(QLatin1String("id")).toString();
        e.displayName        = obj.value(QLatin1String("displayName")).toString(e.id);
        e.iconId             = obj.value(QLatin1String("iconId")).toString(QStringLiteral("shield"));
        e.category           = obj.value(QLatin1String("category")).toInt(0);
        e.currentMode        = obj.value(QLatin1String("currentMode")).toInt(0);
        e.supportedModesMask = obj.value(QLatin1String("supportedModesMask")).toInt(0);
        e.detailPage         = obj.value(QLatin1String("detailPage")).toString();
        e.statusHealth       = HealthFromJson(obj);
        e.statusDetail       = obj.value(QLatin1String("statusDetail")).toString(
            obj.value(QLatin1String("lastError")).toString());
        e.isBinary           = obj.value(QLatin1String("binary")).toBool(false);
        return e;
    }

    [[nodiscard]] int IndexOf(const QString& id) const noexcept
    {
        for (int i = 0; i < rows.size(); ++i)
            if (rows[i].id == id) return i;
        return -1;
    }
};

// ── ModulesListModel ──────────────────────────────────────────────────────────

ModulesListModel::ModulesListModel(QObject* parent)
    : QAbstractListModel(parent)
    , m_impl(std::make_unique<Impl>())
{
    // Subscribe to ProtectionStateChanged (102) for real-time per-module deltas.
    m_impl->subToken = PipeClient::Instance().Subscribe(
        CommandType::ProtectionStateChanged,
        [self = QPointer<ModulesListModel>(this)](const QJsonObject& ev) {
            if (!self) return;
            const QJsonArray updated = ev.value(QLatin1String("modules")).toArray();
            if (updated.isEmpty()) {
                // Full-state broadcast — refresh the entire list.
                self->refresh();
                return;
            }
            for (const auto& item : updated) {
                const QJsonObject obj = item.toObject();
                const QString id = obj.value(QLatin1String("id")).toString();
                if (id.isEmpty()) continue;
                const int idx = self->m_impl->IndexOf(id);
                if (idx < 0) continue;

                ModuleEntry& e = self->m_impl->rows[idx];
                e.currentMode  = obj.value(QLatin1String("currentMode")).toInt(e.currentMode);
                e.statusHealth = Impl::HealthFromJson(obj);
                e.statusDetail = obj.value(QLatin1String("statusDetail")).toString(e.statusDetail);

                const QModelIndex mi = self->index(idx, 0);
                emit self->dataChanged(mi, mi,
                    {CurrentModeRole, StatusHealthRole, StatusDetailRole});
            }
        });

    refresh();
}

ModulesListModel::~ModulesListModel()
{
    if (m_impl->subToken)
        PipeClient::Instance().Unsubscribe(m_impl->subToken);
}

int ModulesListModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid()) return 0;
    return m_impl->rows.size();
}

QVariant ModulesListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid()
        || index.row() < 0
        || index.row() >= m_impl->rows.size())
        return {};

    const ModuleEntry& e = m_impl->rows[index.row()];
    switch (static_cast<Role>(role)) {
    case IdRole:               return e.id;
    case DisplayNameRole:      return e.displayName;
    case IconIdRole:           return e.iconId;
    case CategoryRole:         return e.category;
    case CurrentModeRole:      return e.currentMode;
    case SupportedModesMaskRole: return e.supportedModesMask;
    case DetailPageRole:       return e.detailPage;
    case StatusHealthRole:     return e.statusHealth;
    case StatusDetailRole:     return e.statusDetail;
    case BinaryRole:           return e.isBinary;
    }
    return {};
}

QHash<int, QByteArray> ModulesListModel::roleNames() const
{
    return {
        {IdRole,               "moduleId"},
        {DisplayNameRole,      "displayName"},
        {IconIdRole,           "iconId"},
        {CategoryRole,         "category"},
        {CurrentModeRole,      "currentMode"},
        {SupportedModesMaskRole, "supportedModesMask"},
        {DetailPageRole,       "detailPage"},
        {StatusHealthRole,     "statusHealth"},
        {StatusDetailRole,     "statusDetail"},
        {BinaryRole,           "binary"},
    };
}

void ModulesListModel::refresh()
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::ListModules,
        {},
        [self = QPointer<ModulesListModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            const QJsonArray arr = r.payload.value(QLatin1String("modules")).toArray();
            QVector<ModuleEntry> newRows;
            newRows.reserve(static_cast<int>(arr.size()));
            for (const auto& item : arr) {
                ModuleEntry entry = Impl::EntryFromJson(item.toObject());
                if (!entry.id.isEmpty())
                    newRows.append(std::move(entry));
            }
            self->beginResetModel();
            self->m_impl->rows = std::move(newRows);
            self->endResetModel();
        });
}

void ModulesListModel::setModuleMode(const QString& id, int mode)
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetModuleMode,
        QJsonObject{
            {QLatin1String("id"),   id},
            {QLatin1String("mode"), mode}},
        [self = QPointer<ModulesListModel>(this), id, mode](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            const int idx = self->m_impl->IndexOf(id);
            if (idx < 0) return;
            self->m_impl->rows[idx].currentMode = mode;
            const QModelIndex mi = self->index(idx, 0);
            emit self->dataChanged(mi, mi, {CurrentModeRole});
        });
}

void ModulesListModel::toggleBinaryModule(const QString& id, bool enabled)
{
    const int mode = enabled ? 2 : 0; // Balanced=2, Off=0
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::SetModuleEnabled,
        QJsonObject{
            {QLatin1String("id"),      id},
            {QLatin1String("enabled"), enabled}},
        [self = QPointer<ModulesListModel>(this), id, mode](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            const int idx = self->m_impl->IndexOf(id);
            if (idx < 0) return;
            self->m_impl->rows[idx].currentMode = mode;
            const QModelIndex mi = self->index(idx, 0);
            emit self->dataChanged(mi, mi, {CurrentModeRole});
        });
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
