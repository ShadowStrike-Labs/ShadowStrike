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

#include "SettingsViewModel.hpp"

#include <QHash>
#include <QJsonObject>
#include <QJsonValue>
#include <QPointer>
#include <QVariant>
#include <shared_mutex>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

// ── PIMPL ────────────────────────────────────────────────────────────────────

struct SettingsViewModel::Impl {
    mutable std::shared_mutex       mutex;
    QHash<QString, QVariant>        cache;
    bool                            cacheLoaded{false};
    bool                            cacheLoading{false};
};

// ── SettingsViewModel ────────────────────────────────────────────────────────

SettingsViewModel::SettingsViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
}

SettingsViewModel::~SettingsViewModel() = default;

// ── Private helpers ──────────────────────────────────────────────────────────

void SettingsViewModel::primeCacheIfNeeded() const
{
    {
        std::shared_lock lock(m_impl->mutex);
        if (m_impl->cacheLoaded || m_impl->cacheLoading) return;
    }
    {
        std::unique_lock lock(m_impl->mutex);
        if (m_impl->cacheLoaded || m_impl->cacheLoading) return;
        m_impl->cacheLoading = true;
    }

    // Trigger async load; cast away const — this is intentional memoization.
    const_cast<SettingsViewModel*>(this)->refreshAll();
}

// ── Public API ────────────────────────────────────────────────────────────────

QVariant SettingsViewModel::get(const QString& key, const QVariant& def) const
{
    primeCacheIfNeeded();
    std::shared_lock lock(m_impl->mutex);
    return m_impl->cache.value(key, def);
}

void SettingsViewModel::set(const QString& key, const QVariant& value)
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::UpdateConfig,
        QJsonObject{
            {QLatin1String("key"),   key},
            {QLatin1String("value"), QJsonValue::fromVariant(value)}},
        [self = QPointer<SettingsViewModel>(this), key, value](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            {
                std::unique_lock lock(self->m_impl->mutex);
                self->m_impl->cache[key] = value;
            }
            emit self->settingChanged(key, value);
        });
}

void SettingsViewModel::refreshAll()
{
    {
        std::unique_lock lock(m_impl->mutex);
        m_impl->cacheLoading = true;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::GetConfig,
        {},
        [self = QPointer<SettingsViewModel>(this)](const Response& r) {
            if (!self) return;

            if (!r.ok) {
                {
                    std::unique_lock lock(self->m_impl->mutex);
                    self->m_impl->cacheLoading = false;
                }
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }

            const QJsonObject settings =
                r.payload.value(QLatin1String("values")).toObject();

            // Collect changed keys outside the lock, then emit signals
            // (signals must NOT be emitted while holding the mutex).
            QHash<QString, QVariant> incoming;
            incoming.reserve(settings.size());
            for (auto it = settings.begin(); it != settings.end(); ++it)
                incoming[it.key()] = it.value().toVariant();

            QVector<QPair<QString, QVariant>> changed;
            {
                std::unique_lock lock(self->m_impl->mutex);
                for (auto it = incoming.cbegin(); it != incoming.cend(); ++it) {
                    const auto existing = self->m_impl->cache.find(it.key());
                    if (existing == self->m_impl->cache.end()
                        || existing.value() != it.value())
                        changed.append({it.key(), it.value()});
                }
                self->m_impl->cache       = std::move(incoming);
                self->m_impl->cacheLoaded  = true;
                self->m_impl->cacheLoading = false;
            }

            for (const auto& [key, val] : std::as_const(changed))
                emit self->settingChanged(key, val);
        },
        std::chrono::milliseconds{8000});
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
