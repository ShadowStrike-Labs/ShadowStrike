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
/**
 * @file SettingsViewModel.hpp
 * @brief Generic key/value settings bridge between QML and the service.
 *
 * Cache strategy:
 *   - First call to get() triggers an async GetConfig (31) to prime the cache.
 *   - Subsequent get() calls return cached values synchronously.
 *   - set() sends UpdateConfig (30) asynchronously; cache and settingChanged
 *     are updated only after the service confirms.
 *   - refreshAll() re-fetches GetConfig (31) and emits settingChanged for
 *     every key that changed.
 *
 * Thread safety: the cache is protected by std::shared_mutex.
 *   Reads hold a shared lock; writes hold an exclusive lock.
 *   All IPC callbacks arrive on the Qt main thread.
 */
#pragma once

#include <QObject>
#include <QVariant>
#include <QString>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class SettingsViewModel final : public QObject {
    Q_OBJECT

public:
    explicit SettingsViewModel(QObject* parent = nullptr);
    ~SettingsViewModel() override;

    /**
     * @brief Return the cached value for @p key, or @p def if absent.
     *
     * If the cache has not yet been primed, triggers an async GetConfig (31)
     * and returns @p def for this call; subsequent calls will use the cache.
     */
    [[nodiscard]] Q_INVOKABLE QVariant get(const QString& key,
                                           const QVariant& def = {}) const;

    /**
     * @brief Persist @p value for @p key via UpdateConfig (30).
     *
     * The local cache and settingChanged signal are updated only after the
     * service acknowledges the write.  On failure requestError is emitted
     * and the cache is left unchanged.
     */
    Q_INVOKABLE void set(const QString& key, const QVariant& value);

    /** Force-refresh the entire settings cache from GetConfig (31). */
    Q_INVOKABLE void refreshAll();

signals:
    void settingChanged(QString key, QVariant value);
    void requestError(QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void primeCacheIfNeeded() const;
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
