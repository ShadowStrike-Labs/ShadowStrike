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
 * @file QuarantineModel.hpp
 * @brief QAbstractListModel exposing the quarantine vault to QML.
 *
 * Populated from ListQuarantine (230).
 * Restore / delete route through the v2 QuarantineAction wire code (231).
 * deleteAll() sends a bulk "deleteAll" action and optimistically clears the
 * local model; on error it re-fetches via refresh().
 */
#pragma once

#include <QAbstractListModel>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class QuarantineModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        IdRole           = Qt::UserRole + 1,
        NameRole,
        PathRole,
        ThreatRole,
        SizeRole,
        QuarantinedAtRole,
        SourceRole,
    };
    Q_ENUM(Role)

    explicit QuarantineModel(QObject* parent = nullptr);
    ~QuarantineModel() override;

    [[nodiscard]] int      rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    /** Fetch the current quarantine list from the service. */
    Q_INVOKABLE void refresh();

    /**
     * @brief Restore a quarantined item to its original location.
     *
     * Sends QuarantineAction v2 (231) with {id, action:"restore"}.
     * Row is removed from the model only on service confirmation.
     */
    Q_INVOKABLE void restore(const QString& id);

    /**
     * @brief Permanently delete a quarantined item.
     *
     * Sends QuarantineAction v2 (231) with {id, action:"delete"}.
     * Row is removed from the model only on service confirmation.
     */
    Q_INVOKABLE void deletePermanently(const QString& id);

    /**
     * @brief Delete all quarantined items.
     *
     * Sends QuarantineAction v2 (231) with {action:"deleteAll"}.
     * Optimistically clears the model; re-fetches on error.
     */
    Q_INVOKABLE void deleteAll();

signals:
    void requestError(QString code, QString message);
    void actionCompleted(QString id, QString action);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void sendAction(const QString& id, const QString& action);
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
