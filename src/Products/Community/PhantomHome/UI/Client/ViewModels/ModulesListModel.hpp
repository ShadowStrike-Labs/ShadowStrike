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
 * @file ModulesListModel.hpp
 * @brief QAbstractListModel exposing the ordered list of protection modules
 *        to QML.  Populated from ListModules (200) and enriched via
 *        ModuleCatalog when available.  Subscribes to ProtectionStateChanged
 *        (102) for real-time per-module state updates.
 */
#pragma once

#include <QAbstractListModel>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class ModulesListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        IdRole               = Qt::UserRole + 1,
        DisplayNameRole,
        IconIdRole,
        CategoryRole,
        CurrentModeRole,
        SupportedModesMaskRole,
        DetailPageRole,
        StatusHealthRole,
        StatusDetailRole,
        BinaryRole,
    };
    Q_ENUM(Role)

    explicit ModulesListModel(QObject* parent = nullptr);
    ~ModulesListModel() override;

    // QAbstractListModel interface
    [[nodiscard]] int      rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    // Actions invokable from QML
    Q_INVOKABLE void refresh();
    Q_INVOKABLE void setModuleMode(const QString& id, int mode);

    /**
     * @brief Toggle a binary (on/off) module.
     *
     * Internally maps enabled→Balanced(1), disabled→Off(0) so that binary
     * modules integrate cleanly with the per-module mode framework.
     *
     * @param id      Module identifier.
     * @param enabled true = enable (Balanced mode); false = disable (Off mode).
     */
    Q_INVOKABLE void toggleBinaryModule(const QString& id, bool enabled);

signals:
    void requestError(QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
