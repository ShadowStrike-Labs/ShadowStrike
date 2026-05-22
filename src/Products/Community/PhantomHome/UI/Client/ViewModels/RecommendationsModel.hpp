/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#pragma once

#include <QAbstractListModel>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class RecommendationsModel final : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(bool loading READ isLoading NOTIFY loadingChanged)

public:
    enum Role {
        IdRole = Qt::UserRole + 1,
        DisplayNameRole,
        DetailRole,
        SeverityRole,
        ActionLabelRole,
        DismissibleRole,
        CreatedAtMsRole,
        ActionKindRole,
        ActionRouteRole,
    };
    Q_ENUM(Role)

    explicit RecommendationsModel(QObject* parent = nullptr);
    ~RecommendationsModel() override;

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;
    [[nodiscard]] bool isLoading() const noexcept;

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void dismiss(const QString& id);
    Q_INVOKABLE bool executeAction(const QString& id);

signals:
    void loadingChanged();
    void requestError(QString code, QString message);
    void navigateToUrl(QString url);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void setLoading(bool loading);
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
