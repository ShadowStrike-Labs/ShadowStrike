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
#include <QObject>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class PgtiFeedListModel final : public QAbstractListModel {
    Q_OBJECT

public:
    enum Role {
        FeedIdRole = Qt::UserRole + 1,
        DisplayNameRole,
        HealthRole,
        LastSuccessTsRole,
        LatencyMsRole,
        EntryCountRole,
        EnabledRole,
    };
    Q_ENUM(Role)

    explicit PgtiFeedListModel(QObject* parent = nullptr);
    ~PgtiFeedListModel() override;

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    void replaceFromJson(const QJsonArray& feeds);
    void setEnabledState(const QString& feedId, bool enabled);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

class PgtiViewModel final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QAbstractListModel* feeds READ feeds CONSTANT)
    Q_PROPERTY(bool loading READ isLoading NOTIFY loadingChanged)

public:
    explicit PgtiViewModel(QObject* parent = nullptr);
    ~PgtiViewModel() override;

    [[nodiscard]] QAbstractListModel* feeds() noexcept;
    [[nodiscard]] bool isLoading() const noexcept;

    Q_INVOKABLE void refreshAll();
    Q_INVOKABLE void refreshFeed(const QString& feedId);
    Q_INVOKABLE void setFeedEnabled(const QString& feedId, bool enabled);

signals:
    void loadingChanged();
    void refreshAllCompleted();
    void requestError(QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void loadFeeds();
    void setLoading(bool loading);
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
