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

#include <QObject>
#include <QJsonObject>
#include <QVariantList>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class PrivacyViewModel final : public QObject {
    Q_OBJECT

    Q_PROPERTY(int webcamAccessBlocked READ webcamAccessBlocked NOTIFY dashboardChanged)
    Q_PROPERTY(int micAccessBlocked READ micAccessBlocked NOTIFY dashboardChanged)
    Q_PROPERTY(int locationAccessBlocked READ locationAccessBlocked NOTIFY dashboardChanged)
    Q_PROPERTY(int cookiesBlocked READ cookiesBlocked NOTIFY dashboardChanged)
    Q_PROPERTY(QVariantList recentPrivacyEvents READ recentPrivacyEvents NOTIFY dashboardChanged)
    Q_PROPERTY(QVariantList modules READ modules NOTIFY modulesChanged)
    Q_PROPERTY(bool loading READ isLoading NOTIFY loadingChanged)

public:
    explicit PrivacyViewModel(QObject* parent = nullptr);
    ~PrivacyViewModel() override;

    [[nodiscard]] int webcamAccessBlocked() const noexcept;
    [[nodiscard]] int micAccessBlocked() const noexcept;
    [[nodiscard]] int locationAccessBlocked() const noexcept;
    [[nodiscard]] int cookiesBlocked() const noexcept;
    [[nodiscard]] QVariantList recentPrivacyEvents() const;
    [[nodiscard]] QVariantList modules() const;
    [[nodiscard]] bool isLoading() const noexcept;

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void setModuleEnabled(const QString& moduleId, bool enabled);
    Q_INVOKABLE void setModuleMode(const QString& moduleId, int mode);
    Q_INVOKABLE void runPrivacyCleanup();
    Q_INVOKABLE void auditPermissions();
    Q_INVOKABLE void openBrowserPrivacy();

signals:
    void dashboardChanged();
    void modulesChanged();
    void loadingChanged();
    void requestError(QString code, QString message);
    void privacyActionCompleted(QString action);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void setLoading(bool loading);
    void applyConfigPayload(const QJsonObject& payload);
    void applyModulesPayload(const QJsonObject& payload);
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
