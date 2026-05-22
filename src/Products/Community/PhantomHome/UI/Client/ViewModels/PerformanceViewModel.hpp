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

class PerformanceViewModel final : public QObject {
    Q_OBJECT

    Q_PROPERTY(int currentPowerPlan READ currentPowerPlan NOTIFY currentPowerPlanChanged)
    Q_PROPERTY(QVariantList impactMetrics READ impactMetrics NOTIFY metricsChanged)
    Q_PROPERTY(QVariantList recentOptimizations READ recentOptimizations NOTIFY optimizationsChanged)
    Q_PROPERTY(QVariantList upcomingScansModel READ upcomingScansModel NOTIFY scheduledScansChanged)
    Q_PROPERTY(bool loading READ isLoading NOTIFY loadingChanged)

public:
    explicit PerformanceViewModel(QObject* parent = nullptr);
    ~PerformanceViewModel() override;

    [[nodiscard]] int currentPowerPlan() const noexcept;
    [[nodiscard]] QVariantList impactMetrics() const;
    [[nodiscard]] QVariantList recentOptimizations() const;
    [[nodiscard]] QVariantList upcomingScansModel() const;
    [[nodiscard]] bool isLoading() const noexcept;

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void setPowerPlan(int mode);
    Q_INVOKABLE void rescheduleScan(const QString& scanName);

signals:
    void currentPowerPlanChanged();
    void metricsChanged();
    void optimizationsChanged();
    void scheduledScansChanged();
    void loadingChanged();
    void requestError(QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void setLoading(bool loading);
    void applyConfigPayload(const QJsonObject& payload);
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
