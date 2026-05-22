/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "PerformanceViewModel.hpp"

#include <algorithm>

#include <QJsonObject>
#include <QJsonValue>
#include <QPointer>
#include <QSharedPointer>
#include <QVariantMap>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {
namespace {

constexpr QLatin1String kPowerPlanKey{"Home/Performance/PowerPlan"};
constexpr QLatin1String kReduceCpuKey{"Home/Gaming/ReduceCPU"};
constexpr QLatin1String kPostponeScansKey{"Home/Gaming/PostponeScans"};
constexpr QLatin1String kPostponeUpdatesKey{"Home/Gaming/PostponeUpdates"};
constexpr QLatin1String kScheduledScanEnabledKey{"Home/Scan/ScheduledScan"};
constexpr QLatin1String kScheduledScanDayKey{"Home/Scan/ScheduledDay"};
constexpr QLatin1String kScheduledScanHourKey{"Home/Scan/ScheduledHour"};

[[nodiscard]] bool BoolValue(const QJsonObject& values, QLatin1String key, bool fallback) noexcept
{
    const QJsonValue value = values.value(key);
    return value.isBool() ? value.toBool(fallback) : fallback;
}

[[nodiscard]] int IntValue(const QJsonObject& values, QLatin1String key, int fallback) noexcept
{
    const QJsonValue value = values.value(key);
    return value.isDouble() ? value.toInt(fallback) : fallback;
}

[[nodiscard]] QString DayName(int day)
{
    switch (day) {
    case 0: return QStringLiteral("Daily");
    case 1: return QStringLiteral("Monday");
    case 2: return QStringLiteral("Tuesday");
    case 3: return QStringLiteral("Wednesday");
    case 4: return QStringLiteral("Thursday");
    case 5: return QStringLiteral("Friday");
    case 6: return QStringLiteral("Saturday");
    case 7: return QStringLiteral("Sunday");
    default: return QStringLiteral("Scheduled");
    }
}

[[nodiscard]] QVariantMap Metric(QString label, int pct, QString state)
{
    QVariantMap row;
    row.insert(QStringLiteral("label"), std::move(label));
    row.insert(QStringLiteral("pct"), pct);
    row.insert(QStringLiteral("state"), std::move(state));
    return row;
}

[[nodiscard]] QVariantMap Optimization(QString text, QString time)
{
    QVariantMap row;
    row.insert(QStringLiteral("text"), std::move(text));
    row.insert(QStringLiteral("time"), std::move(time));
    row.insert(QStringLiteral("ok"), true);
    return row;
}

[[nodiscard]] QVariantMap Scheduled(QString name, QString scheduled)
{
    QVariantMap row;
    row.insert(QStringLiteral("name"), std::move(name));
    row.insert(QStringLiteral("scheduled"), std::move(scheduled));
    return row;
}

[[nodiscard]] int PowerPlanFromConfig(const QJsonObject& values) noexcept
{
    const int explicitPlan = IntValue(values, kPowerPlanKey, -1);
    if (explicitPlan >= 0 && explicitPlan <= 2) {
        return explicitPlan;
    }

    const bool reduceCpu = BoolValue(values, kReduceCpuKey, true);
    const bool postponeScans = BoolValue(values, kPostponeScansKey, true);
    const bool postponeUpdates = BoolValue(values, kPostponeUpdatesKey, true);
    if (!reduceCpu && !postponeScans && !postponeUpdates) {
        return 2;
    }
    return 1;
}

} // namespace

struct PerformanceViewModel::Impl {
    int currentPowerPlan{1};
    int scheduledScanHour{23};
    QVariantList impactMetrics;
    QVariantList recentOptimizations;
    QVariantList upcomingScansModel;
    bool loading{false};
};

PerformanceViewModel::PerformanceViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
    refresh();
}

PerformanceViewModel::~PerformanceViewModel() = default;

int PerformanceViewModel::currentPowerPlan() const noexcept { return m_impl->currentPowerPlan; }
QVariantList PerformanceViewModel::impactMetrics() const { return m_impl->impactMetrics; }
QVariantList PerformanceViewModel::recentOptimizations() const { return m_impl->recentOptimizations; }
QVariantList PerformanceViewModel::upcomingScansModel() const { return m_impl->upcomingScansModel; }
bool PerformanceViewModel::isLoading() const noexcept { return m_impl->loading; }

void PerformanceViewModel::setLoading(bool loading)
{
    if (m_impl->loading == loading) {
        return;
    }
    m_impl->loading = loading;
    emit loadingChanged();
}

void PerformanceViewModel::applyConfigPayload(const QJsonObject& payload)
{
    const QJsonObject values = payload.value(QLatin1String("values")).toObject();
    const int plan = PowerPlanFromConfig(values);
    const bool reduceCpu = BoolValue(values, kReduceCpuKey, true);
    const bool postponeScans = BoolValue(values, kPostponeScansKey, true);
    const bool postponeUpdates = BoolValue(values, kPostponeUpdatesKey, true);
    const bool scheduledEnabled = BoolValue(values, kScheduledScanEnabledKey, true);
    const int scheduledDay = IntValue(values, kScheduledScanDayKey, 0);
    const int scheduledHour = std::clamp(IntValue(values, kScheduledScanHourKey, 23), 0, 23);

    if (m_impl->currentPowerPlan != plan) {
        m_impl->currentPowerPlan = plan;
        emit currentPowerPlanChanged();
    }
    m_impl->scheduledScanHour = scheduledHour;

    QVariantList metrics;
    switch (plan) {
    case 0:
        metrics.append(Metric(QStringLiteral("TPM"), 1, QStringLiteral("on")));
        metrics.append(Metric(QStringLiteral("CPU"), 2, QStringLiteral("on")));
        metrics.append(Metric(QStringLiteral("Memory"), 32, QStringLiteral("on")));
        break;
    case 2:
        metrics.append(Metric(QStringLiteral("TPM"), 3, QStringLiteral("on")));
        metrics.append(Metric(QStringLiteral("CPU"), 8, QStringLiteral("on")));
        metrics.append(Metric(QStringLiteral("Memory"), 42, QStringLiteral("warning")));
        break;
    default:
        metrics.append(Metric(QStringLiteral("TPM"), 2, QStringLiteral("on")));
        metrics.append(Metric(QStringLiteral("CPU"), 4, QStringLiteral("on")));
        metrics.append(Metric(QStringLiteral("Memory"), 38, QStringLiteral("warning")));
        break;
    }
    m_impl->impactMetrics = std::move(metrics);
    emit metricsChanged();

    QVariantList optimizations;
    if (reduceCpu) {
        optimizations.append(Optimization(QStringLiteral("Background scanner CPU throttling enabled"),
                                          QStringLiteral("configured")));
    }
    if (postponeScans) {
        optimizations.append(Optimization(QStringLiteral("Scheduled scans defer during active use"),
                                          QStringLiteral("configured")));
    }
    if (postponeUpdates) {
        optimizations.append(Optimization(QStringLiteral("Definition updates avoid gaming sessions"),
                                          QStringLiteral("configured")));
    }
    if (optimizations.isEmpty()) {
        optimizations.append(Optimization(QStringLiteral("Full performance scanning profile active"),
                                          QStringLiteral("configured")));
    }
    m_impl->recentOptimizations = std::move(optimizations);
    emit optimizationsChanged();

    QVariantList scans;
    if (scheduledEnabled) {
        scans.append(Scheduled(QStringLiteral("Full system scan"),
                               QStringLiteral("%1, %2:00")
                                   .arg(DayName(scheduledDay))
                                   .arg(scheduledHour, 2, 10, QLatin1Char('0'))));
    }
    scans.append(Scheduled(QStringLiteral("Definitions update"),
                           postponeUpdates ? QStringLiteral("Deferred during gameplay")
                                           : QStringLiteral("Automatic")));
    m_impl->upcomingScansModel = std::move(scans);
    emit scheduledScansChanged();
}

void PerformanceViewModel::refresh()
{
    setLoading(true);
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::GetConfig,
        QJsonObject{{QLatin1String("prefix"), QStringLiteral("Home/")}},
        [self = QPointer<PerformanceViewModel>(this)](const Response& r) {
            if (!self) return;
            self->setLoading(false);
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->applyConfigPayload(r.payload);
        });
}

void PerformanceViewModel::setPowerPlan(int mode)
{
    if (mode < 0 || mode > 2) {
        emit requestError(QStringLiteral("invalid_power_plan"),
                          QStringLiteral("Power plan must be Quiet(0), Balanced(1), or Performance(2)"));
        return;
    }

    const bool reduceCpu = mode != 2;
    const bool postponeScans = mode != 2;
    const bool postponeUpdates = mode == 0;

    struct PendingUpdate {
        int remaining{4};
        bool failed{false};
        int mode{1};
    };

    auto pending = QSharedPointer<PendingUpdate>::create();
    pending->mode = mode;

    const auto onDone = [self = QPointer<PerformanceViewModel>(this), pending](const Response& r) {
        if (!self) return;
        if (!r.ok && !pending->failed) {
            pending->failed = true;
            emit self->requestError(r.errorCode, r.errorMessage);
        }
        --pending->remaining;
        if (pending->remaining != 0) {
            return;
        }
        if (pending->failed) {
            self->refresh();
            return;
        }
        if (self->m_impl->currentPowerPlan != pending->mode) {
            self->m_impl->currentPowerPlan = pending->mode;
            emit self->currentPowerPlanChanged();
        }
        self->refresh();
    };

    auto& pipe = PipeClient::Instance();
    (void)pipe.SendAndExpect(CommandType::UpdateConfig,
        QJsonObject{{QLatin1String("key"), QString(kPowerPlanKey)},
                    {QLatin1String("value"), mode}}, onDone);
    (void)pipe.SendAndExpect(CommandType::UpdateConfig,
        QJsonObject{{QLatin1String("key"), QString(kReduceCpuKey)},
                    {QLatin1String("value"), reduceCpu}}, onDone);
    (void)pipe.SendAndExpect(CommandType::UpdateConfig,
        QJsonObject{{QLatin1String("key"), QString(kPostponeScansKey)},
                    {QLatin1String("value"), postponeScans}}, onDone);
    (void)pipe.SendAndExpect(CommandType::UpdateConfig,
        QJsonObject{{QLatin1String("key"), QString(kPostponeUpdatesKey)},
                    {QLatin1String("value"), postponeUpdates}}, onDone);
}

void PerformanceViewModel::rescheduleScan(const QString& scanName)
{
    Q_UNUSED(scanName);

    const int nextHour = (m_impl->scheduledScanHour + 1) % 24;
    struct PendingUpdate {
        int remaining{2};
        bool failed{false};
    };
    auto pending = QSharedPointer<PendingUpdate>::create();
    const auto onDone = [self = QPointer<PerformanceViewModel>(this), pending](const Response& r) {
        if (!self) return;
        if (!r.ok && !pending->failed) {
            pending->failed = true;
            emit self->requestError(r.errorCode, r.errorMessage);
        }
        --pending->remaining;
        if (pending->remaining == 0) {
            self->refresh();
        }
    };

    auto& pipe = PipeClient::Instance();
    (void)pipe.SendAndExpect(CommandType::UpdateConfig,
        QJsonObject{{QLatin1String("key"), QString(kScheduledScanEnabledKey)},
                    {QLatin1String("value"), true}}, onDone);
    (void)pipe.SendAndExpect(CommandType::UpdateConfig,
        QJsonObject{{QLatin1String("key"), QString(kScheduledScanHourKey)},
                    {QLatin1String("value"), nextHour}}, onDone);
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
