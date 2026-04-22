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
 * @file ProtectionViewModel.hpp
 * @brief QObject ViewModel bridging the QML Protection page to the
 *        ShadowStrike service IPC layer.
 *
 * Exposes:
 *   - globalMode        — ProtectionMode as int (0=Off, 1=Balanced, 2=Aggressive)
 *   - protectionPaused  — true while the protection engine is temporarily paused
 *   - headlineState     — "healthy" | "atRisk" | "critical"
 *   - criticalCount     — number of modules in critical state
 *   - atRiskCount       — number of modules at risk
 *   - modules           — ModulesListModel* (CONSTANT; owned by this VM)
 *
 * Push events: ProtectionStateChanged (102), HeadlineStateChanged (104).
 * IPC commands: GetStatus (10), GetDashboard (250), UpdateConfig (30),
 *               PauseProtection (210), ResumeProtection (211).
 */
#pragma once

#include <QJsonObject>
#include <QObject>
#include <QString>
#include <memory>

#include "ModulesListModel.hpp"

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class ProtectionViewModel final : public QObject {
    Q_OBJECT

    Q_PROPERTY(int     globalMode       READ globalMode    NOTIFY globalModeChanged)
    Q_PROPERTY(bool    protectionPaused READ isPaused      NOTIFY pausedChanged)
    Q_PROPERTY(QString headlineState    READ headlineState NOTIFY headlineChanged)
    Q_PROPERTY(int     criticalCount    READ criticalCount NOTIFY headlineChanged)
    Q_PROPERTY(int     atRiskCount      READ atRiskCount   NOTIFY headlineChanged)
    Q_PROPERTY(ShadowStrike::PhantomHome::UI::ViewModels::ModulesListModel* modules
               READ modules CONSTANT)

public:
    explicit ProtectionViewModel(QObject* parent = nullptr);
    ~ProtectionViewModel() override;

    [[nodiscard]] int              globalMode()    const noexcept;
    [[nodiscard]] bool             isPaused()      const noexcept;
    [[nodiscard]] QString          headlineState() const noexcept;
    [[nodiscard]] int              criticalCount() const noexcept;
    [[nodiscard]] int              atRiskCount()   const noexcept;
    [[nodiscard]] ModulesListModel* modules()      const noexcept;

    /**
     * @brief Request a global protection mode change.
     *
     * Sends UpdateConfig (30) with {key:"globalMode", value:<mode>}.
     * Property update is deferred until the service confirms; on failure
     * requestError is emitted and the property is not changed.
     */
    Q_INVOKABLE void setGlobalMode(int mode);

    /**
     * @brief Temporarily pause real-time protection.
     *
     * Sends PauseProtection (210) with {minutes:<minutes>}.
     * @param minutes  0 = pause indefinitely; >0 = auto-resume after N minutes.
     */
    Q_INVOKABLE void pauseProtection(int minutes);

    /** Sends ResumeProtection (211). */
    Q_INVOKABLE void resumeProtection();

    /** Re-fetches GetStatus (10) and GetDashboard (250) from the service. */
    Q_INVOKABLE void refresh();

signals:
    void globalModeChanged();
    void pausedChanged();
    void headlineChanged();
    void requestError(QString code, QString message);

private:
    // Called from member-function context (lambdas + push handlers).
    void applyProtectionStateUpdate(const QJsonObject& payload) noexcept;
    void applyHeadlineStateUpdate(const QJsonObject& payload) noexcept;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
