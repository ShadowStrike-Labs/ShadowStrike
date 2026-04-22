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

#include "ProtectionViewModel.hpp"

#include <QJsonObject>
#include <QPointer>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

namespace ShadowStrike::PhantomHome::UI::ViewModels {

// ── PIMPL ───────────────────────────────────────────────────────────────────

struct ProtectionViewModel::Impl {
    int     globalMode{0};
    bool    paused{false};
    QString headlineState{QStringLiteral("healthy")};
    int     criticalCount{0};
    int     atRiskCount{0};

    // ModulesListModel has no Qt parent — owned via unique_ptr, lifetime
    // is strictly tied to ProtectionViewModel.
    std::unique_ptr<ModulesListModel> modules;

    std::uint64_t subProtState{0};
    std::uint64_t subHeadline{0};
};

// ── Private member helpers ───────────────────────────────────────────────────

void ProtectionViewModel::applyProtectionStateUpdate(const QJsonObject& payload) noexcept
{
    const int  newMode   = payload.value(QLatin1String("globalMode")).toInt(m_impl->globalMode);
    const bool newPaused = payload.value(QLatin1String("paused")).toBool(m_impl->paused);

    const bool modeChanged   = (newMode   != m_impl->globalMode);
    const bool pausedChanged = (newPaused != m_impl->paused);

    m_impl->globalMode = newMode;
    m_impl->paused     = newPaused;

    if (modeChanged)   emit globalModeChanged();
    if (pausedChanged) emit pausedChanged();
}

void ProtectionViewModel::applyHeadlineStateUpdate(const QJsonObject& payload) noexcept
{
    m_impl->headlineState = payload.value(QLatin1String("headlineState")).toString(m_impl->headlineState);
    m_impl->criticalCount = payload.value(QLatin1String("criticalCount")).toInt(m_impl->criticalCount);
    m_impl->atRiskCount   = payload.value(QLatin1String("atRiskCount")).toInt(m_impl->atRiskCount);
    emit headlineChanged();
}

// ── ProtectionViewModel ──────────────────────────────────────────────────────

ProtectionViewModel::ProtectionViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
    m_impl->modules = std::make_unique<ModulesListModel>();

    auto& pipe = PipeClient::Instance();

    // Push: ProtectionStateChanged (102)
    m_impl->subProtState = pipe.Subscribe(
        CommandType::ProtectionStateChanged,
        [self = QPointer<ProtectionViewModel>(this)](const QJsonObject& ev) {
            if (!self) return;
            self->applyProtectionStateUpdate(ev);
        });

    // Push: HeadlineStateChanged (104)
    m_impl->subHeadline = pipe.Subscribe(
        CommandType::HeadlineStateChanged,
        [self = QPointer<ProtectionViewModel>(this)](const QJsonObject& ev) {
            if (!self) return;
            self->applyHeadlineStateUpdate(ev);
        });

    refresh();
}

ProtectionViewModel::~ProtectionViewModel()
{
    auto& pipe = PipeClient::Instance();
    if (m_impl->subProtState) pipe.Unsubscribe(m_impl->subProtState);
    if (m_impl->subHeadline)  pipe.Unsubscribe(m_impl->subHeadline);
}

int              ProtectionViewModel::globalMode()    const noexcept { return m_impl->globalMode; }
bool             ProtectionViewModel::isPaused()      const noexcept { return m_impl->paused; }
QString          ProtectionViewModel::headlineState() const noexcept { return m_impl->headlineState; }
int              ProtectionViewModel::criticalCount() const noexcept { return m_impl->criticalCount; }
int              ProtectionViewModel::atRiskCount()   const noexcept { return m_impl->atRiskCount; }
ModulesListModel* ProtectionViewModel::modules()     const noexcept { return m_impl->modules.get(); }

void ProtectionViewModel::setGlobalMode(int mode)
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::UpdateConfig,
        QJsonObject{
            {QLatin1String("key"),   QLatin1String("globalMode")},
            {QLatin1String("value"), mode}},
        [self = QPointer<ProtectionViewModel>(this), mode](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            if (self->m_impl->globalMode != mode) {
                self->m_impl->globalMode = mode;
                emit self->globalModeChanged();
            }
        });
}

void ProtectionViewModel::pauseProtection(int minutes)
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::PauseProtection,
        QJsonObject{{QLatin1String("minutes"), minutes}},
        [self = QPointer<ProtectionViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            if (!self->m_impl->paused) {
                self->m_impl->paused = true;
                emit self->pausedChanged();
            }
        });
}

void ProtectionViewModel::resumeProtection()
{
    (void)PipeClient::Instance().SendAndExpect(
        CommandType::ResumeProtection,
        {},
        [self = QPointer<ProtectionViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            if (self->m_impl->paused) {
                self->m_impl->paused = false;
                emit self->pausedChanged();
            }
        });
}

void ProtectionViewModel::refresh()
{
    auto& pipe = PipeClient::Instance();

    // GetStatus (10) — carries globalMode + paused flag.
    (void)pipe.SendAndExpect(
        CommandType::GetStatus,
        {},
        [self = QPointer<ProtectionViewModel>(this)](const Response& r) {
            if (!self || !r.ok) return;
            self->applyProtectionStateUpdate(r.payload);
        });

    // GetDashboard (250) — carries headlineState, criticalCount, atRiskCount.
    (void)pipe.SendAndExpect(
        CommandType::GetDashboard,
        {},
        [self = QPointer<ProtectionViewModel>(this)](const Response& r) {
            if (!self || !r.ok) return;
            self->applyHeadlineStateUpdate(r.payload);
        });
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
