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

#include "ScanViewModel.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QPointer>
#include <QTimer>

#include "../IPC/PipeClient.hpp"

using namespace ShadowStrike::PhantomHome::UI::IPC;
using ShadowStrike::Service::CommandType;

// v2 wire codes that are NOT named enum members (see ServiceCommunicator.hpp comment).
static constexpr auto kStartScanV2 = static_cast<CommandType>(220);
static constexpr auto kStopScanV2  = static_cast<CommandType>(221);

namespace ShadowStrike::PhantomHome::UI::ViewModels {

// ── Poll intervals ───────────────────────────────────────────────────────────
static constexpr int kPollIntervalRunningMs = 500;
static constexpr int kPollIntervalPausedMs  = 5000;

// ── PIMPL ────────────────────────────────────────────────────────────────────

struct ScanViewModel::Impl {
    int     state{ScanState::Idle};
    int     percent{0};
    quint64 itemsScanned{0};
    quint64 threatsFound{0};
    QString currentPath;
    quint64 scanId{0};

    // QTimer owned by unique_ptr; no Qt parent required because ScanViewModel's
    // destructor will reset m_impl, dropping the timer safely.
    std::unique_ptr<QTimer> pollTimer;

    std::uint64_t subScanProgress{0};

    void startPollTimer(int intervalMs)
    {
        if (!pollTimer) return;
        pollTimer->setInterval(intervalMs);
        if (!pollTimer->isActive())
            pollTimer->start();
        else
            pollTimer->setInterval(intervalMs); // adjust while running
    }

    void stopPollTimer()
    {
        if (pollTimer) pollTimer->stop();
    }
};

// ── ScanViewModel ─────────────────────────────────────────────────────────────

ScanViewModel::ScanViewModel(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>())
{
    m_impl->pollTimer = std::make_unique<QTimer>();
    m_impl->pollTimer->setSingleShot(false);
    QObject::connect(m_impl->pollTimer.get(), &QTimer::timeout,
                     this, &ScanViewModel::pollProgress);

    // Subscribe to ScanProgressEvent push (103) for real-time updates.
    m_impl->subScanProgress = PipeClient::Instance().Subscribe(
        CommandType::ScanProgressEvent,
        [self = QPointer<ScanViewModel>(this)](const QJsonObject& ev) {
            if (!self) return;
            self->applyProgressUpdate(ev);
        });
}

ScanViewModel::~ScanViewModel()
{
    if (m_impl->subScanProgress)
        PipeClient::Instance().Unsubscribe(m_impl->subScanProgress);
    m_impl->stopPollTimer();
}

int     ScanViewModel::state()        const noexcept { return m_impl->state; }
int     ScanViewModel::percent()      const noexcept { return m_impl->percent; }
quint64 ScanViewModel::itemsScanned() const noexcept { return m_impl->itemsScanned; }
quint64 ScanViewModel::threatsFound() const noexcept { return m_impl->threatsFound; }
QString ScanViewModel::currentPath()  const noexcept { return m_impl->currentPath; }
quint64 ScanViewModel::scanId()       const noexcept { return m_impl->scanId; }

// ── Private helpers ──────────────────────────────────────────────────────────

void ScanViewModel::applyProgressUpdate(const QJsonObject& ev)
{
    const int prevState = m_impl->state;

    // Parse state string if present
    const QString stateStr = ev.value(QLatin1String("state")).toString();
    if (!stateStr.isEmpty()) {
        if      (stateStr == QLatin1String("idle"))      m_impl->state = Idle;
        else if (stateStr == QLatin1String("preparing")) m_impl->state = Preparing;
        else if (stateStr == QLatin1String("running"))   m_impl->state = Running;
        else if (stateStr == QLatin1String("paused"))    m_impl->state = Paused;
        else if (stateStr == QLatin1String("completed")) m_impl->state = Completed;
        else if (stateStr == QLatin1String("failed"))    m_impl->state = Failed;
    }
    // Also accept numeric state for backwards compat
    if (ev.contains(QLatin1String("stateCode")))
        m_impl->state = ev.value(QLatin1String("stateCode")).toInt(m_impl->state);

    m_impl->percent      = ev.value(QLatin1String("percent")).toInt(m_impl->percent);
    m_impl->itemsScanned = static_cast<quint64>(
        ev.value(QLatin1String("itemsScanned")).toDouble(static_cast<double>(m_impl->itemsScanned)));
    m_impl->threatsFound = static_cast<quint64>(
        ev.value(QLatin1String("threatsFound")).toDouble(static_cast<double>(m_impl->threatsFound)));
    m_impl->currentPath  = ev.value(QLatin1String("currentPath")).toString(m_impl->currentPath);
    m_impl->scanId       = static_cast<quint64>(
        ev.value(QLatin1String("scanId")).toDouble(static_cast<double>(m_impl->scanId)));

    emit progressChanged();

    if (m_impl->state != prevState) {
        emit stateChanged();

        switch (m_impl->state) {
        case Running:
            m_impl->startPollTimer(kPollIntervalRunningMs);
            break;
        case Paused:
            m_impl->startPollTimer(kPollIntervalPausedMs);
            break;
        case Completed:
            m_impl->stopPollTimer();
            emit scanCompleted(m_impl->scanId, m_impl->threatsFound);
            break;
        case Failed:
            [[fallthrough]];
        case Idle:
            m_impl->stopPollTimer();
            break;
        default:
            break;
        }
    }
}

void ScanViewModel::pollProgress()
{
    // Only poll when a scan is actually active.
    if (m_impl->state != Running && m_impl->state != Paused) {
        m_impl->stopPollTimer();
        return;
    }

    (void)PipeClient::Instance().SendAndExpect(
        CommandType::GetScanProgress,
        QJsonObject{{QLatin1String("scanId"), static_cast<qint64>(m_impl->scanId)}},
        [self = QPointer<ScanViewModel>(this)](const Response& r) {
            if (!self || !r.ok) return;
            self->applyProgressUpdate(r.payload);
        },
        std::chrono::milliseconds{3000});
}

void ScanViewModel::doStartScan(const QJsonObject& payload)
{
    if (m_impl->state == Running || m_impl->state == Preparing) return;

    m_impl->state        = Preparing;
    m_impl->percent      = 0;
    m_impl->itemsScanned = 0;
    m_impl->threatsFound = 0;
    m_impl->currentPath.clear();
    emit stateChanged();
    emit progressChanged();

    (void)PipeClient::Instance().SendAndExpect(
        kStartScanV2,
        payload,
        [self = QPointer<ScanViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                self->m_impl->state = Failed;
                emit self->stateChanged();
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->m_impl->scanId = static_cast<quint64>(
                r.payload.value(QLatin1String("scanId")).toDouble(0.0));
            self->m_impl->state = Running;
            emit self->stateChanged();
            self->m_impl->startPollTimer(kPollIntervalRunningMs);
        });
}

// ── Public invokables ────────────────────────────────────────────────────────

void ScanViewModel::startFastScan()
{
    doStartScan(QJsonObject{{QLatin1String("type"), QLatin1String("fast")}});
}

void ScanViewModel::startFullScan()
{
    doStartScan(QJsonObject{{QLatin1String("type"), QLatin1String("full")}});
}

void ScanViewModel::startCustomScan(const QStringList& paths)
{
    QJsonArray arr;
    for (const QString& p : paths)
        arr.append(p);
    doStartScan(QJsonObject{
        {QLatin1String("type"),  QLatin1String("custom")},
        {QLatin1String("paths"), arr}});
}

void ScanViewModel::pause()
{
    if (m_impl->state != Running) return;

    // No dedicated PauseScan wire command in v2 protocol.
    // Update local state and reduce poll frequency to 5 s so the UI
    // reflects "paused" immediately.  The service will continue running;
    // the true pause behaviour requires a future protocol extension.
    m_impl->state = Paused;
    m_impl->startPollTimer(kPollIntervalPausedMs);
    emit stateChanged();
}

void ScanViewModel::resume()
{
    if (m_impl->state != Paused) return;

    m_impl->state = Running;
    m_impl->startPollTimer(kPollIntervalRunningMs);
    emit stateChanged();
}

void ScanViewModel::cancel()
{
    if (m_impl->state == Idle
        || m_impl->state == Completed
        || m_impl->state == Failed)
        return;

    (void)PipeClient::Instance().SendAndExpect(
        kStopScanV2,
        QJsonObject{{QLatin1String("scanId"), static_cast<qint64>(m_impl->scanId)}},
        [self = QPointer<ScanViewModel>(this)](const Response& r) {
            if (!self) return;
            if (!r.ok) {
                emit self->requestError(r.errorCode, r.errorMessage);
                return;
            }
            self->m_impl->state = Idle;
            self->m_impl->stopPollTimer();
            emit self->stateChanged();
        });
}

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
