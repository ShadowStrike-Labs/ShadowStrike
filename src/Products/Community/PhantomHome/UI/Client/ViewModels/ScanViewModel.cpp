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
#include <QJsonValue>
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
    QString scanId;

    // Seeded from the request payload at doStartScan so the surface is
    // correct from the first frame, then confirmed by every poll reply.
    QString scope{QStringLiteral("fast")};
    QString targetSummary;

    quint64 totalFiles{0};
    quint64 bytesScanned{0};
    quint64 elapsedMs{0};
    quint64 estimatedRemainingMs{0};
    quint64 filesPerSecond{0};
    quint64 bytesPerSecond{0};

    // QTimer owned by unique_ptr; no Qt parent required because ScanViewModel's
    // destructor will reset m_impl, dropping the timer safely.
    std::unique_ptr<QTimer> pollTimer;

    std::uint64_t subScanProgress{0};

    /// Targets requested while a scan was already active.  Drained when the
    /// active scan reaches Completed or Failed; cleared by an explicit cancel.
    QStringList pendingPaths;

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
QString ScanViewModel::scanId()       const noexcept { return m_impl->scanId; }

QString ScanViewModel::scope()         const noexcept { return m_impl->scope; }
QString ScanViewModel::targetSummary() const noexcept { return m_impl->targetSummary; }
quint64 ScanViewModel::totalFiles()    const noexcept { return m_impl->totalFiles; }
quint64 ScanViewModel::bytesScanned()  const noexcept { return m_impl->bytesScanned; }
quint64 ScanViewModel::elapsedMs()     const noexcept { return m_impl->elapsedMs; }
quint64 ScanViewModel::filesPerSecond() const noexcept { return m_impl->filesPerSecond; }
quint64 ScanViewModel::bytesPerSecond() const noexcept { return m_impl->bytesPerSecond; }

quint64 ScanViewModel::estimatedRemainingMs() const noexcept
{
    return m_impl->estimatedRemainingMs;
}

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

    // EACH FIELD KEEPS ITS PREVIOUS VALUE WHEN ABSENT, matching the fields
    // above. A progress event and a poll reply do not carry the same key
    // set - the broadcast event is deliberately small - so defaulting an
    // absent key to zero would make every value flicker between the real
    // figure and nothing as the two sources interleaved.
    m_impl->scope = ev.value(QLatin1String("scope")).toString(m_impl->scope);

    // targetCount is authoritative even though the list is capped, so the
    // summary is built from the count and only NAMES a target when exactly
    // one was requested. Saying "3 items" is honest; naming one of three
    // as though it were the whole selection is not.
    if (ev.contains(QLatin1String("targetCount"))) {
        const auto count = static_cast<quint64>(
            ev.value(QLatin1String("targetCount")).toDouble(0.0));
        const QJsonArray targets =
            ev.value(QLatin1String("targets")).toArray();
        if (count == 1 && targets.size() == 1) {
            m_impl->targetSummary = targets.at(0).toString();
        } else if (count > 1) {
            m_impl->targetSummary = tr("%1 items").arg(count);
        } else {
            m_impl->targetSummary.clear();
        }
    }

    const auto readCounter = [&ev](const char* key, quint64 previous) -> quint64 {
        return static_cast<quint64>(
            ev.value(QLatin1String(key)).toDouble(static_cast<double>(previous)));
    };
    m_impl->totalFiles           = readCounter("totalFiles", m_impl->totalFiles);
    m_impl->bytesScanned         = readCounter("bytesScanned", m_impl->bytesScanned);
    m_impl->elapsedMs            = readCounter("elapsedMs", m_impl->elapsedMs);
    m_impl->estimatedRemainingMs = readCounter("estimatedRemainingMs",
                                               m_impl->estimatedRemainingMs);
    m_impl->filesPerSecond       = readCounter("filesPerSecond",
                                               m_impl->filesPerSecond);
    m_impl->bytesPerSecond       = readCounter("bytesPerSecond",
                                               m_impl->bytesPerSecond);
    if (ev.contains(QLatin1String("scanId"))) {
        const QJsonValue idValue = ev.value(QLatin1String("scanId"));
        if (idValue.isString()) {
            m_impl->scanId = idValue.toString();
        } else if (idValue.isDouble()) {
            m_impl->scanId = QString::number(static_cast<qulonglong>(idValue.toDouble(0.0)));
        }
    }

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
            // Queued targets start on the NEXT event-loop turn, not here.
            // doStartScan rewrites the very state this switch is reacting to
            // and emits from it, so starting inline would re-enter this
            // transition while it is still in progress.
            QTimer::singleShot(0, this, &ScanViewModel::drainPendingCustomScan);
            break;
        case Failed:
            // A failed scan does not cancel a DIFFERENT request that arrived
            // while it was running, so the queue is drained here as well.
            m_impl->stopPollTimer();
            QTimer::singleShot(0, this, &ScanViewModel::drainPendingCustomScan);
            break;
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
        QJsonObject{{QLatin1String("scanId"), m_impl->scanId}},
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
    m_impl->scanId.clear();

    m_impl->totalFiles           = 0;
    m_impl->bytesScanned         = 0;
    m_impl->elapsedMs            = 0;
    m_impl->estimatedRemainingMs = 0;
    m_impl->filesPerSecond       = 0;
    m_impl->bytesPerSecond       = 0;

    // SEEDED FROM THE PAYLOAD BEING SENT, not from the caller that built it.
    // Reading the request means the label cannot disagree with the scope the
    // service is about to record, and it puts one derivation here instead of
    // one in each of the three entry points.
    //
    // This matters before the first reply arrives: the tile switches to its
    // running state as soon as StartScan is acknowledged, which is earlier
    // than the first progress poll, so without a seed it would show the
    // previous scan's label for one interval.
    m_impl->scope = payload.value(QLatin1String("scope"))
                        .toString(QStringLiteral("fast"));

    const QJsonArray requested = payload.value(QLatin1String("paths")).toArray();
    if (requested.size() == 1) {
        m_impl->targetSummary = requested.at(0).toString();
    } else if (requested.size() > 1) {
        m_impl->targetSummary = tr("%1 items").arg(requested.size());
    } else {
        m_impl->targetSummary.clear();
    }
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
            const QJsonValue idValue = r.payload.value(QLatin1String("scanId"));
            if (idValue.isString()) {
                self->m_impl->scanId = idValue.toString();
            } else if (idValue.isDouble()) {
                self->m_impl->scanId = QString::number(static_cast<qulonglong>(idValue.toDouble(0.0)));
            } else {
                self->m_impl->state = Failed;
                emit self->stateChanged();
                emit self->requestError(QStringLiteral("invalid_response"),
                                        QStringLiteral("StartScan response did not include scanId"));
                return;
            }
            self->m_impl->state = Running;
            emit self->stateChanged();
            self->m_impl->startPollTimer(kPollIntervalRunningMs);
        });
}

// ── Public invokables ────────────────────────────────────────────────────────

void ScanViewModel::startFastScan()
{
    doStartScan(QJsonObject{{QLatin1String("scope"), QLatin1String("fast")}});
}

void ScanViewModel::startFullScan()
{
    doStartScan(QJsonObject{{QLatin1String("scope"), QLatin1String("full")}});
}

void ScanViewModel::startCustomScan(const QStringList& paths)
{
    // Filter blanks HERE rather than at the wire.  The service rejects the
    // whole request when "paths" is empty, so one stray blank from a caller
    // would fail an entire selection instead of the single unusable item.
    QStringList targets;
    for (const QString& p : paths) {
        const QString trimmed = p.trimmed();
        if (!trimmed.isEmpty() && !targets.contains(trimmed))
            targets.append(trimmed);
    }
    if (targets.isEmpty())
        return;

    // A scan is already in flight.  QUEUE, never discard - see the header.
    if (m_impl->state == Running || m_impl->state == Preparing) {
        for (const QString& t : targets) {
            if (!m_impl->pendingPaths.contains(t))
                m_impl->pendingPaths.append(t);
        }
        return;
    }

    QJsonArray arr;
    for (const QString& p : targets)
        arr.append(p);
    doStartScan(QJsonObject{
        {QLatin1String("scope"), QLatin1String("custom")},
        {QLatin1String("paths"), arr}});
}

void ScanViewModel::drainPendingCustomScan()
{
    if (m_impl->pendingPaths.isEmpty())
        return;
    if (m_impl->state == Running || m_impl->state == Preparing)
        return;

    // Detach the list BEFORE starting.  startCustomScan re-enters this object
    // and, if the queue were still populated, would observe its own targets as
    // pending and append them a second time.
    QStringList next;
    next.swap(m_impl->pendingPaths);
    startCustomScan(next);
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

    // "Stop scanning" includes whatever is queued behind the active scan.
    // Draining after an explicit cancel would restart work the user just
    // asked to stop.
    m_impl->pendingPaths.clear();

    (void)PipeClient::Instance().SendAndExpect(
        kStopScanV2,
        QJsonObject{{QLatin1String("scanId"), m_impl->scanId}},
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
