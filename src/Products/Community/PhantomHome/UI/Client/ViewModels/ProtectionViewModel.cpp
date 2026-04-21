// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) ShadowStrike-Labs. All rights reserved.

#include "ProtectionViewModel.hpp"

#include <QDateTime>
#include <QLocale>
#include <QMetaObject>
#include <QPointer>
#include <QString>
#include <QTimer>

#include <format>

#include "../IPC/PipeClient.hpp"
#include "../../IPC/Messages.hpp"

namespace ShadowStrike::PhantomHome::UI::Client {

using ::ShadowStrike::PhantomHome::IPC::FrameEnvelope;
using ::ShadowStrike::PhantomHome::IPC::MessageType;
using ::ShadowStrike::PhantomHome::IPC::OverallState;
using ::ShadowStrike::PhantomHome::IPC::ProtectionStateReply;
using ::ShadowStrike::PhantomHome::IPC::GetModuleStatusReply;
using ::ShadowStrike::PhantomHome::IPC::ModuleStatusEntry;
using ::ShadowStrike::PhantomHome::IPC::ModuleState;
using ::ShadowStrike::PhantomHome::IPC::ScanStartRequest;
using ::ShadowStrike::PhantomHome::IPC::ScanType;

namespace {

QString OverallStateTag(OverallState s) {
    switch (s) {
    case OverallState::Green:  return QStringLiteral("green");
    case OverallState::Amber:  return QStringLiteral("amber");
    case OverallState::Red:    return QStringLiteral("red");
    case OverallState::Paused: return QStringLiteral("paused");
    case OverallState::Unknown:
    default:                   return QStringLiteral("amber");
    }
}

QString OverallStateCopy(OverallState s) {
    switch (s) {
    case OverallState::Green:  return QObject::tr("We are protecting you");
    case OverallState::Amber:  return QObject::tr("Attention needed");
    case OverallState::Red:    return QObject::tr("Your device is at risk");
    case OverallState::Paused: return QObject::tr("Protection is paused");
    case OverallState::Unknown:
    default:                   return QObject::tr("Connecting to the service");
    }
}

QString ModuleStateTag(ModuleState s) {
    switch (s) {
    case ModuleState::Running:      return QStringLiteral("running");
    case ModuleState::Initializing: return QStringLiteral("initializing");
    case ModuleState::Degraded:     return QStringLiteral("degraded");
    case ModuleState::Failed:       return QStringLiteral("failed");
    case ModuleState::Disabled:
    default:                        return QStringLiteral("disabled");
    }
}

QString FormatUnix(std::uint64_t unix) {
    if (unix == 0) return QStringLiteral("—");
    return QLocale().toString(
        QDateTime::fromSecsSinceEpoch(static_cast<qint64>(unix)),
        QLocale::ShortFormat);
}

} // namespace

ProtectionViewModel::ProtectionViewModel(std::shared_ptr<PipeClient> client,
                                         QObject* parent)
    : QObject(parent)
    , m_client(std::move(client)) {
    wireClient();

    // -----------------------------------------------------------------
    // First-fetch robustness:
    //
    //  (a) If PipeClient established its connection *before* QML finished
    //      constructing this view-model, the SetStateCallback edge has
    //      already fired and onConnectionChanged(true) will never be
    //      delivered. In that case the UI spins on "Loading protection
    //      modules…" forever. Ask immediately if we're already up.
    //
    //  (b) As a belt-and-braces guarantee against any future transport
    //      race (slow connect, reconnect in-flight at ctor time, etc.),
    //      arm a single-shot 1.5s timer that fires an unconditional
    //      refreshAll() on the GUI thread. refreshAll() is idempotent —
    //      two back-to-back calls just cause two replies, which
    //      modulesChanged() coalesces naturally.
    // -----------------------------------------------------------------
    if (m_client && m_client->IsConnected()) {
        QMetaObject::invokeMethod(this, "refreshAll", Qt::QueuedConnection);
    }
    QTimer::singleShot(1500, this, [self = QPointer<ProtectionViewModel>(this)]() {
        if (!self) return;
        self->refreshAll();
    });
}

ProtectionViewModel::~ProtectionViewModel() {
    if (m_client) {
        m_client->SetPushCallback(nullptr);
        m_client->SetStateCallback(nullptr);
    }
}

void ProtectionViewModel::wireClient() {
    if (!m_client) return;

    m_client->SetStateCallback([self = QPointer<ProtectionViewModel>(this)](bool connected) {
        if (!self) return;
        QMetaObject::invokeMethod(
            self.data(), "onConnectionChanged", Qt::QueuedConnection,
            Q_ARG(bool, connected));
    });

    m_client->SetPushCallback([self = QPointer<ProtectionViewModel>(this)](const FrameEnvelope& env) {
        if (!self) return;
        switch (env.type) {
        case MessageType::EventStateChanged: {
            auto parsed = ProtectionStateReply::FromJson(env.payload);
            if (!parsed) return;
            QMetaObject::invokeMethod(
                self.data(), "onStateReply", Qt::QueuedConnection,
                Q_ARG(QString, OverallStateTag(parsed->state)),
                Q_ARG(QString, QString::fromStdString(parsed->reason)),
                Q_ARG(int,     static_cast<int>(parsed->active_threats)),
                Q_ARG(qint64,  static_cast<qint64>(parsed->last_update_unix)),
                Q_ARG(bool,    parsed->sensor_ok),
                Q_ARG(QString, QString::fromStdString(parsed->sensor_reason)),
                Q_ARG(int,     static_cast<int>(parsed->cortex_active)),
                Q_ARG(int,     static_cast<int>(parsed->cortex_total)));
            break;
        }
        case MessageType::EventDetection: {
            QString title   = QStringLiteral("Threat detected");
            QString module  = QString::fromStdString(env.payload.value("m", ""));
            QString sev     = QString::fromStdString(env.payload.value("sv", ""));
            QMetaObject::invokeMethod(
                self.data(), "onDetectionPush", Qt::QueuedConnection,
                Q_ARG(QString, title),
                Q_ARG(QString, module),
                Q_ARG(QString, sev));
            break;
        }
        default:
            break;
        }
    });
}

void ProtectionViewModel::refreshAll() {
    if (!m_client) return;

    m_client->RequestAsync(MessageType::GetState, nlohmann::json::object(),
        [self = QPointer<ProtectionViewModel>(this)](std::optional<FrameEnvelope> reply) {
            if (!self) return;
            if (!reply) return;
            auto parsed = ProtectionStateReply::FromJson(reply->payload);
            if (!parsed) return;
            QMetaObject::invokeMethod(
                self.data(), "onStateReply", Qt::QueuedConnection,
                Q_ARG(QString, OverallStateTag(parsed->state)),
                Q_ARG(QString, QString::fromStdString(parsed->reason)),
                Q_ARG(int,     static_cast<int>(parsed->active_threats)),
                Q_ARG(qint64,  static_cast<qint64>(parsed->last_update_unix)),
                Q_ARG(bool,    parsed->sensor_ok),
                Q_ARG(QString, QString::fromStdString(parsed->sensor_reason)),
                Q_ARG(int,     static_cast<int>(parsed->cortex_active)),
                Q_ARG(int,     static_cast<int>(parsed->cortex_total)));
        });

    m_client->RequestAsync(MessageType::GetModuleStatus, nlohmann::json::object(),
        [self = QPointer<ProtectionViewModel>(this)](std::optional<FrameEnvelope> reply) {
            if (!self) return;
            if (!reply) return;
            auto parsed = GetModuleStatusReply::FromJson(reply->payload);
            if (!parsed) return;

            QVariantList vl;
            vl.reserve(static_cast<int>(parsed->modules.size()));
            for (const auto& m : parsed->modules) {
                QVariantMap r;
                r.insert(QStringLiteral("id"),          QString::fromStdString(m.id));
                r.insert(QStringLiteral("displayName"), QString::fromStdString(m.display_name));
                r.insert(QStringLiteral("state"),       ModuleStateTag(m.state));
                r.insert(QStringLiteral("enabled"),     m.enabled);
                r.insert(QStringLiteral("group"),       QString::fromStdString(m.group));
                vl.push_back(std::move(r));
            }
            QMetaObject::invokeMethod(self.data(), [self, list = std::move(vl)]() mutable {
                if (!self) return;
                self->m_modules = std::move(list);
                emit self->modulesChanged();
            }, Qt::QueuedConnection);
        });
}

void ProtectionViewModel::startFastScan() {
    if (!m_client) return;
    ScanStartRequest req;
    req.type = ScanType::Quick;
    m_client->RequestAsync(MessageType::ScanStart, req.ToJson(),
        [](std::optional<FrameEnvelope>) { /* progress arrives via push */ });
}

void ProtectionViewModel::setModuleEnabled(const QString& id, bool enabled) {
    if (!m_client) return;
    nlohmann::json payload = {
        {"id", id.toStdString()},
        {"e",  enabled},
    };
    m_client->RequestAsync(MessageType::SetModuleEnable, payload,
        [self = QPointer<ProtectionViewModel>(this)](std::optional<FrameEnvelope>) {
            if (!self) return;
            self->refreshAll();
        });
}

void ProtectionViewModel::onStateReply(QString state,
                                       QString reason,
                                       int activeThreats,
                                       qint64 lastUpdateUnix,
                                       bool sensorOk,
                                       QString sensorReason,
                                       int cortexActive,
                                       int cortexTotal) {
    m_protectionState  = std::move(state);
    const bool risky   = m_protectionState != QStringLiteral("green");
    m_stateCopy        = risky
        ? (m_protectionState == QStringLiteral("red")
              ? tr("Your device is at risk")
              : tr("Attention needed"))
        : tr("We are protecting you");
    m_stateSubCopy     = reason.isEmpty()
        ? (risky ? tr("Review the Security tab for details.")
                 : tr("Real-time protection is active."))
        : std::move(reason);
    m_threatsBlocked7d = activeThreats;
    m_lastScan         = FormatUnix(static_cast<std::uint64_t>(lastUpdateUnix));

    m_sensorOk     = sensorOk;
    m_sensorReason = std::move(sensorReason);
    m_cortexActive = cortexActive;
    m_cortexTotal  = cortexTotal;

    emit stateChanged();
}

void ProtectionViewModel::onDetectionPush(QString title,
                                          QString module,
                                          QString severity) {
    QVariantMap e;
    e.insert(QStringLiteral("title"),    title);
    e.insert(QStringLiteral("module"),   module);
    e.insert(QStringLiteral("severity"), severity);
    e.insert(QStringLiteral("timeUnix"),
             static_cast<qint64>(QDateTime::currentSecsSinceEpoch()));

    // Keep a bounded rolling window of 100 events.
    m_recentEvents.prepend(std::move(e));
    while (m_recentEvents.size() > 100) {
        m_recentEvents.removeLast();
    }
    emit eventsChanged();
}

void ProtectionViewModel::onConnectionChanged(bool connected) {
    if (!connected) {
        m_protectionState = QStringLiteral("amber");
        m_stateCopy       = tr("Reconnecting to the service");
        m_stateSubCopy    = tr("Hold tight — we're re-establishing the link.");
        emit stateChanged();
    } else {
        refreshAll();
    }
    emit connectionChanged(connected);
}

} // namespace ShadowStrike::PhantomHome::UI::Client
