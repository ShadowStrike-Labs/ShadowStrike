// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) ShadowStrike-Labs. All rights reserved.
//
// ProtectionViewModel
// -------------------
// Qt-side facade over PipeClient. Owns the protection-state cache, exposes
// Q_PROPERTY bindings for QML, and marshals server-push events onto the GUI
// thread via queued invocations.
//
// Threading model:
//   * PipeClient runs its I/O on its own worker thread(s).
//   * Any callback that mutates this object is trampolined via
//     QMetaObject::invokeMethod(..., Qt::QueuedConnection) so that property
//     signals fire on the GUI thread, where QML bindings are safe.
//
// This VM is intentionally narrow: it is NOT a policy engine. It just mirrors
// whatever the service publishes and translates user intents into requests.

#pragma once

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <memory>
#include <string>

namespace ShadowStrike::PhantomHome::IPC {
class PipeClient;
}

namespace ShadowStrike::PhantomHome::UI::Client {

using ::ShadowStrike::PhantomHome::IPC::PipeClient;

class ProtectionViewModel : public QObject {
    Q_OBJECT

    Q_PROPERTY(QString protectionState    READ protectionState    NOTIFY stateChanged)
    Q_PROPERTY(QString stateCopy          READ stateCopy          NOTIFY stateChanged)
    Q_PROPERTY(QString stateSubCopy       READ stateSubCopy       NOTIFY stateChanged)
    Q_PROPERTY(QString lastScan           READ lastScan           NOTIFY stateChanged)
    Q_PROPERTY(int     threatsBlocked7d   READ threatsBlocked7d   NOTIFY stateChanged)
    Q_PROPERTY(QString updateStatus       READ updateStatus       NOTIFY stateChanged)

    // Engine-health atoms (populated from ProtectionStateReply).
    Q_PROPERTY(bool    sensorOk           READ sensorOk           NOTIFY stateChanged)
    Q_PROPERTY(QString sensorReason       READ sensorReason       NOTIFY stateChanged)
    Q_PROPERTY(int     cortexActive       READ cortexActive       NOTIFY stateChanged)
    Q_PROPERTY(int     cortexTotal        READ cortexTotal        NOTIFY stateChanged)

    Q_PROPERTY(double  cpuPct             READ cpuPct             NOTIFY perfChanged)
    Q_PROPERTY(double  memPct             READ memPct             NOTIFY perfChanged)
    Q_PROPERTY(bool    gameModeActive     READ gameModeActive     NOTIFY perfChanged)
    Q_PROPERTY(bool    batterySaverActive READ batterySaverActive NOTIFY perfChanged)

    Q_PROPERTY(QVariantList modules         READ modules         NOTIFY modulesChanged)
    Q_PROPERTY(QVariantList recentEvents    READ recentEvents    NOTIFY eventsChanged)
    Q_PROPERTY(QVariantList quarantineItems READ quarantineItems NOTIFY quarantineChanged)

public:
    explicit ProtectionViewModel(std::shared_ptr<PipeClient> client,
                                 QObject* parent = nullptr);
    ~ProtectionViewModel() override;

    ProtectionViewModel(const ProtectionViewModel&)            = delete;
    ProtectionViewModel& operator=(const ProtectionViewModel&) = delete;

    // ---- Getters -----------------------------------------------------------
    QString protectionState()  const { return m_protectionState; }
    QString stateCopy()        const { return m_stateCopy; }
    QString stateSubCopy()     const { return m_stateSubCopy; }
    QString lastScan()         const { return m_lastScan; }
    int     threatsBlocked7d() const { return m_threatsBlocked7d; }
    QString updateStatus()     const { return m_updateStatus; }

    bool    sensorOk()     const { return m_sensorOk; }
    QString sensorReason() const { return m_sensorReason; }
    int     cortexActive() const { return m_cortexActive; }
    int     cortexTotal()  const { return m_cortexTotal; }

    double  cpuPct()             const { return m_cpuPct; }
    double  memPct()             const { return m_memPct; }
    bool    gameModeActive()     const { return m_gameMode; }
    bool    batterySaverActive() const { return m_batterySaver; }

    QVariantList modules()         const { return m_modules; }
    QVariantList recentEvents()    const { return m_recentEvents; }
    QVariantList quarantineItems() const { return m_quarantineItems; }

public slots:
    // ---- User intents, callable from QML -----------------------------------
    Q_INVOKABLE void startFastScan();
    Q_INVOKABLE void setModuleEnabled(const QString& id, bool enabled);
    Q_INVOKABLE void setDetectionAction(const QString& id, int action);
    Q_INVOKABLE void configureModule(const QString& id, const QVariantMap& payload);
    Q_INVOKABLE void runTuneUp(const QString& name);
    Q_INVOKABLE void runPasswordAudit();
    Q_INVOKABLE void refreshQuarantine();
    Q_INVOKABLE void restoreQuarantineItem(const QString& id);
    Q_INVOKABLE void deleteQuarantineItem(const QString& id);
    Q_INVOKABLE void exportReportCsv();
    Q_INVOKABLE void installUpdate();
    Q_INVOKABLE void refreshAll();

signals:
    void stateChanged();
    void perfChanged();
    void modulesChanged();
    void eventsChanged();
    void quarantineChanged();
    void connectionChanged(bool connected);

private:
    // Inbound wire handlers (invoked on GUI thread via QueuedConnection)
    Q_INVOKABLE void onStateReply(QString state, QString reason,
                                  int activeThreats, qint64 lastUpdateUnix,
                                  bool sensorOk, QString sensorReason,
                                  int cortexActive, int cortexTotal);
    Q_INVOKABLE void onDetectionPush(QString title, QString module,
                                     QString severity);
    Q_INVOKABLE void onConnectionChanged(bool connected);

    void wireClient();

    std::shared_ptr<PipeClient> m_client;

    // Cached state
    QString m_protectionState  = "green";
    QString m_stateCopy        = "We are protecting you";
    QString m_stateSubCopy     = "Connecting to the service…";
    QString m_lastScan         = "—";
    int     m_threatsBlocked7d = 0;
    QString m_updateStatus     = "Checking…";

    bool    m_sensorOk     = false;
    QString m_sensorReason = "probing";
    int     m_cortexActive = 0;
    int     m_cortexTotal  = 0;

    double  m_cpuPct       = 0.0;
    double  m_memPct       = 0.0;
    bool    m_gameMode     = false;
    bool    m_batterySaver = false;

    QVariantList m_modules;
    QVariantList m_recentEvents;
    QVariantList m_quarantineItems;
};

} // namespace ShadowStrike::PhantomHome::UI::Client
