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
 * @file ScanViewModel.hpp
 * @brief QObject ViewModel for the Scan page.
 *
 * State machine: Idle → Preparing → Running ⇆ Paused → Completed | Failed
 *
 * Real-time progress arrives via ScanProgressEvent push (103).
 * Polling fallback: GetScanProgress (222) at 500 ms while Running,
 * 5 s while Paused, stopped otherwise.
 *
 * Start:  static_cast<CommandType>(220) — v2 StartScan wire code
 * Cancel: static_cast<CommandType>(221) — v2 StopScan wire code
 * Pause / Resume: local state + poll-frequency adjustment only;
 *   no dedicated PauseScan/ResumeScan command exists in the v2 protocol.
 */
#pragma once

#include <QObject>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class ScanViewModel final : public QObject {
    Q_OBJECT

    Q_PROPERTY(int     state        READ state        NOTIFY stateChanged)
    Q_PROPERTY(int     percent      READ percent      NOTIFY progressChanged)
    Q_PROPERTY(quint64 itemsScanned READ itemsScanned NOTIFY progressChanged)
    Q_PROPERTY(quint64 threatsFound READ threatsFound NOTIFY progressChanged)
    Q_PROPERTY(QString currentPath  READ currentPath  NOTIFY progressChanged)
    Q_PROPERTY(QString scanId       READ scanId       NOTIFY stateChanged)

public:
    enum ScanState {
        Idle      = 0,
        Preparing = 1,
        Running   = 2,
        Paused    = 3,
        Completed = 4,
        Failed    = 5,
    };
    Q_ENUM(ScanState)

    explicit ScanViewModel(QObject* parent = nullptr);
    ~ScanViewModel() override;

    [[nodiscard]] int     state()        const noexcept;
    [[nodiscard]] int     percent()      const noexcept;
    [[nodiscard]] quint64 itemsScanned() const noexcept;
    [[nodiscard]] quint64 threatsFound() const noexcept;
    [[nodiscard]] QString currentPath()  const noexcept;
    [[nodiscard]] QString scanId()       const noexcept;

    Q_INVOKABLE void startFastScan();
    Q_INVOKABLE void startFullScan();
    /**
     * @brief Scan an explicit set of files and/or directories.
     *
     * Reached from the Scan page custom-path field and from the Explorer
     * "Scan with ShadowStrike" verb via the scan-path argument declared in
     * TrayUiArgs.hpp.  Directories are walked recursively by the service.
     *
     * IF A SCAN IS ALREADY ACTIVE the targets are QUEUED and started when it
     * finishes, rather than discarded.  doStartScan returns early while another
     * scan runs, so without the queue a second request would be accepted and
     * produce nothing.  That is not an edge case: Explorer invokes a verb ONCE
     * PER SELECTED ITEM, so it is the normal multi-selection path.
     */
    Q_INVOKABLE void startCustomScan(const QStringList& paths);

    /**
     * @brief Pause a running scan.
     *
     * Updates local UI state to Paused and reduces the poll-timer
     * frequency to 5 s.  A dedicated PauseScan wire command is not
     * yet defined in the v2 protocol; full service-side pause requires
     * a future protocol extension.
     */
    Q_INVOKABLE void pause();

    /**
     * @brief Resume a paused scan.
     *
     * Restores local UI state to Running and resets the poll-timer
     * to 500 ms.  See note in pause() regarding protocol limitations.
     */
    Q_INVOKABLE void resume();

    /** Sends v2 StopScan (static_cast<CommandType>(221)) to the service. */
    Q_INVOKABLE void cancel();

signals:
    void stateChanged();
    void progressChanged();
    void scanCompleted(QString id, quint64 threats);
    void requestError(QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    // Implementation helpers defined in the .cpp (not part of the public ABI).
    void doStartScan(const QJsonObject& payload);
    void applyProgressUpdate(const QJsonObject& ev);
    void pollProgress();

    /// Starts a scan for targets queued while an earlier scan was running.
    /// Invoked on the next event-loop turn after a scan reaches Completed or
    /// Failed, never inline from the state transition that observed it.
    void drainPendingCustomScan();
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
