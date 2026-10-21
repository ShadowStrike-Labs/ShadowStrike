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
#include <QVariantList>
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

    //
    // WHAT THE SCAN FOUND. One map per confirmed detection - path, threatName,
    // detectionSource, quarantined, actionable, pending - so the page can list
    // the files beside the action. Empty until the scan completes; a count of
    // threats with no way to see or act on them was the defect this replaces.
    //
    Q_PROPERTY(QVariantList detections        READ detections        NOTIFY detectionsChanged)
    Q_PROPERTY(int          detectionsOmitted READ detectionsOmitted NOTIFY detectionsChanged)

    //
    // WHAT THE SCAN IS. Without these the model could describe a scan only
    // as a percentage, so the one progress surface in the product labelled
    // every scan "Quick Scan" - including a right-click scan of a single
    // file, which is neither quick-scan scope nor machine-wide.
    //
    // NOTIFIED BY progressChanged, NOT stateChanged, and that is deliberate:
    // stateChanged is emitted only on a state TRANSITION, while these values
    // arrive on ordinary poll replies. Binding them to stateChanged would
    // leave them stale for the whole run of a scan.
    //
    Q_PROPERTY(QString scope         READ scope         NOTIFY progressChanged)
    Q_PROPERTY(QString targetSummary READ targetSummary NOTIFY progressChanged)

    /// WHY THE LAST ATTEMPT FAILED, as a readable property rather than only as
    /// a signal.
    ///
    /// requestError() already carried this, and nothing consumed it for the
    /// scan surface - measured, MainPage declares no onRequestError handler on
    /// this object - so the reason was emitted into the void. A transient
    /// signal also cannot be rendered by a declarative binding, which is what
    /// the tile needs in order to SHOW the failure instead of implying one.
    ///
    /// Notified by its own signal, not by stateChanged: cancel() can fail
    /// without changing state, and folding the two would leave that reason
    /// unpublished.
    Q_PROPERTY(QString lastErrorCode    READ lastErrorCode    NOTIFY lastErrorChanged)
    Q_PROPERTY(QString lastErrorMessage READ lastErrorMessage NOTIFY lastErrorChanged)

    //
    // THE ENGINE'S OWN FIGURES, each with a producer in ScanBatch's emitter.
    // totalBytes is absent because no emitter sets it - the engine cannot
    // know it without stat-ing every file before scanning - so there is
    // deliberately no property for a value that would always read zero.
    //
    Q_PROPERTY(quint64 totalFiles    READ totalFiles    NOTIFY progressChanged)
    Q_PROPERTY(quint64 bytesScanned  READ bytesScanned  NOTIFY progressChanged)
    Q_PROPERTY(quint64 elapsedMs     READ elapsedMs     NOTIFY progressChanged)
    Q_PROPERTY(quint64 estimatedRemainingMs
                                     READ estimatedRemainingMs
                                     NOTIFY progressChanged)
    Q_PROPERTY(quint64 filesPerSecond
                                     READ filesPerSecond
                                     NOTIFY progressChanged)
    Q_PROPERTY(quint64 bytesPerSecond
                                     READ bytesPerSecond
                                     NOTIFY progressChanged)

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
    [[nodiscard]] QVariantList detections()        const;
    [[nodiscard]] int          detectionsOmitted() const noexcept;

    [[nodiscard]] QString scope()         const noexcept;
    [[nodiscard]] QString targetSummary() const noexcept;
    [[nodiscard]] QString lastErrorCode()    const noexcept;
    [[nodiscard]] QString lastErrorMessage() const noexcept;
    [[nodiscard]] quint64 totalFiles()    const noexcept;
    [[nodiscard]] quint64 bytesScanned()  const noexcept;
    [[nodiscard]] quint64 elapsedMs()     const noexcept;
    [[nodiscard]] quint64 estimatedRemainingMs() const noexcept;
    [[nodiscard]] quint64 filesPerSecond() const noexcept;
    [[nodiscard]] quint64 bytesPerSecond() const noexcept;

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

    /**
     * @brief Quarantine one file the completed scan reported.
     *
     * Sends QuarantineDetection (232) with this scan's id and the path exactly as
     * the service reported it. The service refuses any path the scan did not
     * report, and refuses a file whose content has changed since it was scanned.
     * The outcome arrives as detectionActionFinished().
     */
    Q_INVOKABLE void quarantineDetection(const QString& path);

signals:
    void stateChanged();
    void progressChanged();
    void scanCompleted(QString id, quint64 threats);
    void requestError(QString code, QString message);
    /// Emitted whenever lastErrorCode/lastErrorMessage change, including when
    /// they are CLEARED at the start of a new attempt - so a stale reason
    /// cannot outlive the failure it described.
    void lastErrorChanged();
    void detectionsChanged();
    /// @p code is the service's stable outcome code ("ok", "content_changed",
    /// "system_file_protected", ...), so the page can explain a refusal rather
    /// than only report that one happened.
    void detectionActionFinished(QString path, bool ok, QString code, QString message);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    // Implementation helpers defined in the .cpp (not part of the public ABI).
    void doStartScan(const QJsonObject& payload);
    void applyProgressUpdate(const QJsonObject& ev);
    /// Rewrites one detection's map in place. Returns false if it is not listed.
    bool updateDetection(const QString& path, const QVariantMap& changes);
    void pollProgress();

    /// Starts a scan for targets queued while an earlier scan was running.
    /// Invoked on the next event-loop turn after a scan reaches Completed or
    /// Failed, never inline from the state transition that observed it.
    void drainPendingCustomScan();
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
