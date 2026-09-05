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
 * @file ReportsModel.hpp
 * @brief Paginated QAbstractListModel for historical detection reports.
 *
 * Fetches pages via GetReports (240) with {offset, limit, filter}.
 * loadMore() appends the next page.  setFilter() resets the model
 * and re-fetches from offset 0.  exportCsv() writes the currently
 * loaded rows to a local CSV file without requiring service assistance.
 *
 * Page size: kPageSize (50 items).
 */
#pragma once

#include <QAbstractListModel>
#include <QDateTime>
#include <QUrl>
#include <memory>

namespace ShadowStrike::PhantomHome::UI::ViewModels {

class ReportsModel final : public QAbstractListModel {
    Q_OBJECT

    Q_PROPERTY(bool loading READ isLoading NOTIFY loadingChanged)
    Q_PROPERTY(bool hasMore READ hasMore   NOTIFY hasMoreChanged)

public:
    enum Role {
        IdRole          = Qt::UserRole + 1,
        TypeRole,
        SeverityRole,
        TitleRole,
        SummaryRole,
        TimestampRole,
        ActorRole,
        DetailsJsonRole,
    };
    Q_ENUM(Role)

    static constexpr int kPageSize = 50;

    explicit ReportsModel(QObject* parent = nullptr);
    ~ReportsModel() override;

    [[nodiscard]] int      rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QHash<int, QByteArray> roleNames() const override;

    [[nodiscard]] bool isLoading() const noexcept;
    [[nodiscard]] bool hasMore()   const noexcept;

    /**
     * @brief Load the next page of reports from the service.
     *
     * No-op if a load is already in progress or hasMore() is false.
     */
    Q_INVOKABLE void loadMore();

    /**
     * @brief Apply a filter and reload from offset 0.
     *
     * @param category    Empty string = all categories.
     * @param from        Null datetime = no lower bound.
     * @param to          Null datetime = no upper bound.
     * @param minSeverity Negative = no severity filter. Otherwise the
     *                    lowest ReportSeverity ordinal to include, so 3
     *                    means High and Critical.
     *
     * The range is sent to the service as epoch MILLISECONDS rather than
     * ISO 8601: report entries are stored in that unit, so the bound needs
     * no conversion and no date parser on the receiving side, and a local
     * QDateTime rendered with Qt::ISODate carries no zone offset for the
     * service to interpret.
     */
    Q_INVOKABLE void setFilter(const QString& category,
                               const QDateTime& from,
                               const QDateTime& to,
                               int minSeverity = -1);

    /**
     * @brief Export currently loaded rows to a UTF-8 CSV file.
     *
     * Written entirely client-side from the in-memory model.
     * exportCompleted or exportFailed is emitted when done.
     *
     * @param destination  file:// URL of the target CSV path.
     */
    Q_INVOKABLE void exportCsv(const QUrl& destination);

    /**
     * @brief Default destination for exportCsv, chosen on the C++ side.
     *
     * WHY THIS IS NOT DONE IN QML. ReportsSubroute.qml built this path itself
     * with QtCore's StandardPaths, which made the Reports page the only file in
     * the UI needing `import QtCore`. That QML module is not deployed, so QML
     * engine loading of the page failed outright with
     *
     *     ReportsSubroute.qml:25:1 - "QtCore" module is not installed
     *
     * and the page rendered BLANK on every navigation in the 1.0.109 field run -
     * the title still drew, because it comes from the route table rather than
     * from the page, which is why it looked like an empty report list rather
     * than a load failure.
     *
     * Deploying the module would also have worked, but this is the better fix:
     * the path is a platform question, QStandardPaths answers it natively in C++
     * with no QML module involved, and this class has to open the file anyway.
     * The layer that writes the file now chooses where it goes.
     *
     * Mirrors the QML behaviour exactly, including the fallback order:
     * Documents, then AppData, then AppConfig. Returns an empty QUrl if the
     * platform supplies none of them, which exportCsv already reports as an
     * invalid destination.
     *
     * @return file:// URL carrying a timestamped CSV name, or an empty QUrl.
     */
    Q_INVOKABLE QUrl suggestedExportPath() const;

signals:
    void loadingChanged();
    void hasMoreChanged();
    void requestError(QString code, QString message);
    void exportCompleted(QUrl destination);
    void exportFailed(QString reason);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;

    void doLoad(int offset);
};

} // namespace ShadowStrike::PhantomHome::UI::ViewModels
