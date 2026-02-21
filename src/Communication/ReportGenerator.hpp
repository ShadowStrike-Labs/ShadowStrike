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
 * ============================================================================
 * ShadowStrike NGAV - REPORT GENERATOR MODULE
 * ============================================================================
 *
 * @file ReportGenerator.hpp
 * @brief Enterprise-grade security report generation with multiple formats,
 *        templates, scheduling, and compliance documentation support.
 *
 * Provides comprehensive report generation including security audits, threat
 * analysis, compliance documentation, executive summaries, and forensic reports.
 *
 * REPORT CAPABILITIES:
 * ====================
 *
 * 1. FORMAT SUPPORT
 *    - PDF generation
 *    - HTML reports
 *    - JSON data export
 *    - CSV spreadsheets
 *    - XML documents
 *    - RTF documents
 *    - SIEM-compatible formats
 *
 * 2. REPORT TYPES
 *    - Security audit
 *    - Threat summary
 *    - Scan history
 *    - Compliance report
 *    - Executive summary
 *    - Forensic analysis
 *    - Incident report
 *
 * 3. TEMPLATE ENGINE
 *    - Custom templates
 *    - Branding support
 *    - Localization
 *    - Variable substitution
 *    - Conditional sections
 *
 * 4. SCHEDULING
 *    - Automated generation
 *    - Email delivery
 *    - Archive management
 *    - Retention policies
 *
 * 5. DATA AGGREGATION
 *    - Multi-source data
 *    - Statistics calculation
 *    - Trend analysis
 *    - Visualization data
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/TimeUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Communication {
    class ReportGeneratorImpl;
}

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ReportConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum report size (MB)
    inline constexpr size_t MAX_REPORT_SIZE_MB = 100;
    
    /// @brief Default template directory
    inline constexpr const wchar_t* DEFAULT_TEMPLATE_DIR = L"Templates\\Reports";
    
    /// @brief Default output directory
    inline constexpr const wchar_t* DEFAULT_OUTPUT_DIR = L"Reports";
    
    /// @brief Archive retention days
    inline constexpr uint32_t DEFAULT_RETENTION_DAYS = 365;
    
    /// @brief Maximum items per report section
    inline constexpr size_t MAX_ITEMS_PER_SECTION = 10000;

}  // namespace ReportConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Report format
 */
enum class ReportFormat : uint8_t {
    PDF             = 0,
    HTML            = 1,
    JSON            = 2,
    CSV             = 3,
    XML             = 4,
    RTF             = 5,
    XLSX            = 6,
    SYSLOG          = 7,
    CEF             = 8,    ///< Common Event Format
    LEEF            = 9     ///< Log Event Extended Format
};

/**
 * @brief Report type
 */
enum class ReportType : uint8_t {
    SecurityAudit       = 0,    ///< Full security audit
    ThreatSummary       = 1,    ///< Threat detection summary
    ScanHistory         = 2,    ///< Scan history log
    ComplianceReport    = 3,    ///< Compliance documentation
    ExecutiveSummary    = 4,    ///< High-level summary
    ForensicAnalysis    = 5,    ///< Forensic investigation
    IncidentReport      = 6,    ///< Specific incident
    SystemHealth        = 7,    ///< System health report
    PerformanceReport   = 8,    ///< Performance metrics
    UpdateHistory       = 9,    ///< Update/patch history
    UserActivity        = 10,   ///< User activity log
    QuarantineLog       = 11,   ///< Quarantine history
    Custom              = 12
};

/**
 * @brief Report period
 */
enum class ReportPeriod : uint8_t {
    Today           = 0,
    Yesterday       = 1,
    Last7Days       = 2,
    Last30Days      = 3,
    Last90Days      = 4,
    LastYear        = 5,
    Custom          = 6,
    AllTime         = 7
};

/**
 * @brief Report status
 */
enum class ReportStatus : uint8_t {
    Pending         = 0,
    Generating      = 1,
    Completed       = 2,
    Failed          = 3,
    Cancelled       = 4,
    Delivered       = 5
};

/**
 * @brief Compliance standard
 */
enum class ComplianceStandard : uint8_t {
    None            = 0,
    HIPAA           = 1,
    PCI_DSS         = 2,
    GDPR            = 3,
    SOX             = 4,
    ISO27001        = 5,
    NIST            = 6,
    CIS             = 7,
    FERPA           = 8,
    SOC2            = 9
};

/**
 * @brief Module status
 */
enum class ReportModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Generating      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Time range
 */
struct TimeRange {
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief End time
    SystemTimePoint endTime;
    
    /// @brief Period type
    ReportPeriod period = ReportPeriod::Last7Days;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Report section
 */
struct ReportSection {
    /// @brief Section ID
    std::string sectionId;
    
    /// @brief Section title
    std::string title;
    
    /// @brief Section content
    std::string content;
    
    /// @brief Data (key-value)
    std::map<std::string, std::string> data;
    
    /// @brief Table data (rows)
    std::vector<std::vector<std::string>> tableData;
    
    /// @brief Table headers
    std::vector<std::string> tableHeaders;
    
    /// @brief Chart data (for visualization)
    std::map<std::string, double> chartData;
    
    /// @brief Order index
    uint32_t order = 0;
    
    /// @brief Is visible
    bool isVisible = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Report metadata
 */
struct ReportMetadata {
    /// @brief Report ID
    std::string reportId;
    
    /// @brief Report title
    std::string title;
    
    /// @brief Report type
    ReportType reportType = ReportType::SecurityAudit;
    
    /// @brief Generated time
    SystemTimePoint generatedTime;
    
    /// @brief Organization name
    std::string organizationName;
    
    /// @brief Generated by
    std::string generatedBy;
    
    /// @brief Time range
    TimeRange timeRange;
    
    /// @brief Version
    std::string version;
    
    /// @brief Description
    std::string description;
    
    /// @brief Tags
    std::vector<std::string> tags;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Threat statistics for report
 */
struct ThreatStatistics {
    /// @brief Total detections
    uint64_t totalDetections = 0;
    
    /// @brief By severity
    std::map<std::string, uint64_t> bySeverity;
    
    /// @brief By type
    std::map<std::string, uint64_t> byType;
    
    /// @brief By action
    std::map<std::string, uint64_t> byAction;
    
    /// @brief Daily counts
    std::map<std::string, uint64_t> dailyCounts;
    
    /// @brief Top threats
    std::vector<std::pair<std::string, uint64_t>> topThreats;
    
    /// @brief Top affected files
    std::vector<std::pair<std::string, uint64_t>> topAffectedPaths;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan statistics for report
 */
struct ScanStatistics {
    /// @brief Total scans
    uint64_t totalScans = 0;
    
    /// @brief Files scanned
    uint64_t filesScanned = 0;
    
    /// @brief Bytes scanned
    uint64_t bytesScanned = 0;
    
    /// @brief Average scan time (ms)
    uint64_t avgScanTimeMs = 0;
    
    /// @brief By scan type
    std::map<std::string, uint64_t> byScanType;
    
    /// @brief By result
    std::map<std::string, uint64_t> byResult;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Compliance check result
 */
struct ComplianceCheckResult {
    /// @brief Check ID
    std::string checkId;
    
    /// @brief Check name
    std::string checkName;
    
    /// @brief Standard
    ComplianceStandard standard = ComplianceStandard::None;
    
    /// @brief Is passed
    bool passed = false;
    
    /// @brief Finding
    std::string finding;
    
    /// @brief Recommendation
    std::string recommendation;
    
    /// @brief Severity (1-10)
    uint8_t severity = 5;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Report job
 */
struct ReportJob {
    /// @brief Job ID
    std::string jobId;
    
    /// @brief Report type
    ReportType reportType = ReportType::SecurityAudit;
    
    /// @brief Format
    ReportFormat format = ReportFormat::PDF;
    
    /// @brief Time range
    TimeRange timeRange;
    
    /// @brief Output path
    fs::path outputPath;
    
    /// @brief Template name
    std::string templateName;
    
    /// @brief Status
    ReportStatus status = ReportStatus::Pending;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Completed time
    std::optional<SystemTimePoint> completedTime;
    
    /// @brief Progress (0-100)
    uint8_t progress = 0;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief File size (bytes)
    size_t fileSize = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Report template
 */
struct ReportTemplate {
    /// @brief Template ID
    std::string templateId;
    
    /// @brief Template name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Template path
    fs::path templatePath;
    
    /// @brief Report type
    ReportType reportType = ReportType::SecurityAudit;
    
    /// @brief Supported formats
    std::set<ReportFormat> supportedFormats;
    
    /// @brief Variables
    std::vector<std::string> variables;
    
    /// @brief Is default
    bool isDefault = false;
    
    /// @brief Is built-in
    bool isBuiltIn = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Schedule configuration
 */
struct ReportSchedule {
    /// @brief Schedule ID
    std::string scheduleId;
    
    /// @brief Report type
    ReportType reportType = ReportType::SecurityAudit;
    
    /// @brief Format
    ReportFormat format = ReportFormat::PDF;
    
    /// @brief Period
    ReportPeriod period = ReportPeriod::Last7Days;
    
    /// @brief Cron expression
    std::string cronExpression;
    
    /// @brief Email recipients
    std::vector<std::string> emailRecipients;
    
    /// @brief Output directory
    fs::path outputDirectory;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Next run time
    SystemTimePoint nextRunTime;
    
    /// @brief Last run time
    std::optional<SystemTimePoint> lastRunTime;
    
    /// @brief Last run success
    bool lastRunSuccess = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct ReportStatistics {
    std::atomic<uint64_t> reportsGenerated{0};
    std::atomic<uint64_t> reportsFailed{0};
    std::atomic<uint64_t> reportsDelivered{0};
    std::atomic<uint64_t> totalGenerationTimeMs{0};
    std::atomic<uint64_t> totalSizeBytes{0};
    std::array<std::atomic<uint64_t>, 16> byFormat{};
    std::array<std::atomic<uint64_t>, 16> byType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ReportConfiguration {
    /// @brief Enable report generation
    bool enabled = true;
    
    /// @brief Template directory
    fs::path templateDirectory;
    
    /// @brief Output directory
    fs::path outputDirectory;
    
    /// @brief Archive directory
    fs::path archiveDirectory;
    
    /// @brief Default format
    ReportFormat defaultFormat = ReportFormat::PDF;
    
    /// @brief Max report size (MB)
    size_t maxReportSizeMB = ReportConstants::MAX_REPORT_SIZE_MB;
    
    /// @brief Retention days
    uint32_t retentionDays = ReportConstants::DEFAULT_RETENTION_DAYS;
    
    /// @brief Enable compression
    bool enableCompression = true;
    
    /// @brief Enable encryption
    bool enableEncryption = false;
    
    /// @brief Encryption password
    std::string encryptionPassword;
    
    /// @brief Organization name
    std::string organizationName;
    
    /// @brief Logo path
    fs::path logoPath;
    
    /// @brief Default compliance standards
    std::set<ComplianceStandard> defaultCompliance;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProgressCallback = std::function<void(const std::string& jobId, uint8_t progress)>;
using CompletionCallback = std::function<void(const ReportJob&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// REPORT GENERATOR CLASS
// ============================================================================

/**
 * @class ReportGenerator
 * @brief Enterprise report generation
 */
class ReportGenerator final {
public:
    [[nodiscard]] static ReportGenerator& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ReportGenerator(const ReportGenerator&) = delete;
    ReportGenerator& operator=(const ReportGenerator&) = delete;
    ReportGenerator(ReportGenerator&&) = delete;
    ReportGenerator& operator=(ReportGenerator&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ReportConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ReportModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const ReportConfiguration& config);
    [[nodiscard]] ReportConfiguration GetConfiguration() const;

    // ========================================================================
    // REPORT GENERATION
    // ========================================================================
    
    /// @brief Generate HTML report
    [[nodiscard]] std::string GenerateHtmlReport(uint64_t startTime, uint64_t endTime);
    
    /// @brief Generate report (returns path)
    [[nodiscard]] std::optional<fs::path> GenerateReport(
        ReportType type,
        ReportFormat format,
        const TimeRange& timeRange,
        const std::string& templateName = "");
    
    /// @brief Generate report asynchronously
    [[nodiscard]] std::string GenerateReportAsync(
        ReportType type,
        ReportFormat format,
        const TimeRange& timeRange,
        const std::string& templateName = "");
    
    /// @brief Generate compliance report
    [[nodiscard]] std::optional<fs::path> GenerateComplianceReport(
        ComplianceStandard standard,
        ReportFormat format,
        const TimeRange& timeRange);
    
    /// @brief Generate incident report
    [[nodiscard]] std::optional<fs::path> GenerateIncidentReport(
        const std::string& incidentId,
        ReportFormat format);

    // ========================================================================
    // EXPORT FUNCTIONS
    // ========================================================================
    
    /// @brief Export to CSV
    [[nodiscard]] bool ExportToCsv(const std::wstring& outputPath);
    
    /// @brief Export to CSV with time range
    [[nodiscard]] bool ExportToCsv(
        const fs::path& outputPath,
        const TimeRange& timeRange);
    
    /// @brief Export to JSON
    [[nodiscard]] bool ExportToJson(
        const fs::path& outputPath,
        const TimeRange& timeRange);
    
    /// @brief Export to SIEM format
    [[nodiscard]] bool ExportToSiem(
        const fs::path& outputPath,
        ReportFormat siemFormat,
        const TimeRange& timeRange);

    // ========================================================================
    // TEMPLATE MANAGEMENT
    // ========================================================================
    
    /// @brief Load templates
    [[nodiscard]] bool LoadTemplates();
    
    /// @brief Get available templates
    [[nodiscard]] std::vector<ReportTemplate> GetTemplates(
        std::optional<ReportType> filterType = std::nullopt);
    
    /// @brief Import custom template
    [[nodiscard]] bool ImportTemplate(const fs::path& templatePath);
    
    /// @brief Delete template
    [[nodiscard]] bool DeleteTemplate(const std::string& templateId);

    // ========================================================================
    // SCHEDULING
    // ========================================================================
    
    /// @brief Create schedule
    [[nodiscard]] std::string CreateSchedule(const ReportSchedule& schedule);
    
    /// @brief Update schedule
    [[nodiscard]] bool UpdateSchedule(const ReportSchedule& schedule);
    
    /// @brief Delete schedule
    [[nodiscard]] bool DeleteSchedule(const std::string& scheduleId);
    
    /// @brief Get schedules
    [[nodiscard]] std::vector<ReportSchedule> GetSchedules();
    
    /// @brief Enable/disable schedule
    [[nodiscard]] bool SetScheduleEnabled(const std::string& scheduleId, bool enabled);

    // ========================================================================
    // JOB MANAGEMENT
    // ========================================================================
    
    /// @brief Get job status
    [[nodiscard]] std::optional<ReportJob> GetJobStatus(const std::string& jobId);
    
    /// @brief Get pending jobs
    [[nodiscard]] std::vector<ReportJob> GetPendingJobs();
    
    /// @brief Cancel job
    [[nodiscard]] bool CancelJob(const std::string& jobId);

    // ========================================================================
    // DATA ACCESS
    // ========================================================================
    
    /// @brief Get threat statistics
    [[nodiscard]] ThreatStatistics GetThreatStatistics(const TimeRange& timeRange);
    
    /// @brief Get scan statistics
    [[nodiscard]] ScanStatistics GetScanStatistics(const TimeRange& timeRange);
    
    /// @brief Get compliance check results
    [[nodiscard]] std::vector<ComplianceCheckResult> GetComplianceResults(
        ComplianceStandard standard);

    // ========================================================================
    // ARCHIVE MANAGEMENT
    // ========================================================================
    
    /// @brief Get archived reports
    [[nodiscard]] std::vector<ReportJob> GetArchivedReports(
        const TimeRange& timeRange,
        std::optional<ReportType> filterType = std::nullopt);
    
    /// @brief Delete archived report
    [[nodiscard]] bool DeleteArchivedReport(const std::string& reportId);
    
    /// @brief Cleanup old archives
    [[nodiscard]] size_t CleanupArchives(uint32_t olderThanDays);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterCompletionCallback(CompletionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ReportStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ReportGenerator();
    ~ReportGenerator();
    
    std::unique_ptr<ReportGeneratorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetFormatName(ReportFormat format) noexcept;
[[nodiscard]] std::string_view GetFormatExtension(ReportFormat format) noexcept;
[[nodiscard]] std::string_view GetReportTypeName(ReportType type) noexcept;
[[nodiscard]] std::string_view GetPeriodName(ReportPeriod period) noexcept;
[[nodiscard]] std::string_view GetComplianceStandardName(ComplianceStandard std) noexcept;
[[nodiscard]] std::string_view GetStatusName(ReportStatus status) noexcept;

/// @brief Calculate time range from period
[[nodiscard]] TimeRange CalculateTimeRange(ReportPeriod period);

/// @brief Format file size
[[nodiscard]] std::string FormatFileSize(size_t bytes);

/// @brief Escape HTML
[[nodiscard]] std::string EscapeHtml(const std::string& input);

/// @brief Escape CSV field
[[nodiscard]] std::string EscapeCsvField(const std::string& field);

}  // namespace Communication
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_GENERATE_REPORT(type, format, range) \
    ::ShadowStrike::Communication::ReportGenerator::Instance().GenerateReport(type, format, range)

#define SS_EXPORT_CSV(path) \
    ::ShadowStrike::Communication::ReportGenerator::Instance().ExportToCsv(path)
