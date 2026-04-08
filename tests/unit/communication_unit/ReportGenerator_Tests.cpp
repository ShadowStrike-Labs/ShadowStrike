#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Communication/ReportGenerator.hpp"

#include <chrono>
#include <string>

namespace Reports = ShadowStrike::Communication;

namespace {

using SystemClock = std::chrono::system_clock;

SystemClock::time_point FixedTime() {
    return SystemClock::from_time_t(1'700'000'000);
}

} // namespace

/*
 * ============================================================================
 * ShadowStrike ReportGenerator - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Report DTO serialization for export pipelines
 * - Time/config validation guards
 * - Statistics reset and snapshot behavior
 *
 * ============================================================================
 */

TEST(ReportGeneratorTest, TimeRangeValidationAndSerializationReflectRequestedWindow) {
    Reports::TimeRange range{};
    range.startTime = FixedTime();
    range.endTime = FixedTime() + std::chrono::hours(24);
    range.period = Reports::ReportPeriod::Custom;

    EXPECT_TRUE(range.IsValid());
    const std::string json = range.ToJson();
    EXPECT_NE(json.find("\"period\":\"Custom\""), std::string::npos);

    range.endTime = range.startTime;
    EXPECT_FALSE(range.IsValid());
}

TEST(ReportGeneratorTest, ReportSectionAndMetadataSerializeStructuredContent) {
    Reports::ReportSection section{};
    section.sectionId = "summary";
    section.title = "Executive Summary";
    section.content = "All critical systems healthy";
    section.data["severity"] = "low";
    section.tableHeaders = {"ColumnA", "ColumnB"};
    section.tableData = {{"v1", "v2"}};
    section.chartData["blocked"] = 7.0;
    section.order = 1;
    section.isVisible = true;

    const std::string sectionJson = section.ToJson();
    EXPECT_NE(sectionJson.find("\"sectionId\":\"summary\""), std::string::npos);
    EXPECT_NE(sectionJson.find("\"blocked\":7.000000"), std::string::npos);

    Reports::ReportMetadata metadata{};
    metadata.reportId = "report-1";
    metadata.title = "Daily Security Audit";
    metadata.reportType = Reports::ReportType::SecurityAudit;
    metadata.generatedTime = FixedTime();
    metadata.organizationName = "ShadowStrike Labs";
    metadata.generatedBy = "UnitTest";
    metadata.timeRange.startTime = FixedTime();
    metadata.timeRange.endTime = FixedTime() + std::chrono::hours(1);
    metadata.version = "3.0.0";
    metadata.description = "Daily validation";
    metadata.tags = {"daily", "security"};

    const std::string metadataJson = metadata.ToJson();
    EXPECT_NE(metadataJson.find("\"reportId\":\"report-1\""), std::string::npos);
    EXPECT_NE(metadataJson.find("\"organizationName\":\"ShadowStrike Labs\""), std::string::npos);
    EXPECT_NE(metadataJson.find("\"tags\":[\"daily\",\"security\"]"), std::string::npos);
}

TEST(ReportGeneratorTest, StatisticalReportStructuresSerializeAggregatesAndFindings) {
    Reports::ThreatStatistics threatStats{};
    threatStats.totalDetections = 9;
    threatStats.bySeverity["High"] = 4;
    threatStats.byType["Ransomware"] = 2;
    threatStats.byAction["Blocked"] = 8;
    threatStats.dailyCounts["2026-04-08"] = 9;
    threatStats.topThreats.push_back({"Trojan.Test", 3});
    const std::string threatJson = threatStats.ToJson();
    EXPECT_NE(threatJson.find("\"totalDetections\":9"), std::string::npos);
    EXPECT_NE(threatJson.find("\"name\":\"Trojan.Test\""), std::string::npos);

    Reports::ScanStatistics scanStats{};
    scanStats.totalScans = 5;
    scanStats.filesScanned = 100;
    scanStats.bytesScanned = 4096;
    scanStats.avgScanTimeMs = 15;
    scanStats.byScanType["Quick"] = 3;
    scanStats.byResult["Clean"] = 4;
    const std::string scanJson = scanStats.ToJson();
    EXPECT_NE(scanJson.find("\"filesScanned\":100"), std::string::npos);
    EXPECT_NE(scanJson.find("\"avgScanTimeMs\":15"), std::string::npos);

    Reports::ComplianceCheckResult compliance{};
    compliance.checkId = "cis-1";
    compliance.checkName = "PowerShell logging enabled";
    compliance.standard = Reports::ComplianceStandard::CIS;
    compliance.passed = true;
    compliance.finding = "Configured";
    compliance.recommendation = "No action required";
    compliance.severity = 2;
    const std::string complianceJson = compliance.ToJson();
    EXPECT_NE(complianceJson.find("\"passed\":true"), std::string::npos);
    EXPECT_NE(complianceJson.find("\"severity\":2"), std::string::npos);
}

TEST(ReportGeneratorTest, ReportJobsTemplatesAndSchedulesSerializeLifecycleMetadata) {
    Reports::ReportJob job{};
    job.jobId = "job-1";
    job.reportType = Reports::ReportType::ThreatSummary;
    job.format = Reports::ReportFormat::JSON;
    job.outputPath = LR"(C:\Reports\threat-summary.json)";
    job.status = Reports::ReportStatus::Completed;
    job.createdTime = FixedTime();
    job.completedTime = FixedTime() + std::chrono::minutes(1);
    job.progress = 100;
    job.fileSize = 2048;
    job.errorMessage = "none";
    const std::string jobJson = job.ToJson();
    EXPECT_NE(jobJson.find("\"jobId\":\"job-1\""), std::string::npos);
    EXPECT_NE(jobJson.find("\"progress\":100"), std::string::npos);
    EXPECT_NE(jobJson.find("\"error\":\"none\""), std::string::npos);

    Reports::ReportTemplate templ{};
    templ.templateId = "tpl-1";
    templ.name = "Executive";
    templ.description = "Exec overview";
    templ.reportType = Reports::ReportType::ExecutiveSummary;
    templ.isDefault = true;
    templ.isBuiltIn = false;
    const std::string templateJson = templ.ToJson();
    EXPECT_NE(templateJson.find("\"templateId\":\"tpl-1\""), std::string::npos);
    EXPECT_NE(templateJson.find("\"isBuiltIn\":false"), std::string::npos);

    Reports::ReportSchedule schedule{};
    schedule.scheduleId = "sched-1";
    schedule.reportType = Reports::ReportType::SecurityAudit;
    schedule.format = Reports::ReportFormat::PDF;
    schedule.period = Reports::ReportPeriod::Last7Days;
    schedule.enabled = true;
    schedule.nextRunTime = FixedTime();
    schedule.lastRunTime = FixedTime() - std::chrono::hours(24);
    const std::string scheduleJson = schedule.ToJson();
    EXPECT_NE(scheduleJson.find("\"scheduleId\":\"sched-1\""), std::string::npos);
    EXPECT_NE(scheduleJson.find("\"enabled\":true"), std::string::npos);
}

TEST(ReportGeneratorTest, ReportConfigurationRejectsTraversalAndInvalidCapacitySettings) {
    Reports::ReportConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.maxReportSizeMB = 1024;
    EXPECT_TRUE(config.IsValid());

    config.maxReportSizeMB = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.retentionDays = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.outputDirectory = LR"(C:\Reports\..\Escaped)";
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.archiveDirectory = LR"(C:\Archive\..\Escaped)";
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.templateDirectory = LR"(C:\Templates\..\Escaped)";
    EXPECT_FALSE(config.IsValid());
}

TEST(ReportGeneratorTest, ReportStatisticsResetProducesStableSnapshotAndJson) {
    Reports::ReportStatistics stats{};
    stats.reportsGenerated.store(6, std::memory_order_relaxed);
    stats.reportsFailed.store(1, std::memory_order_relaxed);
    stats.reportsDelivered.store(5, std::memory_order_relaxed);
    stats.totalGenerationTimeMs.store(900, std::memory_order_relaxed);
    stats.totalSizeBytes.store(50'000, std::memory_order_relaxed);
    stats.byFormat[1].store(3, std::memory_order_relaxed);
    stats.byType[2].store(4, std::memory_order_relaxed);

    Reports::ReportStatisticsSnapshot snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.reportsGenerated, 6u);
    EXPECT_EQ(snapshot.totalSizeBytes, 50'000u);
    EXPECT_EQ(snapshot.byFormat[1], 3u);
    EXPECT_EQ(snapshot.byType[2], 4u);
    EXPECT_NE(snapshot.ToJson().find("\"reportsDelivered\":5"), std::string::npos);

    stats.Reset();
    snapshot = stats.TakeSnapshot();
    EXPECT_EQ(snapshot.reportsGenerated, 0u);
    EXPECT_EQ(snapshot.totalGenerationTimeMs, 0u);
    EXPECT_EQ(snapshot.byFormat[1], 0u);
}
