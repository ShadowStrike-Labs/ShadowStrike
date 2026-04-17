/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Compliance/ComplianceReporter.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <format>
#include <fstream>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::Products::PhantomEDR::Compliance {

namespace {

using json = nlohmann::json;
using ShadowStrike::Utils::Logger;

constexpr std::string_view kLogPrefix = "[ComplianceReporter]";

[[nodiscard]] std::string TimeToIso8601(Clock::time_point tp) {
    const auto tt = Clock::to_time_t(tp);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

[[nodiscard]] std::string EscapeHtml(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

[[nodiscard]] std::string StatusBadgeClass(CheckStatus s) {
    switch (s) {
        case CheckStatus::Pass:          return "badge-pass";
        case CheckStatus::Fail:          return "badge-fail";
        case CheckStatus::Unknown:       return "badge-unknown";
        case CheckStatus::NotApplicable: return "badge-na";
        case CheckStatus::Error:         return "badge-error";
    }
    return "badge-unknown";
}

[[nodiscard]] std::string SeverityColor(Severity s) {
    switch (s) {
        case Severity::Critical: return "#dc3545";
        case Severity::High:     return "#fd7e14";
        case Severity::Medium:   return "#ffc107";
        case Severity::Low:      return "#28a745";
        case Severity::Info:     return "#17a2b8";
    }
    return "#6c757d";
}

[[nodiscard]] bool WriteStringToFile(std::string_view filePath, std::string_view content) {
    std::ofstream ofs(std::string(filePath), std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    return ofs.good();
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class ComplianceReporterImpl {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lk(m_mtx);
        if (m_initialized) return true;
        m_initialized = true;
        Logger::Info("{} Initialized", kLogPrefix);
        return true;
    }

    void Shutdown() {
        std::unique_lock lk(m_mtx);
        m_initialized = false;
        Logger::Info("{} Shut down", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lk(m_mtx);
        return m_initialized;
    }

    [[nodiscard]] std::string GenerateJsonReport(const ComplianceScanResult& scan) const {
        json j;
        j["scanId"] = scan.scanId;
        j["framework"] = std::string(ToString(scan.framework));
        j["startedAt"] = TimeToIso8601(scan.startedAt);
        j["completedAt"] = TimeToIso8601(scan.completedAt);
        j["complianceScore"] = scan.ComplianceScore();
        j["summary"] = {
            {"totalChecks", scan.totalChecks},
            {"passed", scan.passed},
            {"failed", scan.failed},
            {"unknown", scan.unknown},
            {"notApplicable", scan.notApplicable},
            {"errors", scan.errors}
        };

        // Group results by category
        std::unordered_map<std::string, json> categories;
        for (const auto& r : scan.results) {
            auto catName = std::string(ToString(r.category));
            if (!categories.contains(catName)) {
                categories[catName] = json::array();
            }
            json check;
            check["checkId"] = r.checkId;
            check["title"] = r.title;
            check["severity"] = std::string(ToString(r.severity));
            check["status"] = std::string(ToString(r.status));
            check["expectedValue"] = r.expectedValue;
            check["actualValue"] = r.actualValue;
            check["detail"] = r.detail;
            check["evaluatedAt"] = TimeToIso8601(r.evaluatedAt);
            categories[catName].push_back(std::move(check));
        }

        json catArray = json::object();
        for (auto& [name, arr] : categories) {
            catArray[name] = std::move(arr);
        }
        j["categories"] = std::move(catArray);

        return j.dump(2);
    }

    [[nodiscard]] std::string GenerateHtmlReport(const ComplianceScanResult& scan) const {
        std::ostringstream html;

        html << R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowStrike Compliance Report</title>
<style>
    :root { --bg: #0d1117; --card: #161b22; --text: #c9d1d9; --border: #30363d; --accent: #58a6ff; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
           background: var(--bg); color: var(--text); padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #f0f6fc; margin-bottom: 0.5rem; font-size: 1.8rem; }
    h2 { color: #f0f6fc; margin: 1.5rem 0 0.8rem; font-size: 1.3rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
    .subtitle { color: #8b949e; margin-bottom: 1.5rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1.2rem; margin-bottom: 1rem; }
    .score-big { font-size: 3rem; font-weight: 700; }
    .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.8rem; }
    .stat { flex: 1; min-width: 100px; text-align: center; padding: 0.5rem; border-radius: 4px; background: #21262d; }
    .stat-label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; }
    .stat-value { font-size: 1.3rem; font-weight: 600; }
    table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
    th, td { padding: 0.5rem 0.7rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
    th { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 0.7rem; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
    .badge-pass { background: #238636; color: #fff; }
    .badge-fail { background: #da3633; color: #fff; }
    .badge-unknown { background: #6e7681; color: #fff; }
    .badge-na { background: #30363d; color: #8b949e; }
    .badge-error { background: #bd561d; color: #fff; }
    .severity-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.3rem; }
    footer { margin-top: 2rem; text-align: center; color: #484f58; font-size: 0.75rem; }
</style>
</head>
<body>
<div class="container">
)";

        html << "<h1>&#x1f6e1; ShadowStrike Compliance Report</h1>\n";
        html << "<p class=\"subtitle\">Framework: " << EscapeHtml(ToString(scan.framework))
             << " &bull; Scan ID: " << EscapeHtml(scan.scanId)
             << " &bull; " << TimeToIso8601(scan.startedAt) << "</p>\n";

        // Executive Summary
        const auto score = scan.ComplianceScore();
        std::string scoreColor = score >= 80.0 ? "#238636" : (score >= 50.0 ? "#ffc107" : "#da3633");

        html << "<div class=\"card\">\n";
        html << "  <div class=\"score-big\" style=\"color:" << scoreColor << "\">"
             << std::format("{:.1f}%", score) << "</div>\n";
        html << "  <div class=\"stats\">\n";
        html << "    <div class=\"stat\"><div class=\"stat-value\" style=\"color:#238636\">" << scan.passed << "</div><div class=\"stat-label\">Passed</div></div>\n";
        html << "    <div class=\"stat\"><div class=\"stat-value\" style=\"color:#da3633\">" << scan.failed << "</div><div class=\"stat-label\">Failed</div></div>\n";
        html << "    <div class=\"stat\"><div class=\"stat-value\" style=\"color:#6e7681\">" << scan.unknown << "</div><div class=\"stat-label\">Unknown</div></div>\n";
        html << "    <div class=\"stat\"><div class=\"stat-value\">" << scan.notApplicable << "</div><div class=\"stat-label\">N/A</div></div>\n";
        html << "    <div class=\"stat\"><div class=\"stat-value\" style=\"color:#bd561d\">" << scan.errors << "</div><div class=\"stat-label\">Errors</div></div>\n";
        html << "    <div class=\"stat\"><div class=\"stat-value\">" << scan.totalChecks << "</div><div class=\"stat-label\">Total</div></div>\n";
        html << "  </div>\n</div>\n";

        // Group by category
        std::unordered_map<std::string, std::vector<const ComplianceCheckResult*>> cats;
        for (const auto& r : scan.results) {
            cats[std::string(ToString(r.category))].push_back(&r);
        }

        // Failed checks first
        html << "<h2>&#x274c; Failed Checks</h2>\n";
        html << "<div class=\"card\"><table>\n";
        html << "<tr><th>ID</th><th>Title</th><th>Severity</th><th>Expected</th><th>Actual</th><th>Detail</th></tr>\n";

        uint32_t failCount = 0;
        for (const auto& r : scan.results) {
            if (r.status != CheckStatus::Fail) continue;
            ++failCount;
            html << "<tr><td>" << EscapeHtml(r.checkId) << "</td>"
                 << "<td>" << EscapeHtml(r.title) << "</td>"
                 << "<td><span class=\"severity-dot\" style=\"background:" << SeverityColor(r.severity) << "\"></span>"
                 << EscapeHtml(ToString(r.severity)) << "</td>"
                 << "<td>" << EscapeHtml(r.expectedValue) << "</td>"
                 << "<td>" << EscapeHtml(r.actualValue) << "</td>"
                 << "<td>" << EscapeHtml(r.detail) << "</td></tr>\n";
        }
        if (failCount == 0) {
            html << "<tr><td colspan=\"6\" style=\"text-align:center;color:#238636\">No failed checks!</td></tr>\n";
        }
        html << "</table></div>\n";

        // All checks by category
        for (auto& [catName, catResults] : cats) {
            html << "<h2>" << EscapeHtml(catName) << "</h2>\n";
            html << "<div class=\"card\"><table>\n";
            html << "<tr><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Expected</th><th>Actual</th></tr>\n";
            for (const auto* r : catResults) {
                html << "<tr><td>" << EscapeHtml(r->checkId) << "</td>"
                     << "<td>" << EscapeHtml(r->title) << "</td>"
                     << "<td><span class=\"badge " << StatusBadgeClass(r->status) << "\">"
                     << EscapeHtml(ToString(r->status)) << "</span></td>"
                     << "<td><span class=\"severity-dot\" style=\"background:" << SeverityColor(r->severity) << "\"></span>"
                     << EscapeHtml(ToString(r->severity)) << "</td>"
                     << "<td>" << EscapeHtml(r->expectedValue) << "</td>"
                     << "<td>" << EscapeHtml(r->actualValue) << "</td></tr>\n";
            }
            html << "</table></div>\n";
        }

        html << "<footer>Generated by ShadowStrike Compliance Engine &bull; " << TimeToIso8601(Clock::now()) << "</footer>\n";
        html << "</div></body></html>\n";

        return html.str();
    }

    [[nodiscard]] bool ExportJsonToFile(const ComplianceScanResult& scan, std::string_view path) const {
        auto content = GenerateJsonReport(scan);
        if (!WriteStringToFile(path, content)) {
            Logger::Error("{} Failed to write JSON report to {}", kLogPrefix, path);
            return false;
        }
        Logger::Info("{} JSON report exported to {}", kLogPrefix, path);
        return true;
    }

    [[nodiscard]] bool ExportHtmlToFile(const ComplianceScanResult& scan, std::string_view path) const {
        auto content = GenerateHtmlReport(scan);
        if (!WriteStringToFile(path, content)) {
            Logger::Error("{} Failed to write HTML report to {}", kLogPrefix, path);
            return false;
        }
        Logger::Info("{} HTML report exported to {}", kLogPrefix, path);
        return true;
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

ComplianceReporter::ComplianceReporter() : m_impl(std::make_unique<ComplianceReporterImpl>()) {}
ComplianceReporter::~ComplianceReporter() = default;

ComplianceReporter& ComplianceReporter::Instance() {
    static ComplianceReporter instance;
    return instance;
}

bool ComplianceReporter::Initialize() { return m_impl->Initialize(); }
void ComplianceReporter::Shutdown() { m_impl->Shutdown(); }
bool ComplianceReporter::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
std::string ComplianceReporter::GenerateJsonReport(const ComplianceScanResult& scan) const { return m_impl->GenerateJsonReport(scan); }
std::string ComplianceReporter::GenerateHtmlReport(const ComplianceScanResult& scan) const { return m_impl->GenerateHtmlReport(scan); }
bool ComplianceReporter::ExportJsonToFile(const ComplianceScanResult& scan, std::string_view path) const { return m_impl->ExportJsonToFile(scan, path); }
bool ComplianceReporter::ExportHtmlToFile(const ComplianceScanResult& scan, std::string_view path) const { return m_impl->ExportHtmlToFile(scan, path); }

} // namespace ShadowStrike::Products::PhantomEDR::Compliance
