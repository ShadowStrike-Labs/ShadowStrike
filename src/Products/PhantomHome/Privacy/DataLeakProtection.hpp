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
 * ShadowStrike NGAV - DATA LEAK PROTECTION (DLP) MODULE
 * ============================================================================
 *
 * @file DataLeakProtection.hpp
 * @brief Enterprise-grade Data Loss Prevention with PII detection, content
 *        inspection, and policy-based data egress control.
 *
 * Provides comprehensive DLP capabilities including sensitive data detection,
 * clipboard monitoring, network egress control, and document classification.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. SENSITIVE DATA DETECTION
 *    - Credit card numbers (Luhn validation)
 *    - Social Security Numbers
 *    - IBAN/Bank accounts
 *    - Driver's license numbers
 *    - Passport numbers
 *    - Health records (HIPAA)
 *    - Tax IDs / EIN
 *    - Email addresses
 *    - Phone numbers
 *    - Custom patterns
 *
 * 2. CONTENT INSPECTION
 *    - File scanning
 *    - Network payload analysis
 *    - Clipboard monitoring
 *    - Print job inspection
 *    - Archive content scanning
 *    - Document metadata
 *
 * 3. CHANNEL MONITORING
 *    - HTTP/HTTPS uploads
 *    - Email attachments
 *    - Cloud storage sync
 *    - USB transfers
 *    - Instant messaging
 *    - Remote desktop
 *
 * 4. POLICY ENFORCEMENT
 *    - Block egress
 *    - Encrypt data
 *    - Redact sensitive data
 *    - Alert and log
 *    - User justification
 *    - Manager approval
 *
 * 5. DOCUMENT CLASSIFICATION
 *    - Confidential marking
 *    - Sensitivity labels
 *    - Rights management
 *    - Watermarking
 *
 * INTEGRATION:
 * ============
 * - PatternStore for detection patterns
 * - ThreatIntel for data exfiltration IOCs
 * - Network monitoring for egress control
 *
 * @note GDPR/HIPAA/PCI-DSS compliant.
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
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <regex>
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
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class DataLeakProtectionImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DLPConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum content size to scan
    inline constexpr size_t MAX_CONTENT_SCAN_SIZE = 100 * 1024 * 1024;  // 100MB
    
    /// @brief Clipboard polling interval
    inline constexpr uint32_t CLIPBOARD_POLL_INTERVAL_MS = 500;
    
    /// @brief Match context size (chars before/after)
    inline constexpr size_t MATCH_CONTEXT_SIZE = 50;

    /// @brief Credit card regex patterns
    inline constexpr const char* CC_PATTERNS[] = {
        R"(\b4[0-9]{12}(?:[0-9]{3})?\b)",           // Visa
        R"(\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b)",  // MasterCard
        R"(\b3[47][0-9]{13}\b)",                     // Amex
        R"(\b6(?:011|5[0-9]{2})[0-9]{12}\b)"         // Discover
    };

    /// @brief SSN regex pattern
    inline constexpr const char* SSN_PATTERN = R"(\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b)";
    
    /// @brief IBAN pattern
    inline constexpr const char* IBAN_PATTERN = R"(\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b)";

}  // namespace DLPConstants

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
 * @brief Data category
 */
enum class DataCategory : uint32_t {
    None                = 0,
    CreditCard          = 1 << 0,
    SocialSecurity      = 1 << 1,
    BankAccount         = 1 << 2,
    IBAN                = 1 << 3,
    DriverLicense       = 1 << 4,
    Passport            = 1 << 5,
    HealthRecord        = 1 << 6,  // HIPAA PHI
    TaxID               = 1 << 7,
    DateOfBirth         = 1 << 8,
    PhoneNumber         = 1 << 9,
    EmailAddress        = 1 << 10,
    Address             = 1 << 11,
    IPAddress           = 1 << 12,
    Credentials         = 1 << 13,
    SourceCode          = 1 << 14,
    TradeSecret         = 1 << 15,
    Custom              = 1 << 16,
    All                 = 0xFFFFFFFF
};

/**
 * @brief DLP action
 */
enum class DLPAction : uint8_t {
    Allow           = 0,    ///< Allow operation
    Block           = 1,    ///< Block operation
    Encrypt         = 2,    ///< Encrypt content
    Redact          = 3,    ///< Redact sensitive data
    Alert           = 4,    ///< Alert only
    Justify         = 5,    ///< Require justification
    Approve         = 6,    ///< Require approval
    Quarantine      = 7     ///< Quarantine content
};

/**
 * @brief Channel type
 */
enum class ChannelType : uint8_t {
    Unknown         = 0,
    FileSystem      = 1,
    Network         = 2,
    Email           = 3,
    CloudStorage    = 4,
    USB             = 5,
    Clipboard       = 6,
    Print           = 7,
    Messaging       = 8,
    RemoteDesktop   = 9,
    Browser         = 10
};

/**
 * @brief Severity level
 */
enum class SeverityLevel : uint8_t {
    Info            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Critical        = 4
};

/**
 * @brief Compliance framework
 */
enum class ComplianceFramework : uint8_t {
    None            = 0,
    GDPR            = 1,
    HIPAA           = 2,
    PCIDSS          = 3,
    CCPA            = 4,
    SOX             = 5,
    GLBA            = 6,
    FERPA           = 7,
    Custom          = 8
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief PII pattern rule
 */
struct PIIPattern {
    /// @brief Pattern ID
    std::string patternId;
    
    /// @brief Pattern name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Regex pattern
    std::string regexPattern;
    
    /// @brief Compiled regex
    std::optional<std::regex> compiledRegex;
    
    /// @brief Data category
    DataCategory category = DataCategory::None;
    
    /// @brief Severity
    SeverityLevel severity = SeverityLevel::Medium;
    
    /// @brief Requires validation (Luhn, checksum, etc.)
    bool requiresValidation = false;
    
    /// @brief Validation function name
    std::string validationFunction;
    
    /// @brief Minimum match count to trigger
    int minimumMatchCount = 1;
    
    /// @brief Compliance frameworks
    std::vector<ComplianceFramework> frameworks;
    
    /// @brief Is enabled
    bool enabled = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Sensitive data match
 */
struct SensitiveDataMatch {
    /// @brief Pattern that matched
    PIIPattern pattern;
    
    /// @brief Matched value (partially redacted)
    std::string redactedValue;
    
    /// @brief Full value (for logging/evidence)
    std::string fullValue;
    
    /// @brief Context (surrounding text)
    std::string context;
    
    /// @brief Offset in content
    size_t offset = 0;
    
    /// @brief Length of match
    size_t length = 0;
    
    /// @brief Confidence (0-100)
    int confidence = 0;
    
    /// @brief Validation passed
    bool validationPassed = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result
 */
struct DLPScanResult {
    /// @brief Content hash
    std::string contentHash;
    
    /// @brief Total size scanned
    size_t contentSize = 0;
    
    /// @brief Has sensitive data
    bool hasSensitiveData = false;
    
    /// @brief Match count
    int totalMatches = 0;
    
    /// @brief Categories detected (bitmask)
    DataCategory detectedCategories = DataCategory::None;
    
    /// @brief Highest severity
    SeverityLevel highestSeverity = SeverityLevel::Info;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Matches found
    std::vector<SensitiveDataMatch> matches;
    
    /// @brief Recommended action
    DLPAction recommendedAction = DLPAction::Allow;
    
    /// @brief Compliance violations
    std::vector<ComplianceFramework> complianceViolations;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] bool ShouldBlock() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DLP policy
 */
struct DLPPolicy {
    /// @brief Policy ID
    std::string policyId;
    
    /// @brief Policy name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Categories to monitor
    DataCategory monitoredCategories = DataCategory::All;
    
    /// @brief Channels to monitor
    std::vector<ChannelType> monitoredChannels;
    
    /// @brief Action on detection
    DLPAction action = DLPAction::Alert;
    
    /// @brief Minimum severity to trigger
    SeverityLevel minimumSeverity = SeverityLevel::Medium;
    
    /// @brief Excluded users
    std::vector<std::string> excludedUsers;
    
    /// @brief Excluded processes
    std::vector<std::string> excludedProcesses;
    
    /// @brief Excluded domains
    std::vector<std::string> excludedDomains;
    
    /// @brief Applied file patterns
    std::vector<std::string> filePatterns;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DLP incident
 */
struct DLPIncident {
    /// @brief Incident ID
    std::string incidentId;
    
    /// @brief Policy that triggered
    std::string policyId;
    
    /// @brief User
    std::string userName;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Channel
    ChannelType channel = ChannelType::Unknown;
    
    /// @brief Destination (URL, path, etc.)
    std::string destination;
    
    /// @brief File path (if applicable)
    fs::path filePath;
    
    /// @brief Scan result
    DLPScanResult scanResult;
    
    /// @brief Action taken
    DLPAction actionTaken = DLPAction::Allow;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief User justification (if any)
    std::string userJustification;
    
    /// @brief Manager approval
    std::optional<bool> managerApproval;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct DLPStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> sensitiveDataFound{0};
    std::atomic<uint64_t> operationsBlocked{0};
    std::atomic<uint64_t> operationsAllowed{0};
    std::atomic<uint64_t> incidentsLogged{0};
    std::atomic<uint64_t> bytesScanned{0};
    std::atomic<uint64_t> clipboardBlocks{0};
    std::atomic<uint64_t> networkBlocks{0};
    std::atomic<uint64_t> fileBlocks{0};
    std::atomic<uint64_t> creditCardsDetected{0};
    std::atomic<uint64_t> ssnDetected{0};
    std::atomic<uint64_t> piiDetected{0};
    std::array<std::atomic<uint64_t>, 32> byCategory{};
    std::array<std::atomic<uint64_t>, 16> byChannel{};
    std::array<std::atomic<uint64_t>, 8> bySeverity{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct DLPConfiguration {
    /// @brief Enable DLP
    bool enabled = true;
    
    /// @brief Enable clipboard monitoring
    bool monitorClipboard = true;
    
    /// @brief Enable network monitoring
    bool monitorNetwork = true;
    
    /// @brief Enable file monitoring
    bool monitorFiles = true;
    
    /// @brief Enable print monitoring
    bool monitorPrint = false;
    
    /// @brief Enable USB monitoring
    bool monitorUSB = true;
    
    /// @brief Monitor browser uploads
    bool monitorBrowserUploads = true;
    
    /// @brief Categories to monitor
    DataCategory monitoredCategories = DataCategory::All;
    
    /// @brief Default action
    DLPAction defaultAction = DLPAction::Alert;
    
    /// @brief Maximum content size
    size_t maxContentSize = DLPConstants::MAX_CONTENT_SCAN_SIZE;
    
    /// @brief Custom patterns
    std::vector<PIIPattern> customPatterns;
    
    /// @brief Policies
    std::vector<DLPPolicy> policies;
    
    /// @brief Excluded file extensions
    std::vector<std::string> excludedExtensions;
    
    /// @brief Excluded paths
    std::vector<std::string> excludedPaths;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const DLPScanResult&)>;
using IncidentCallback = std::function<void(const DLPIncident&)>;
using PolicyViolationCallback = std::function<void(const DLPPolicy&, const DLPScanResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

/// @brief Pre-egress callback (return false to block)
using PreEgressCallback = std::function<bool(const DLPScanResult&, ChannelType)>;

// ============================================================================
// DATA LEAK PROTECTION CLASS
// ============================================================================

/**
 * @class DataLeakProtection
 * @brief Enterprise Data Loss Prevention engine
 */
class DataLeakProtection final {
public:
    [[nodiscard]] static DataLeakProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    DataLeakProtection(const DataLeakProtection&) = delete;
    DataLeakProtection& operator=(const DataLeakProtection&) = delete;
    DataLeakProtection(DataLeakProtection&&) = delete;
    DataLeakProtection& operator=(DataLeakProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const DLPConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const DLPConfiguration& config);
    [[nodiscard]] DLPConfiguration GetConfiguration() const;

    // ========================================================================
    // CONTENT SCANNING
    // ========================================================================
    
    /// @brief Scan buffer for sensitive data
    [[nodiscard]] DLPScanResult ScanBuffer(const std::vector<uint8_t>& buffer);
    
    /// @brief Scan string for sensitive data
    [[nodiscard]] DLPScanResult ScanString(const std::string& content);
    
    /// @brief Scan file for sensitive data
    [[nodiscard]] DLPScanResult ScanFile(const fs::path& filePath);
    
    /// @brief Scan clipboard content
    [[nodiscard]] DLPScanResult ScanClipboard();
    
    /// @brief Check if content has sensitive data (quick check)
    [[nodiscard]] bool HasSensitiveData(const std::string& content);

    // ========================================================================
    // EGRESS CONTROL
    // ========================================================================
    
    /// @brief Analyze outbound data
    [[nodiscard]] DLPScanResult AnalyzeOutboundData(
        const std::vector<uint8_t>& data,
        ChannelType channel = ChannelType::Network,
        const std::string& destination = "");
    
    /// @brief Check if upload should be blocked
    [[nodiscard]] bool ShouldBlockUpload(
        const fs::path& filePath,
        const std::string& destination);
    
    /// @brief Evaluate against policies
    [[nodiscard]] DLPAction EvaluatePolicies(
        const DLPScanResult& scanResult,
        ChannelType channel,
        const std::string& user = "");

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Start clipboard monitoring
    [[nodiscard]] bool StartClipboardMonitoring();
    
    /// @brief Stop clipboard monitoring
    void StopClipboardMonitoring();
    
    /// @brief Is clipboard monitoring active
    [[nodiscard]] bool IsClipboardMonitoringActive() const noexcept;

    // ========================================================================
    // PATTERNS & POLICIES
    // ========================================================================
    
    /// @brief Add custom pattern
    [[nodiscard]] bool AddPattern(const PIIPattern& pattern);
    
    /// @brief Remove pattern
    [[nodiscard]] bool RemovePattern(const std::string& patternId);
    
    /// @brief Get all patterns
    [[nodiscard]] std::vector<PIIPattern> GetPatterns() const;
    
    /// @brief Add policy
    [[nodiscard]] bool AddPolicy(const DLPPolicy& policy);
    
    /// @brief Remove policy
    [[nodiscard]] bool RemovePolicy(const std::string& policyId);
    
    /// @brief Get all policies
    [[nodiscard]] std::vector<DLPPolicy> GetPolicies() const;

    // ========================================================================
    // VALIDATION
    // ========================================================================
    
    /// @brief Validate credit card number (Luhn)
    [[nodiscard]] bool ValidateCreditCard(const std::string& number);
    
    /// @brief Validate SSN format
    [[nodiscard]] bool ValidateSSN(const std::string& ssn);
    
    /// @brief Validate IBAN
    [[nodiscard]] bool ValidateIBAN(const std::string& iban);

    // ========================================================================
    // REDACTION
    // ========================================================================
    
    /// @brief Redact sensitive data from content
    [[nodiscard]] std::string RedactContent(const std::string& content);
    
    /// @brief Get redacted version of a match
    [[nodiscard]] std::string RedactValue(
        const std::string& value,
        DataCategory category);

    // ========================================================================
    // INCIDENTS
    // ========================================================================
    
    /// @brief Get recent incidents
    [[nodiscard]] std::vector<DLPIncident> GetRecentIncidents(
        size_t limit = 100,
        std::optional<SystemTimePoint> since = std::nullopt);
    
    /// @brief Get incident by ID
    [[nodiscard]] std::optional<DLPIncident> GetIncident(const std::string& incidentId);
    
    /// @brief Report incident
    void ReportIncident(const DLPIncident& incident);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterIncidentCallback(IncidentCallback callback);
    void RegisterPolicyCallback(PolicyViolationCallback callback);
    void RegisterPreEgressCallback(PreEgressCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] DLPStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DataLeakProtection();
    ~DataLeakProtection();
    
    std::unique_ptr<DataLeakProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDataCategoryName(DataCategory category) noexcept;
[[nodiscard]] std::string_view GetDLPActionName(DLPAction action) noexcept;
[[nodiscard]] std::string_view GetChannelTypeName(ChannelType channel) noexcept;
[[nodiscard]] std::string_view GetSeverityLevelName(SeverityLevel severity) noexcept;
[[nodiscard]] std::string_view GetComplianceFrameworkName(ComplianceFramework framework) noexcept;

/// @brief Luhn algorithm validation
[[nodiscard]] bool LuhnCheck(const std::string& number);

/// @brief IBAN checksum validation
[[nodiscard]] bool IBANCheck(const std::string& iban);

/// @brief Mask credit card number
[[nodiscard]] std::string MaskCreditCard(const std::string& number);

/// @brief Mask SSN
[[nodiscard]] std::string MaskSSN(const std::string& ssn);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_DLP_SCAN_BUFFER(buffer) \
    ::ShadowStrike::Privacy::DataLeakProtection::Instance().ScanBuffer(buffer)

#define SS_DLP_SCAN_FILE(path) \
    ::ShadowStrike::Privacy::DataLeakProtection::Instance().ScanFile(path)

#define SS_DLP_HAS_SENSITIVE(content) \
    ::ShadowStrike::Privacy::DataLeakProtection::Instance().HasSensitiveData(content)

#define SS_DLP_REDACT(content) \
    ::ShadowStrike::Privacy::DataLeakProtection::Instance().RedactContent(content)
