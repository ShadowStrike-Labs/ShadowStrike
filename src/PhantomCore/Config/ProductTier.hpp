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
 * ShadowStrike NGAV - PRODUCT TIER & FEATURE FLAG MODULE
 * ============================================================================
 *
 * @file ProductTier.hpp
 * @brief Enterprise product tier management and feature flag gating system
 *        for the ShadowStrike NGAV/EDR/XDR platform.
 *
 * Manages three product tiers (Community, Professional, Enterprise) and
 * provides O(1) feature flag lookups used across every detection engine,
 * API route, and UI check in the platform.
 *
 * PRODUCT TIER ARCHITECTURE:
 * ==========================
 *
 * 1. TIERED FEATURE GATING
 *    - Community (free, open-source): Core detection, RTP, behavioral, AI,
 *      localhost dashboard, basic forensics, basic threat intel
 *    - Professional: Cloud console, EDR, fleet management, remote
 *      actions, signed kernel driver, advanced threat intel
 *    - Enterprise: SIEM/SOAR integration, XDR correlation, compliance
 *      reporting, RBAC/SSO, custom rules, cloud telemetry
 *
 * 2. HOT-PATH FEATURE CHECKS
 *    - Pre-computed boolean array indexed by FeatureCategory
 *    - O(1) lookup with zero allocation and no lock contention
 *    - Atomically swapped on tier/license changes
 *
 * 3. LICENSE VALIDATION
 *    - RSA-PSS-SHA256 signature verification via CryptoUtils
 *    - Compile-time embedded issuer public key
 *    - Tamper detection and expiration enforcement
 *    - Graceful degradation to Community tier on failure
 *
 * 4. ADMIN OVERRIDES
 *    - Per-feature enable/disable for debugging and testing
 *    - All overrides logged via SS_LOG_WARN for audit trail
 *    - Cleared on shutdown or explicit reset
 *
 * 5. COMMUNITY-FIRST DESIGN
 *    - No license required for Community tier
 *    - No nag screens, no degradation, no artificial limits
 *    - Full core protection always available
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: AGPL-3.0-or-later
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Config {
    class ProductTierManagerImpl;
}

namespace ShadowStrike {
namespace Config {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TierConstants {

    /// @brief Module version
    inline constexpr uint32_t VERSION_MAJOR = 1;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Total number of feature categories (must match FeatureCategory enum count)
    inline constexpr size_t FEATURE_CATEGORY_COUNT = 18;

    /// @brief Maximum license ID length in bytes
    inline constexpr size_t MAX_LICENSE_ID_LENGTH = 128;

    /// @brief Maximum organization name length in bytes
    inline constexpr size_t MAX_ORGANIZATION_NAME_LENGTH = 256;

    /// @brief Maximum license signature size in bytes
    inline constexpr size_t MAX_SIGNATURE_SIZE = 512;

    /// @brief Maximum additional feature addons per license
    inline constexpr size_t MAX_ADDITIONAL_FEATURES = 32;

    /// @brief Maximum supported endpoints for Community tier
    inline constexpr uint32_t COMMUNITY_MAX_ENDPOINTS = 1;

    /// @brief Default license expiration warning threshold in days
    inline constexpr uint32_t DEFAULT_EXPIRY_WARNING_DAYS = 30;

    /// @brief License format version
    inline constexpr uint32_t CURRENT_LICENSE_VERSION = 1;

}  // namespace TierConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Product tier levels for the ShadowStrike platform.
 *
 * Each tier unlocks progressively more features. Community is the default
 * when no valid license is present and provides full core protection.
 */
enum class ProductTier : uint8_t {
    Community       = 0,    ///< Free, open-source, localhost dashboard
    Professional    = 1,    ///< Signed driver, cloud console, EDR
    Enterprise      = 2     ///< SIEM, SOAR, XDR, compliance
};

/**
 * @brief Feature categories gated by product tier.
 *
 * Each category maps to a set of related capabilities. Feature checks are
 * resolved to a pre-computed boolean array for O(1) hot-path lookups.
 * The enum values are used as array indices — do not reorder or remove
 * entries without updating FEATURE_CATEGORY_COUNT.
 */
enum class FeatureCategory : uint8_t {
    Core                = 0,    ///< Always available: scan, RTP, behavioral, AI
    HomeProtection      = 1,    ///< Banking, email, USB, IoT, privacy, gaming
    ForensicsBasic      = 2,    ///< Basic timeline, basic artifact extraction
    ForensicsAdvanced   = 3,    ///< Full forensics: memory dump, network capture, evidence
    ThreatIntel         = 4,    ///< Basic threat intel feeds (public)
    ThreatIntelAdvanced = 5,    ///< Priority feeds, advanced IOC management
    Dashboard           = 6,    ///< Localhost web dashboard
    CloudConsole        = 7,    ///< Cloud management console
    FleetManagement     = 8,    ///< Multi-endpoint management
    RemoteActions       = 9,    ///< Remote scan/quarantine/isolate
    SIEMIntegration     = 10,   ///< Splunk/Elastic/Sentinel/QRadar connectors
    SOARIntegration     = 11,   ///< Playbook trigger, enrichment, actions
    ComplianceReporting = 12,   ///< PCI-DSS, HIPAA, SOC2, ISO27001 templates
    CustomRules         = 13,   ///< Custom detection rules editor
    RBAC                = 14,   ///< Role-based access control + SSO
    XDRCorrelation      = 15,   ///< Cross-source event correlation
    CloudTelemetry      = 16,   ///< Cloud telemetry aggregation
    KernelProtection    = 17    ///< Signed kernel driver (requires EV cert)
};

/**
 * @brief License validation status.
 *
 * Returned by ValidateLicense() to indicate the current state of the
 * loaded license. Any status other than Valid causes fallback to
 * Community tier.
 */
enum class LicenseStatus : uint8_t {
    Valid               = 0,    ///< License is valid and active
    Expired             = 1,    ///< License has passed its expiration date
    Invalid             = 2,    ///< License data is malformed or unreadable
    Tampered            = 3,    ///< Signature verification failed
    NotFound            = 4,    ///< No license file found at expected path
    CommunityDefault    = 5     ///< No license needed — running as Community
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief License information loaded from a signed license file.
 *
 * Contains the decoded and verified license payload. The signature field
 * holds the RSA-PSS-SHA256 signature over the serialized license payload
 * (excluding the signature field itself).
 */
struct LicenseInfo {
    /// @brief Unique license identifier (UUID format)
    std::string licenseId;

    /// @brief Licensed product tier
    ProductTier tier = ProductTier::Community;

    /// @brief Organization name (display purposes)
    std::string organizationName;

    /// @brief Organization identifier (for fleet association)
    std::string organizationId;

    /// @brief Maximum endpoints covered by this license
    uint32_t maxEndpoints = TierConstants::COMMUNITY_MAX_ENDPOINTS;

    /// @brief Timestamp when the license was issued
    std::chrono::system_clock::time_point issuedAt;

    /// @brief Timestamp when the license expires
    std::chrono::system_clock::time_point expiresAt;

    /// @brief Feature categories granted as addons beyond the base tier
    std::vector<FeatureCategory> additionalFeatures;

    /// @brief RSA-PSS-SHA256 signature over the license payload
    std::vector<uint8_t> signature;

    /// @brief License format version for forward compatibility
    uint32_t version = TierConstants::CURRENT_LICENSE_VERSION;
};

/**
 * @brief Resolved feature information including display metadata.
 *
 * Represents the current resolved state of a single feature category,
 * combining tier-based availability with any active admin overrides.
 */
struct FeatureInfo {
    /// @brief The feature category this info describes
    FeatureCategory category = FeatureCategory::Core;

    /// @brief Human-readable feature name for UI display
    std::wstring displayName;

    /// @brief Human-readable feature description for UI display
    std::wstring description;

    /// @brief Minimum product tier required to unlock this feature
    ProductTier minimumTier = ProductTier::Community;

    /// @brief Current resolved enabled state (tier + overrides)
    bool isEnabled = false;

    /// @brief Whether an admin override is currently active for this feature
    bool isOverridden = false;
};

/**
 * @brief Atomic statistics for tier and license operations.
 *
 * All counters are atomic for lock-free concurrent updates from
 * multiple threads. Copy/move constructors perform relaxed loads
 * to avoid contention on diagnostic reads.
 */
struct TierStatistics {
    /// @brief Total IsFeatureEnabled / IsFeatureAvailable calls
    std::atomic<uint64_t> featureChecks{0};

    /// @brief Feature checks that returned false (feature denied)
    std::atomic<uint64_t> featureDenials{0};

    /// @brief Total license validation attempts
    std::atomic<uint64_t> licenseValidations{0};

    /// @brief License validations that failed
    std::atomic<uint64_t> licenseFailures{0};

    /// @brief Timestamp when statistics collection began
    TimePoint startTime = Clock::now();

    TierStatistics() = default;

    TierStatistics(const TierStatistics& other) noexcept
        : featureChecks(other.featureChecks.load(std::memory_order_relaxed))
        , featureDenials(other.featureDenials.load(std::memory_order_relaxed))
        , licenseValidations(other.licenseValidations.load(std::memory_order_relaxed))
        , licenseFailures(other.licenseFailures.load(std::memory_order_relaxed))
        , startTime(other.startTime) {}

    TierStatistics& operator=(const TierStatistics& other) noexcept {
        if (this != &other) {
            featureChecks.store(other.featureChecks.load(std::memory_order_relaxed),
                               std::memory_order_relaxed);
            featureDenials.store(other.featureDenials.load(std::memory_order_relaxed),
                                std::memory_order_relaxed);
            licenseValidations.store(other.licenseValidations.load(std::memory_order_relaxed),
                                    std::memory_order_relaxed);
            licenseFailures.store(other.licenseFailures.load(std::memory_order_relaxed),
                                 std::memory_order_relaxed);
            startTime = other.startTime;
        }
        return *this;
    }

    /// @brief Reset all counters to zero and restart the clock
    void Reset() noexcept {
        featureChecks.store(0, std::memory_order_relaxed);
        featureDenials.store(0, std::memory_order_relaxed);
        licenseValidations.store(0, std::memory_order_relaxed);
        licenseFailures.store(0, std::memory_order_relaxed);
        startTime = Clock::now();
    }
};

// ============================================================================
// PRODUCT TIER MANAGER CLASS
// ============================================================================

/**
 * @class ProductTierManager
 * @brief Singleton manager for product tier resolution and feature flag gating.
 *
 * Provides the authoritative answer to "is feature X enabled?" for every
 * component in the ShadowStrike platform. Feature checks are the hottest
 * path in the system — called from detection engines, API routes, and UI
 * code on every operation.
 *
 * DESIGN INVARIANTS:
 * - IsFeatureEnabled() is O(1): pre-computed array lookup, no allocation, no lock
 * - Community tier is always the safe default — no license required
 * - All admin overrides are logged for audit compliance
 * - License validation uses RSA-PSS-SHA256 with a compile-time embedded public key
 * - Tier changes atomically recompute the entire feature flag array
 */
class ProductTierManager final {
public:
    // ========================================================================
    // SINGLETON
    // ========================================================================

    /// @brief Get the singleton instance (Meyers' pattern, thread-safe).
    [[nodiscard]] static ProductTierManager& Instance() noexcept;

    /// @brief Check whether the singleton has been instantiated.
    [[nodiscard]] static bool HasInstance() noexcept;

    ProductTierManager(const ProductTierManager&) = delete;
    ProductTierManager& operator=(const ProductTierManager&) = delete;
    ProductTierManager(ProductTierManager&&) = delete;
    ProductTierManager& operator=(ProductTierManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /// @brief Initialize the tier manager, loading license from ConfigurationDB.
    /// @param configDbPath Optional path to the configuration database.
    ///        If empty, uses the default path from ConfigManager.
    /// @return true if initialization succeeded; false on critical failure.
    [[nodiscard]] bool Initialize(const std::wstring& configDbPath = L"") noexcept;

    /// @brief Shut down the tier manager and release resources.
    void Shutdown() noexcept;

    /// @brief Check whether the manager has been initialized.
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ========================================================================
    // TIER QUERIES
    // ========================================================================

    /// @brief Get the currently active product tier.
    [[nodiscard]] ProductTier GetCurrentTier() const noexcept;

    /// @brief Get the internal name of the current tier (e.g., L"Community").
    [[nodiscard]] std::wstring_view GetTierName() const noexcept;

    /// @brief Get the user-facing display name (e.g., L"Phantom Community").
    [[nodiscard]] std::wstring_view GetTierDisplayName() const noexcept;

    // ========================================================================
    // FEATURE FLAG QUERIES (HOT PATH)
    // ========================================================================

    /// @brief Check if a feature is currently enabled (tier + overrides).
    /// @details This is the primary hot-path call. O(1) lookup into a
    ///          pre-computed boolean array. No allocation, no lock.
    /// @param feature The feature category to check.
    /// @return true if the feature is enabled for the current tier/overrides.
    [[nodiscard]] bool IsFeatureEnabled(FeatureCategory feature) const noexcept;

    /// @brief Check if a feature is available for the current tier,
    ///        ignoring any admin overrides.
    /// @param feature The feature category to check.
    /// @return true if the feature's minimum tier <= current tier.
    [[nodiscard]] bool IsFeatureAvailable(FeatureCategory feature) const noexcept;

    /// @brief Get full metadata for a single feature category.
    /// @param feature The feature category to query.
    /// @return FeatureInfo with resolved state and display metadata.
    [[nodiscard]] FeatureInfo GetFeatureInfo(FeatureCategory feature) const noexcept;

    /// @brief Get metadata for all feature categories.
    /// @return Vector of FeatureInfo for every defined feature.
    [[nodiscard]] std::vector<FeatureInfo> GetAllFeatures() const noexcept;

    /// @brief Get all currently enabled feature categories.
    /// @return Vector of FeatureCategory values whose resolved state is enabled.
    [[nodiscard]] std::vector<FeatureCategory> GetEnabledFeatures() const noexcept;

    /// @brief Get all currently disabled feature categories.
    /// @return Vector of FeatureCategory values whose resolved state is disabled.
    [[nodiscard]] std::vector<FeatureCategory> GetDisabledFeatures() const noexcept;

    // ========================================================================
    // LICENSE MANAGEMENT
    // ========================================================================

    /// @brief Load and validate a license from a file on disk.
    /// @param licensePath Absolute path to the signed license file.
    /// @return true if the license was loaded, verified, and applied.
    [[nodiscard]] bool LoadLicense(const std::wstring& licensePath) noexcept;

    /// @brief Activate a license using an online license key.
    /// @param licenseKey The license key string to activate.
    /// @return true if activation succeeded and the tier was updated.
    [[nodiscard]] bool ActivateLicense(std::string_view licenseKey) noexcept;

    /// @brief Validate the currently loaded license.
    /// @return LicenseStatus indicating the validation result.
    [[nodiscard]] LicenseStatus ValidateLicense() const noexcept;

    /// @brief Get the current license information.
    /// @return Const reference to the active LicenseInfo.
    [[nodiscard]] const LicenseInfo& GetLicenseInfo() const noexcept;

    /// @brief Check whether the current license is valid and active.
    /// @return true if ValidateLicense() would return LicenseStatus::Valid.
    [[nodiscard]] bool IsLicenseValid() const noexcept;

    /// @brief Check whether the license is expiring within a threshold.
    /// @param daysThreshold Number of days to consider "soon" (default: 30).
    /// @return true if the license expires within daysThreshold days.
    [[nodiscard]] bool IsLicenseExpiringSoon(
        uint32_t daysThreshold = TierConstants::DEFAULT_EXPIRY_WARNING_DAYS) const noexcept;

    // ========================================================================
    // ADMIN OVERRIDES (AUDITED)
    // ========================================================================

    /// @brief Override a feature's enabled state for debugging/testing.
    /// @details Logged via SS_LOG_WARN for audit trail. Does not persist
    ///          across restarts unless explicitly saved.
    /// @param feature The feature category to override.
    /// @param enabled The desired enabled state.
    /// @return true if the override was applied successfully.
    bool OverrideFeature(FeatureCategory feature, bool enabled) noexcept;

    /// @brief Clear an active override for a specific feature.
    /// @param feature The feature category to restore to tier-based state.
    /// @return true if an override existed and was cleared.
    bool ClearOverride(FeatureCategory feature) noexcept;

    /// @brief Clear all active feature overrides.
    void ClearAllOverrides() noexcept;

    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    /// @brief Get a snapshot of the current tier statistics.
    [[nodiscard]] TierStatistics GetStatistics() const noexcept;

    /// @brief Reset all statistics counters to zero.
    void ResetStatistics() noexcept;

    // ========================================================================
    // STATIC UTILITIES
    // ========================================================================

    /// @brief Convert a ProductTier enum to its string representation.
    /// @param tier The tier to convert.
    /// @return Wide string view of the tier name (e.g., L"Community").
    [[nodiscard]] static std::wstring_view TierToString(ProductTier tier) noexcept;

    /// @brief Convert a FeatureCategory enum to its string representation.
    /// @param cat The feature category to convert.
    /// @return Wide string view of the category name (e.g., L"Core").
    [[nodiscard]] static std::wstring_view FeatureCategoryToString(FeatureCategory cat) noexcept;

    /// @brief Get the minimum tier required for a given feature category.
    /// @param feature The feature category to query.
    /// @return The lowest ProductTier that includes this feature.
    [[nodiscard]] static ProductTier GetMinimumTierForFeature(FeatureCategory feature) noexcept;

private:
    ProductTierManager() noexcept;
    ~ProductTierManager() noexcept;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// @brief Convert a LicenseStatus enum to a human-readable string.
[[nodiscard]] std::wstring_view LicenseStatusToString(LicenseStatus status) noexcept;

/// @brief Convert a ProductTier enum to a human-readable display name.
[[nodiscard]] std::wstring_view ProductTierToDisplayName(ProductTier tier) noexcept;

}  // namespace Config
}  // namespace ShadowStrike

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

/// @brief Quick feature-enabled check — use in hot paths and conditionals.
#define SS_FEATURE_ENABLED(feature) \
    (::ShadowStrike::Config::ProductTierManager::Instance().IsFeatureEnabled( \
        ::ShadowStrike::Config::FeatureCategory::feature))

/// @brief Quick tier check — returns the current ProductTier enum value.
#define SS_CURRENT_TIER() \
    (::ShadowStrike::Config::ProductTierManager::Instance().GetCurrentTier())
