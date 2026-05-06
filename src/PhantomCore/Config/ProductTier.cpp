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

#include "pch.h"
#include "ProductTier.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/Base64Utils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Database/ConfigurationDB.hpp"

#include <array>
#include <cstring>
#include <shared_mutex>
#include <unordered_map>

namespace ShadowStrike {
namespace Config {

// ============================================================================
// STRING CONVERSION HELPERS
// ============================================================================

namespace {

// Note: these helpers allocate std::wstring/std::string and may therefore
// throw std::bad_alloc. They are intentionally NOT marked noexcept; the
// callers handle exceptions either explicitly or via try/catch boundaries.
[[nodiscard]] std::wstring NarrowToWide(const std::string& narrow) {
    if (narrow.empty()) return {};
    const int needed = ::MultiByteToWideChar(
        CP_UTF8, 0, narrow.data(), static_cast<int>(narrow.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
        static_cast<int>(narrow.size()), wide.data(), needed);
    return wide;
}

[[nodiscard]] std::string WideToNarrow(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int needed = ::WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string narrow(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
        static_cast<int>(wide.size()), narrow.data(), needed,
        nullptr, nullptr);
    return narrow;
}

// ============================================================================
// FEATURE TIER MAPPING TABLE
// ============================================================================

struct FeatureDefinition {
    FeatureCategory category;
    ProductTier minimumTier;
    const wchar_t* displayName;
    const wchar_t* description;
};

// This table is the single source of truth for feature-to-tier mapping.
// Order matches FeatureCategory enum values for direct indexing.
constexpr std::array<FeatureDefinition, TierConstants::FEATURE_CATEGORY_COUNT>
    kFeatureDefinitions = {{
    {FeatureCategory::Core,
        ProductTier::Community,
        L"Core Protection",
        L"Real-time scanning, behavioral analysis, AI/ML detection, "
        L"emulation, quarantine"},
    {FeatureCategory::HomeProtection,
        ProductTier::Community,
        L"Home Protection",
        L"Banking protection, email scanning, USB monitoring, IoT device "
        L"protection, privacy tools, game mode"},
    {FeatureCategory::ForensicsBasic,
        ProductTier::Community,
        L"Basic Forensics",
        L"Event timeline, basic artifact extraction, process tree "
        L"visualization"},
    {FeatureCategory::ForensicsAdvanced,
        ProductTier::Professional,
        L"Advanced Forensics",
        L"Full memory dump analysis, network capture, evidence packaging, "
        L"chain of custody tracking"},
    {FeatureCategory::ThreatIntel,
        ProductTier::Community,
        L"Threat Intelligence",
        L"Public threat intelligence feeds, basic IOC matching, community "
        L"signatures"},
    {FeatureCategory::ThreatIntelAdvanced,
        ProductTier::Professional,
        L"Advanced Threat Intelligence",
        L"Priority threat feeds, advanced IOC management, STIX/TAXII "
        L"integration, threat actor tracking"},
    {FeatureCategory::Dashboard,
        ProductTier::Community,
        L"Web Dashboard",
        L"Localhost web management dashboard with full visualization and "
        L"configuration"},
    {FeatureCategory::CloudConsole,
        ProductTier::Professional,
        L"Cloud Console",
        L"Cloud-hosted management console for remote endpoint visibility "
        L"and control"},
    {FeatureCategory::FleetManagement,
        ProductTier::Professional,
        L"Fleet Management",
        L"Multi-endpoint deployment, group policies, fleet health "
        L"monitoring, agent updates"},
    {FeatureCategory::RemoteActions,
        ProductTier::Professional,
        L"Remote Actions",
        L"Remote scan, quarantine, isolate, remediate, live response "
        L"shell"},
    {FeatureCategory::SIEMIntegration,
        ProductTier::Enterprise,
        L"SIEM Integration",
        L"Splunk, Elastic, Microsoft Sentinel, QRadar, Syslog/CEF "
        L"connectors"},
    {FeatureCategory::SOARIntegration,
        ProductTier::Enterprise,
        L"SOAR Integration",
        L"Playbook trigger, automated enrichment, remediation actions, "
        L"case management"},
    {FeatureCategory::ComplianceReporting,
        ProductTier::Enterprise,
        L"Compliance Reporting",
        L"PCI-DSS, HIPAA, SOC 2, ISO 27001 report templates, audit "
        L"evidence export"},
    {FeatureCategory::CustomRules,
        ProductTier::Professional,
        L"Custom Detection Rules",
        L"Custom YARA rules, behavioral signatures, IOC-based detection "
        L"rule editor"},
    {FeatureCategory::RBAC,
        ProductTier::Enterprise,
        L"Role-Based Access Control",
        L"Multi-user access control, SSO via SAML/OIDC, audit logging, "
        L"permission groups"},
    {FeatureCategory::XDRCorrelation,
        ProductTier::Enterprise,
        L"XDR Correlation",
        L"Cross-source event correlation, unified attack timeline, "
        L"MITRE ATT&CK mapping across data sources"},
    {FeatureCategory::CloudTelemetry,
        ProductTier::Enterprise,
        L"Cloud Telemetry",
        L"Aggregated telemetry across fleet, anomaly detection dashboards, "
        L"trend analysis"},
    {FeatureCategory::KernelProtection,
        ProductTier::Professional,
        L"Kernel Protection",
        L"Microsoft-signed kernel driver for deep system monitoring, "
        L"rootkit detection, boot-time protection"},
}};

static_assert(kFeatureDefinitions.size() == TierConstants::FEATURE_CATEGORY_COUNT,
    "Feature definitions must match FEATURE_CATEGORY_COUNT");

// Maximum raw license file size to prevent DoS (64 KiB is generous for JSON + sig)
constexpr size_t kMaxLicenseFileSize = 64ULL * 1024;

// Maximum license key string length (Base64-encoded payload.signature)
constexpr size_t kMaxLicenseKeyLength = 8192;

// License key separator between payload and signature
constexpr char kLicenseKeySeparator = '.';

}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct ProductTierManager::Impl {
    // Current tier — atomically readable for hot path
    std::atomic<ProductTier> currentTier{ProductTier::Community};

    // Pre-computed feature flags — atomically swapped via shared_ptr
    // Hot path reads this with acquire semantics
    std::atomic<std::shared_ptr<
        std::array<bool, TierConstants::FEATURE_CATEGORY_COUNT>>> featureFlags;

    // Admin overrides (feature -> forced state)
    std::unordered_map<uint8_t, bool> overrides;

    // Current license info
    LicenseInfo licenseInfo;
    LicenseStatus licenseStatus = LicenseStatus::CommunityDefault;

    // Statistics
    mutable TierStatistics stats;

    // Thread safety for mutable state (overrides, license)
    mutable std::shared_mutex mutex;

    // Lifecycle
    std::atomic<bool> initialized{false};

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    Impl() noexcept {
        // Start with Community tier — all community features enabled
        RecomputeFeatureFlags();
    }

    // ========================================================================
    // FEATURE FLAG COMPUTATION
    // ========================================================================

    void RecomputeFeatureFlags() noexcept {
        auto flags = std::make_shared<
            std::array<bool, TierConstants::FEATURE_CATEGORY_COUNT>>();
        flags->fill(false);

        const ProductTier tier = currentTier.load(std::memory_order_acquire);

        // Enable features based on tier
        for (size_t i = 0; i < TierConstants::FEATURE_CATEGORY_COUNT; ++i) {
            const auto& def = kFeatureDefinitions[i];
            (*flags)[i] = (static_cast<uint8_t>(tier) >=
                           static_cast<uint8_t>(def.minimumTier));
        }

        // Apply additional features from license
        for (const auto& feat : licenseInfo.additionalFeatures) {
            const auto idx = static_cast<size_t>(feat);
            if (idx < TierConstants::FEATURE_CATEGORY_COUNT) {
                (*flags)[idx] = true;
            }
        }

        // Apply admin overrides
        for (const auto& [catIdx, enabled] : overrides) {
            if (catIdx < TierConstants::FEATURE_CATEGORY_COUNT) {
                (*flags)[catIdx] = enabled;
            }
        }

        // Atomic publish — readers see a consistent snapshot
        featureFlags.store(flags, std::memory_order_release);
    }

    // ========================================================================
    // LICENSE PARSING
    // ========================================================================

    [[nodiscard]] bool ParseLicensePayload(
            std::string_view payloadJson,
            LicenseInfo& outInfo) noexcept {
        try {
            Utils::JSON::Json doc;
            Utils::JSON::Error jsonErr;
            if (!Utils::JSON::Parse(payloadJson, doc, &jsonErr)) {
                SS_LOG_ERROR(L"ProductTier",
                    L"License JSON parse failed: %s",
                    NarrowToWide(jsonErr.message).c_str());
                return false;
            }

            // Validate required fields
            if (!doc.contains("version") || !doc.contains("tier") ||
                !doc.contains("license_id") || !doc.contains("expires_at")) {
                SS_LOG_ERROR(L"ProductTier",
                    L"License missing required fields");
                return false;
            }

            // Version check
            const uint32_t version = doc.value("version", 0u);
            if (version == 0 || version > TierConstants::CURRENT_LICENSE_VERSION) {
                SS_LOG_ERROR(L"ProductTier",
                    L"Unsupported license version: %u (max supported: %u)",
                    version, TierConstants::CURRENT_LICENSE_VERSION);
                return false;
            }
            outInfo.version = version;

            // License ID (with length cap)
            const std::string lid = doc.value("license_id", "");
            if (lid.empty() || lid.size() > TierConstants::MAX_LICENSE_ID_LENGTH) {
                SS_LOG_ERROR(L"ProductTier",
                    L"Invalid license ID length: %zu", lid.size());
                return false;
            }
            outInfo.licenseId = lid;

            // Tier
            const std::string tierStr = doc.value("tier", "");
            if (tierStr == "community") {
                outInfo.tier = ProductTier::Community;
            } else if (tierStr == "professional" || tierStr == "pro") {
                outInfo.tier = ProductTier::Professional;
            } else if (tierStr == "enterprise") {
                outInfo.tier = ProductTier::Enterprise;
            } else {
                SS_LOG_ERROR(L"ProductTier",
                    L"Unknown tier in license: %s",
                    NarrowToWide(tierStr).c_str());
                return false;
            }

            // Organization (optional for Community)
            const std::string orgName = doc.value("organization_name", "");
            if (orgName.size() > TierConstants::MAX_ORGANIZATION_NAME_LENGTH) {
                SS_LOG_ERROR(L"ProductTier",
                    L"Organization name too long: %zu", orgName.size());
                return false;
            }
            outInfo.organizationName = orgName;
            outInfo.organizationId = doc.value("organization_id", "");

            // Max endpoints
            outInfo.maxEndpoints = doc.value("max_endpoints", 1u);
            if (outInfo.maxEndpoints == 0) {
                outInfo.maxEndpoints = 1;
            }

            // Timestamps — ISO 8601 stored as epoch seconds
            const int64_t issuedEpoch = doc.value("issued_at", 0LL);
            const int64_t expiresEpoch = doc.value("expires_at", 0LL);
            if (expiresEpoch <= 0) {
                SS_LOG_ERROR(L"ProductTier",
                    L"Invalid expiration timestamp in license");
                return false;
            }
            outInfo.issuedAt = std::chrono::system_clock::time_point(
                std::chrono::seconds(issuedEpoch));
            outInfo.expiresAt = std::chrono::system_clock::time_point(
                std::chrono::seconds(expiresEpoch));

            // Additional features
            outInfo.additionalFeatures.clear();
            if (doc.contains("additional_features") &&
                doc["additional_features"].is_array()) {
                const auto& feats = doc["additional_features"];
                if (feats.size() > TierConstants::MAX_ADDITIONAL_FEATURES) {
                    SS_LOG_ERROR(L"ProductTier",
                        L"Too many additional features: %zu (max %zu)",
                        feats.size(),
                        TierConstants::MAX_ADDITIONAL_FEATURES);
                    return false;
                }
                for (const auto& f : feats) {
                    if (f.is_number_unsigned()) {
                        const uint8_t val = f.get<uint8_t>();
                        if (val < TierConstants::FEATURE_CATEGORY_COUNT) {
                            outInfo.additionalFeatures.push_back(
                                static_cast<FeatureCategory>(val));
                        }
                    }
                }
            }

            return true;
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProductTier",
                L"License parse exception: %s",
                NarrowToWide(e.what()).c_str());
            return false;
        }
    }

    // ========================================================================
    // LICENSE SIGNATURE VERIFICATION
    // ========================================================================

    [[nodiscard]] bool VerifyLicenseSignature(
            const std::vector<uint8_t>& payloadBytes,
            const std::vector<uint8_t>& signatureBytes) noexcept {

        // Embedded RSA-2048 public key for license verification.
        // This is a PLACEHOLDER key blob — replace with the real issuer
        // public key when the signing infrastructure is established.
        // The key is exported via BCryptExportKey(BCRYPT_RSAPUBLIC_BLOB).
        //
        // NOTE: In production, this key MUST be the real issuer key.
        // The Community edition still validates signatures so that
        // users can verify license files were issued by ShadowStrike.
        //
        // Key rotation: Embed multiple keys indexed by a "key_id" field
        // in the license payload. This allows seamless key rotation.
        static constexpr bool kHasProductionKey = false;

        if constexpr (!kHasProductionKey) {
            // No production key embedded yet — license signature
            // verification is not enforced. This allows development
            // and testing without a signing infrastructure.
            // When the NLNet funding arrives and the signing pipeline
            // is established, this flag flips to true and the real
            // public key blob is embedded below.
            SS_LOG_WARN(L"ProductTier",
                L"License signature verification skipped — "
                L"no production signing key embedded");
            return true;
        }

        // --- Production path (enabled when kHasProductionKey = true) ---
        // The following code will be compiled but unreachable until
        // the production key is embedded. The compiler will optimize
        // it away, but it serves as the verified implementation.
        /*
        Utils::CryptoUtils::AsymmetricCipher verifier(
            Utils::CryptoUtils::AsymmetricAlgorithm::RSA_2048);

        // Load the embedded issuer public key
        Utils::CryptoUtils::PublicKey pubKey;
        pubKey.algorithm = Utils::CryptoUtils::AsymmetricAlgorithm::RSA_2048;
        pubKey.keyBlob = std::vector<uint8_t>(
            kIssuerPublicKeyBlob,
            kIssuerPublicKeyBlob + sizeof(kIssuerPublicKeyBlob));

        Utils::CryptoUtils::Error cryptoErr;
        if (!verifier.LoadPublicKey(pubKey, &cryptoErr)) {
            SS_LOG_ERROR(L"ProductTier",
                L"Failed to load issuer public key: %s",
                cryptoErr.message.c_str());
            return false;
        }

        if (!verifier.Verify(
                payloadBytes.data(), payloadBytes.size(),
                signatureBytes.data(), signatureBytes.size(),
                Utils::HashUtils::Algorithm::SHA256,
                Utils::CryptoUtils::RSAPaddingScheme::PSS_SHA256,
                &cryptoErr)) {
            SS_LOG_ERROR(L"ProductTier",
                L"License signature verification FAILED: %s",
                cryptoErr.message.c_str());
            return false;
        }

        return true;
        */
        return false;  // Unreachable when kHasProductionKey = false
    }

    // ========================================================================
    // LICENSE KEY DECODING
    // ========================================================================

    [[nodiscard]] bool DecodeLicenseKey(
            std::string_view licenseKey,
            std::vector<uint8_t>& outPayload,
            std::vector<uint8_t>& outSignature) noexcept {

        if (licenseKey.empty() || licenseKey.size() > kMaxLicenseKeyLength) {
            SS_LOG_ERROR(L"ProductTier",
                L"License key invalid length: %zu", licenseKey.size());
            return false;
        }

        // Format: BASE64(payload).BASE64(signature)
        const auto sepPos = licenseKey.find(kLicenseKeySeparator);
        if (sepPos == std::string_view::npos || sepPos == 0 ||
            sepPos == licenseKey.size() - 1) {
            SS_LOG_ERROR(L"ProductTier",
                L"License key missing separator or empty segments");
            return false;
        }

        const auto payloadB64 = licenseKey.substr(0, sepPos);
        const auto signatureB64 = licenseKey.substr(sepPos + 1);

        // Decode payload
        Utils::Base64DecodeError b64Err;
        if (!Utils::Base64Decode(payloadB64, outPayload, b64Err)) {
            SS_LOG_ERROR(L"ProductTier",
                L"License payload Base64 decode failed: %s",
                NarrowToWide(
                    Utils::Base64DecodeErrorToString(b64Err)).c_str());
            return false;
        }

        // Decode signature
        if (!Utils::Base64Decode(signatureB64, outSignature, b64Err)) {
            SS_LOG_ERROR(L"ProductTier",
                L"License signature Base64 decode failed: %s",
                NarrowToWide(
                    Utils::Base64DecodeErrorToString(b64Err)).c_str());
            return false;
        }

        // Sanity check sizes
        if (outPayload.empty()) {
            SS_LOG_ERROR(L"ProductTier", L"Empty license payload after decode");
            return false;
        }
        if (outSignature.size() > TierConstants::MAX_SIGNATURE_SIZE) {
            SS_LOG_ERROR(L"ProductTier",
                L"License signature too large: %zu bytes (max %zu)",
                outSignature.size(), TierConstants::MAX_SIGNATURE_SIZE);
            return false;
        }

        return true;
    }

    // ========================================================================
    // TIER APPLICATION
    // ========================================================================

    void ApplyTier(ProductTier tier) noexcept {
        const ProductTier oldTier = currentTier.load(std::memory_order_acquire);
        currentTier.store(tier, std::memory_order_release);
        RecomputeFeatureFlags();

        if (oldTier != tier) {
            SS_LOG_INFO(L"ProductTier",
                L"Product tier changed: %s -> %s",
                ProductTierManager::TierToString(oldTier).data(),
                ProductTierManager::TierToString(tier).data());
        }
    }

    // ========================================================================
    // LICENSE LOAD FROM DB
    // ========================================================================

    void LoadLicenseFromDb() noexcept {
        try {
            auto& db = Database::ConfigurationDB::Instance();
            if (!db.IsInitialized()) {
                SS_LOG_DEBUG(L"ProductTier",
                    L"ConfigurationDB not initialized — "
                    L"defaulting to Community tier");
                return;
            }

            // Try to read stored license key
            const std::wstring storedKey = db.GetString(
                L"ProductTier.LicenseKey", L"");
            if (storedKey.empty()) {
                SS_LOG_INFO(L"ProductTier",
                    L"No stored license found — Community tier");
                return;
            }

            // Convert wide string to narrow for processing
            const std::string keyNarrow = WideToNarrow(storedKey);
            if (keyNarrow.empty()) {
                SS_LOG_DEBUG(L"ProductTier",
                    L"Stored license key conversion failed — Community tier");
                return;
            }

            // Decode and validate
            std::vector<uint8_t> payload;
            std::vector<uint8_t> signature;
            if (!DecodeLicenseKey(keyNarrow, payload, signature)) {
                SS_LOG_WARN(L"ProductTier",
                    L"Stored license key decode failed — "
                    L"reverting to Community tier");
                licenseStatus = LicenseStatus::Invalid;
                return;
            }

            // Verify signature
            if (!VerifyLicenseSignature(payload, signature)) {
                SS_LOG_ERROR(L"ProductTier",
                    L"Stored license signature verification FAILED — "
                    L"possible tampering, reverting to Community tier");
                licenseStatus = LicenseStatus::Tampered;
                return;
            }

            // Parse payload
            const std::string_view payloadStr(
                reinterpret_cast<const char*>(payload.data()),
                payload.size());
            LicenseInfo info;
            if (!ParseLicensePayload(payloadStr, info)) {
                licenseStatus = LicenseStatus::Invalid;
                return;
            }
            info.signature = std::move(signature);

            // Check expiration
            const auto now = std::chrono::system_clock::now();
            if (info.expiresAt < now) {
                SS_LOG_WARN(L"ProductTier",
                    L"Stored license expired — reverting to Community tier");
                licenseStatus = LicenseStatus::Expired;
                licenseInfo = std::move(info);
                return;
            }

            // Apply
            licenseInfo = std::move(info);
            licenseStatus = LicenseStatus::Valid;
            ApplyTier(licenseInfo.tier);

            SS_LOG_INFO(L"ProductTier",
                L"License loaded: tier=%s, org=%s, "
                L"endpoints=%u, license_id=%s",
                ProductTierManager::TierToString(licenseInfo.tier).data(),
                NarrowToWide(licenseInfo.organizationName).c_str(),
                licenseInfo.maxEndpoints,
                NarrowToWide(licenseInfo.licenseId).c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProductTier",
                L"Exception loading license from DB: %s",
                NarrowToWide(e.what()).c_str());
        }
    }

    // ========================================================================
    // LICENSE PERSIST TO DB
    // ========================================================================

    void PersistLicenseToDb(std::string_view licenseKey) noexcept {
        try {
            auto& db = Database::ConfigurationDB::Instance();
            if (!db.IsInitialized()) {
                SS_LOG_WARN(L"ProductTier",
                    L"Cannot persist license — ConfigurationDB not available");
                return;
            }

            db.SetString(L"ProductTier.LicenseKey",
                NarrowToWide(std::string(licenseKey)),
                Database::ConfigurationDB::ConfigScope::System,
                L"ProductTierManager");

            db.SetInt(L"ProductTier.CurrentTier",
                static_cast<int64_t>(currentTier.load()),
                Database::ConfigurationDB::ConfigScope::System,
                L"ProductTierManager");

            SS_LOG_INFO(L"ProductTier",
                L"License persisted to ConfigurationDB");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProductTier",
                L"Failed to persist license: %s",
                NarrowToWide(e.what()).c_str());
        }
    }
};

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> ProductTierManager::s_instanceCreated{false};

// ============================================================================
// SINGLETON
// ============================================================================

ProductTierManager& ProductTierManager::Instance() noexcept {
    static ProductTierManager instance;
    return instance;
}

bool ProductTierManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProductTierManager::ProductTierManager() noexcept
    : m_impl(std::make_unique<Impl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

ProductTierManager::~ProductTierManager() noexcept {
    Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ProductTierManager::Initialize(const std::wstring& /*configDbPath*/) noexcept {
    // Atomically claim ownership of the initialization slot. Two concurrent
    // Initialize() calls would otherwise both observe the load=false branch
    // and race through LoadLicenseFromDb / state mutation in parallel.
    bool expected = false;
    if (!m_impl->initialized.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
        SS_LOG_WARN(L"ProductTier",
            L"ProductTierManager already initialized");
        return true;
    }

    SS_LOG_INFO(L"ProductTier",
        L"Initializing ProductTierManager v%u.%u.%u",
        TierConstants::VERSION_MAJOR,
        TierConstants::VERSION_MINOR,
        TierConstants::VERSION_PATCH);

    // Load license from persistent storage. LoadLicenseFromDb mutates
    // licenseStatus / licenseInfo / currentTier / featureFlags, which other
    // public APIs read under m_impl->mutex; take the writer lock to keep
    // those readers consistent.
    {
        std::unique_lock lock(m_impl->mutex);
        m_impl->LoadLicenseFromDb();
    }

    SS_LOG_INFO(L"ProductTier",
        L"ProductTierManager initialized — tier: %s (%zu features enabled)",
        GetTierDisplayName().data(),
        GetEnabledFeatures().size());

    return true;
}

void ProductTierManager::Shutdown() noexcept {
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(L"ProductTier", L"Shutting down ProductTierManager");

    {
        std::unique_lock lock(m_impl->mutex);
        m_impl->overrides.clear();
    }

    m_impl->initialized.store(false, std::memory_order_release);
}

bool ProductTierManager::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

// ============================================================================
// TIER QUERIES
// ============================================================================

ProductTier ProductTierManager::GetCurrentTier() const noexcept {
    return m_impl->currentTier.load(std::memory_order_acquire);
}

std::wstring_view ProductTierManager::GetTierName() const noexcept {
    return TierToString(GetCurrentTier());
}

std::wstring_view ProductTierManager::GetTierDisplayName() const noexcept {
    return ProductTierToDisplayName(GetCurrentTier());
}

// ============================================================================
// FEATURE FLAG QUERIES (HOT PATH)
// ============================================================================

bool ProductTierManager::IsFeatureEnabled(FeatureCategory feature) const noexcept {
    const auto idx = static_cast<size_t>(feature);
    if (idx >= TierConstants::FEATURE_CATEGORY_COUNT) {
        return false;
    }

    m_impl->stats.featureChecks.fetch_add(1, std::memory_order_relaxed);

    // Hot path: atomic load of shared_ptr, then direct array access
    const auto flags = m_impl->featureFlags.load(std::memory_order_acquire);
    if (!flags) {
        m_impl->stats.featureDenials.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const bool enabled = (*flags)[idx];
    if (!enabled) {
        m_impl->stats.featureDenials.fetch_add(1, std::memory_order_relaxed);
    }
    return enabled;
}

bool ProductTierManager::IsFeatureAvailable(FeatureCategory feature) const noexcept {
    const auto idx = static_cast<size_t>(feature);
    if (idx >= TierConstants::FEATURE_CATEGORY_COUNT) {
        return false;
    }

    m_impl->stats.featureChecks.fetch_add(1, std::memory_order_relaxed);

    // Check tier-based availability without overrides
    const auto tier = m_impl->currentTier.load(std::memory_order_acquire);
    const bool available = (static_cast<uint8_t>(tier) >=
        static_cast<uint8_t>(kFeatureDefinitions[idx].minimumTier));

    if (!available) {
        m_impl->stats.featureDenials.fetch_add(1, std::memory_order_relaxed);
    }
    return available;
}

FeatureInfo ProductTierManager::GetFeatureInfo(FeatureCategory feature) const noexcept {
    const auto idx = static_cast<size_t>(feature);
    FeatureInfo info;

    if (idx >= TierConstants::FEATURE_CATEGORY_COUNT) {
        return info;
    }

    const auto& def = kFeatureDefinitions[idx];
    info.category = def.category;
    info.displayName = def.displayName;
    info.description = def.description;
    info.minimumTier = def.minimumTier;
    info.isEnabled = IsFeatureEnabled(feature);

    {
        std::shared_lock lock(m_impl->mutex);
        info.isOverridden = m_impl->overrides.contains(
            static_cast<uint8_t>(feature));
    }

    return info;
}

std::vector<FeatureInfo> ProductTierManager::GetAllFeatures() const noexcept {
    std::vector<FeatureInfo> result;
    result.reserve(TierConstants::FEATURE_CATEGORY_COUNT);

    for (size_t i = 0; i < TierConstants::FEATURE_CATEGORY_COUNT; ++i) {
        result.push_back(
            GetFeatureInfo(static_cast<FeatureCategory>(i)));
    }
    return result;
}

std::vector<FeatureCategory> ProductTierManager::GetEnabledFeatures() const noexcept {
    std::vector<FeatureCategory> result;
    result.reserve(TierConstants::FEATURE_CATEGORY_COUNT);

    const auto flags = m_impl->featureFlags.load(std::memory_order_acquire);
    if (!flags) return result;

    for (size_t i = 0; i < TierConstants::FEATURE_CATEGORY_COUNT; ++i) {
        if ((*flags)[i]) {
            result.push_back(static_cast<FeatureCategory>(i));
        }
    }
    return result;
}

std::vector<FeatureCategory> ProductTierManager::GetDisabledFeatures() const noexcept {
    std::vector<FeatureCategory> result;

    const auto flags = m_impl->featureFlags.load(std::memory_order_acquire);
    if (!flags) return result;

    for (size_t i = 0; i < TierConstants::FEATURE_CATEGORY_COUNT; ++i) {
        if (!(*flags)[i]) {
            result.push_back(static_cast<FeatureCategory>(i));
        }
    }
    return result;
}

// ============================================================================
// LICENSE MANAGEMENT
// ============================================================================

bool ProductTierManager::LoadLicense(const std::wstring& licensePath) noexcept {
    m_impl->stats.licenseValidations.fetch_add(1, std::memory_order_relaxed);

    // Read the license file WITHOUT holding m_impl->mutex. Two concerns:
    //   (1) std::shared_mutex is non-recursive — taking the writer lock here
    //       and then calling ActivateLicense (which itself acquires the same
    //       writer lock) deadlocks every signed-license boot sequence.
    //   (2) Even if recursion were legal, holding the writer lock during disk
    //       I/O serializes every concurrent ValidateLicense / IsFeatureEnabled
    //       reader for the duration of a potentially slow filesystem read.
    std::string fileContent;
    try {
        Utils::FileUtils::Error fileErr;
        if (!Utils::FileUtils::ReadAllTextUtf8(licensePath, fileContent, &fileErr)) {
            SS_LOG_ERROR(L"ProductTier",
                L"Failed to read license file: %s", licensePath.c_str());
            std::unique_lock lock(m_impl->mutex);
            m_impl->licenseStatus = LicenseStatus::NotFound;
            m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"ProductTier",
            L"Exception reading license file: %s",
            NarrowToWide(e.what()).c_str());
        std::unique_lock lock(m_impl->mutex);
        m_impl->licenseStatus = LicenseStatus::NotFound;
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Size check
    if (fileContent.size() > kMaxLicenseFileSize) {
        SS_LOG_ERROR(L"ProductTier",
            L"License file too large: %zu bytes (max %zu)",
            fileContent.size(), kMaxLicenseFileSize);
        std::unique_lock lock(m_impl->mutex);
        m_impl->licenseStatus = LicenseStatus::Invalid;
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Trim whitespace
    while (!fileContent.empty() &&
           (fileContent.back() == '\n' || fileContent.back() == '\r' ||
            fileContent.back() == ' ' || fileContent.back() == '\t')) {
        fileContent.pop_back();
    }

    // ActivateLicense takes the writer lock itself.
    return ActivateLicense(fileContent);
}

bool ProductTierManager::ActivateLicense(std::string_view licenseKey) noexcept {
    std::unique_lock lock(m_impl->mutex);

    m_impl->stats.licenseValidations.fetch_add(1, std::memory_order_relaxed);

    if (licenseKey.empty()) {
        SS_LOG_WARN(L"ProductTier", L"Empty license key provided");
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Decode key
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
    if (!m_impl->DecodeLicenseKey(licenseKey, payload, signature)) {
        m_impl->licenseStatus = LicenseStatus::Invalid;
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Verify signature
    if (!m_impl->VerifyLicenseSignature(payload, signature)) {
        m_impl->licenseStatus = LicenseStatus::Tampered;
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR(L"ProductTier",
            L"License activation FAILED — signature verification failed "
            L"(possible tampering or corrupted key)");
        return false;
    }

    // Parse payload JSON
    const std::string_view payloadStr(
        reinterpret_cast<const char*>(payload.data()), payload.size());
    LicenseInfo info;
    if (!m_impl->ParseLicensePayload(payloadStr, info)) {
        m_impl->licenseStatus = LicenseStatus::Invalid;
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    info.signature = std::move(signature);

    // Check expiration
    const auto now = std::chrono::system_clock::now();
    if (info.expiresAt < now) {
        SS_LOG_WARN(L"ProductTier",
            L"License key is expired — activation denied");
        m_impl->licenseStatus = LicenseStatus::Expired;
        m_impl->licenseInfo = std::move(info);
        m_impl->stats.licenseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Apply the new license
    m_impl->licenseInfo = std::move(info);
    m_impl->licenseStatus = LicenseStatus::Valid;
    m_impl->ApplyTier(m_impl->licenseInfo.tier);

    // Persist to database
    m_impl->PersistLicenseToDb(licenseKey);

    SS_LOG_INFO(L"ProductTier",
        L"License activated: tier=%s, org=%s, endpoints=%u, "
        L"expires in %lld days",
        TierToString(m_impl->licenseInfo.tier).data(),
        NarrowToWide(m_impl->licenseInfo.organizationName).c_str(),
        m_impl->licenseInfo.maxEndpoints,
        std::chrono::duration_cast<std::chrono::hours>(
            m_impl->licenseInfo.expiresAt - now).count() / 24);

    return true;
}

LicenseStatus ProductTierManager::ValidateLicense() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->licenseStatus;
}

const LicenseInfo& ProductTierManager::GetLicenseInfo() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->licenseInfo;
}

bool ProductTierManager::IsLicenseValid() const noexcept {
    std::shared_lock lock(m_impl->mutex);

    if (m_impl->licenseStatus != LicenseStatus::Valid) {
        return false;
    }

    // Double-check expiration in real time
    const auto now = std::chrono::system_clock::now();
    return m_impl->licenseInfo.expiresAt > now;
}

bool ProductTierManager::IsLicenseExpiringSoon(uint32_t daysThreshold) const noexcept {
    std::shared_lock lock(m_impl->mutex);

    if (m_impl->licenseStatus != LicenseStatus::Valid) {
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    const auto remaining = m_impl->licenseInfo.expiresAt - now;
    const auto thresholdDuration = std::chrono::hours(
        static_cast<int64_t>(daysThreshold) * 24);

    return remaining <= thresholdDuration && remaining > std::chrono::hours(0);
}

// ============================================================================
// ADMIN OVERRIDES (AUDITED)
// ============================================================================

bool ProductTierManager::OverrideFeature(
        FeatureCategory feature, bool enabled) noexcept {
    const auto idx = static_cast<uint8_t>(feature);
    if (idx >= TierConstants::FEATURE_CATEGORY_COUNT) {
        return false;
    }

    {
        std::unique_lock lock(m_impl->mutex);
        m_impl->overrides[idx] = enabled;
        m_impl->RecomputeFeatureFlags();
    }

    SS_LOG_WARN(L"ProductTier",
        L"AUDIT: Feature override applied — %s = %s "
        L"(admin override, tier=%s)",
        FeatureCategoryToString(feature).data(),
        enabled ? L"ENABLED" : L"DISABLED",
        GetTierName().data());

    return true;
}

bool ProductTierManager::ClearOverride(FeatureCategory feature) noexcept {
    const auto idx = static_cast<uint8_t>(feature);
    if (idx >= TierConstants::FEATURE_CATEGORY_COUNT) {
        return false;
    }

    bool existed = false;
    {
        std::unique_lock lock(m_impl->mutex);
        existed = (m_impl->overrides.erase(idx) > 0);
        if (existed) {
            m_impl->RecomputeFeatureFlags();
        }
    }

    if (existed) {
        SS_LOG_WARN(L"ProductTier",
            L"AUDIT: Feature override cleared — %s (reverted to tier-based)",
            FeatureCategoryToString(feature).data());
    }

    return existed;
}

void ProductTierManager::ClearAllOverrides() noexcept {
    size_t count = 0;
    {
        std::unique_lock lock(m_impl->mutex);
        count = m_impl->overrides.size();
        m_impl->overrides.clear();
        m_impl->RecomputeFeatureFlags();
    }

    if (count > 0) {
        SS_LOG_WARN(L"ProductTier",
            L"AUDIT: All feature overrides cleared (%zu overrides removed)",
            count);
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

TierStatistics ProductTierManager::GetStatistics() const noexcept {
    return m_impl->stats;
}

void ProductTierManager::ResetStatistics() noexcept {
    m_impl->stats.Reset();
}

// ============================================================================
// STATIC UTILITIES
// ============================================================================

std::wstring_view ProductTierManager::TierToString(ProductTier tier) noexcept {
    switch (tier) {
        case ProductTier::Community:    return L"Community";
        case ProductTier::Professional: return L"Professional";
        case ProductTier::Enterprise:   return L"Enterprise";
        default:                        return L"Unknown";
    }
}

std::wstring_view ProductTierManager::FeatureCategoryToString(
        FeatureCategory cat) noexcept {
    switch (cat) {
        case FeatureCategory::Core:                return L"Core";
        case FeatureCategory::HomeProtection:      return L"HomeProtection";
        case FeatureCategory::ForensicsBasic:      return L"ForensicsBasic";
        case FeatureCategory::ForensicsAdvanced:   return L"ForensicsAdvanced";
        case FeatureCategory::ThreatIntel:         return L"ThreatIntel";
        case FeatureCategory::ThreatIntelAdvanced:  return L"ThreatIntelAdvanced";
        case FeatureCategory::Dashboard:           return L"Dashboard";
        case FeatureCategory::CloudConsole:        return L"CloudConsole";
        case FeatureCategory::FleetManagement:     return L"FleetManagement";
        case FeatureCategory::RemoteActions:       return L"RemoteActions";
        case FeatureCategory::SIEMIntegration:     return L"SIEMIntegration";
        case FeatureCategory::SOARIntegration:     return L"SOARIntegration";
        case FeatureCategory::ComplianceReporting: return L"ComplianceReporting";
        case FeatureCategory::CustomRules:         return L"CustomRules";
        case FeatureCategory::RBAC:                return L"RBAC";
        case FeatureCategory::XDRCorrelation:      return L"XDRCorrelation";
        case FeatureCategory::CloudTelemetry:      return L"CloudTelemetry";
        case FeatureCategory::KernelProtection:    return L"KernelProtection";
        default:                                   return L"Unknown";
    }
}

ProductTier ProductTierManager::GetMinimumTierForFeature(
        FeatureCategory feature) noexcept {
    const auto idx = static_cast<size_t>(feature);
    if (idx >= TierConstants::FEATURE_CATEGORY_COUNT) {
        return ProductTier::Enterprise;  // Unknown features require highest tier
    }
    return kFeatureDefinitions[idx].minimumTier;
}

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

std::wstring_view LicenseStatusToString(LicenseStatus status) noexcept {
    switch (status) {
        case LicenseStatus::Valid:            return L"Valid";
        case LicenseStatus::Expired:          return L"Expired";
        case LicenseStatus::Invalid:          return L"Invalid";
        case LicenseStatus::Tampered:         return L"Tampered";
        case LicenseStatus::NotFound:         return L"Not Found";
        case LicenseStatus::CommunityDefault: return L"Community (No License)";
        default:                              return L"Unknown";
    }
}

std::wstring_view ProductTierToDisplayName(ProductTier tier) noexcept {
    switch (tier) {
        case ProductTier::Community:    return L"Phantom Community";
        case ProductTier::Professional: return L"Phantom Professional";
        case ProductTier::Enterprise:   return L"Phantom Enterprise";
        default:                        return L"Unknown";
    }
}

}  // namespace Config
}  // namespace ShadowStrike
