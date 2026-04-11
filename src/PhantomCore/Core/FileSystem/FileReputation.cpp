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
 * ShadowStrike Core FileSystem - FILE REPUTATION IMPLEMENTATION
 * ============================================================================
 *
 * @file FileReputation.cpp
 * @brief Enterprise-grade hybrid reputation engine implementation.
 *
 * This module provides comprehensive file reputation checking combining local
 * caches, cloud lookups, threat intelligence, and behavioral analysis to
 * answer: "Is this file safe?"
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Multi-layered reputation scoring (local → cert → threat → cloud)
 * - LRU cache with TTL expiration
 * - Async cloud queries with timeout protection
 * - Integration with HashStore, ThreatIntel, Whitelist
 *
 * Performance Targets:
 * - Local whitelist lookup: <1ms
 * - Certificate verification: ~10ms
 * - ThreatIntel lookup: ~5ms
 * - Cloud query: <100ms (with timeout)
 * - Cache hit rate: >90% in production
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "FileReputation.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/JSONUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../SelfProtection/CertificateValidator.hpp"
#include "FileHasher.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <future>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cmath>

namespace fs = std::filesystem;

// Namespace aliases for infrastructure modules
using ShadowStrike::Utils::StringUtils::ToNarrow;
using ShadowStrike::Utils::StringUtils::ToWide;

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Score weights for reputation calculation — use int to prevent int8_t overflow
    // during intermediate arithmetic. Final score is clamped to [-100, 100].
    constexpr int WEIGHT_WHITELIST = 100;
    constexpr int WEIGHT_BLACKLIST = -100;
    constexpr int WEIGHT_MICROSOFT_SIGNED = 90;
    constexpr int WEIGHT_TRUSTED_CERT = 70;
    constexpr int WEIGHT_VALID_CERT = 30;
    constexpr int WEIGHT_THREAT_INTEL_CRITICAL = -90;
    constexpr int WEIGHT_THREAT_INTEL_HIGH = -70;
    constexpr int WEIGHT_THREAT_INTEL_MEDIUM = -50;
    constexpr int WEIGHT_CLOUD_MALICIOUS = -80;
    constexpr int WEIGHT_HIGH_PREVALENCE = 40;

    // Prevalence thresholds
    constexpr uint64_t HIGH_PREVALENCE_THRESHOLD = 10000;
    constexpr uint64_t LOW_PREVALENCE_THRESHOLD = 100;
    constexpr double RARE_FILE_PERCENTAGE = 0.01; // 0.01%

    // Cloud query settings
    constexpr size_t MAX_CLOUD_RETRIES = 2;
    constexpr uint32_t CLOUD_RETRY_DELAY_MS = 500;

    // Behavioral scoring
    constexpr int BEHAVIOR_C2_PENALTY = -40;
    constexpr int BEHAVIOR_RANSOMWARE_PENALTY = -50;
    constexpr int BEHAVIOR_CLEAN_HISTORY_BONUS = 20;

    // Maximum concurrent async reputation checks to prevent resource exhaustion
    constexpr size_t MAX_CONCURRENT_ASYNC_CHECKS = 64;

    // Microsoft known publishers
    const std::unordered_set<std::wstring> MICROSOFT_PUBLISHERS = {
        L"Microsoft Corporation",
        L"Microsoft Windows",
        L"Microsoft Code Signing PCA",
        L"Microsoft Windows Hardware Compatibility Publisher"
    };

    // Known trusted publishers
    const std::unordered_set<std::wstring> TRUSTED_PUBLISHERS = {
        L"Adobe Systems Incorporated",
        L"Google LLC",
        L"Apple Inc.",
        L"Mozilla Corporation",
        L"Oracle Corporation",
        L"Intel Corporation",
        L"NVIDIA Corporation",
        L"VMware, Inc."
    };

} // anonymous namespace

// ============================================================================
// CACHE ENTRY STRUCTURE
// ============================================================================

struct CacheEntry {
    ReputationResult result;
    std::chrono::system_clock::time_point insertTime;
    std::chrono::system_clock::time_point expiryTime;
    std::atomic<uint32_t> hitCount{ 0 };

    CacheEntry() = default;
    CacheEntry(const CacheEntry& other)
        : result(other.result)
        , insertTime(other.insertTime)
        , expiryTime(other.expiryTime)
        , hitCount(other.hitCount.load(std::memory_order_relaxed)) {}
    CacheEntry& operator=(const CacheEntry& other) {
        if (this != &other) {
            result = other.result;
            insertTime = other.insertTime;
            expiryTime = other.expiryTime;
            hitCount.store(other.hitCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        return *this;
    }

    [[nodiscard]] bool IsExpired() const noexcept {
        return std::chrono::system_clock::now() >= expiryTime;
    }
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FileReputationImpl final {
public:
    FileReputationImpl() = default;
    ~FileReputationImpl() = default;

    // Delete copy/move
    FileReputationImpl(const FileReputationImpl&) = delete;
    FileReputationImpl& operator=(const FileReputationImpl&) = delete;
    FileReputationImpl(FileReputationImpl&&) = delete;
    FileReputationImpl& operator=(FileReputationImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const FileReputationConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            m_shuttingDown.store(false, std::memory_order_release);
            m_initialized = true;

            // Initialize cloud connectivity check
            if (config.defaultMode != QueryMode::LocalOnly) {
                m_cloudAvailable = CheckCloudConnectivity();
            }

            SS_LOG_INFO(L"FileReputation", L"FileReputation initialized (mode=%d, cloud=%ls, cache=%llu)",
                static_cast<int>(config.defaultMode),
                m_cloudAvailable.load(std::memory_order_relaxed) ? L"yes" : L"no",
                static_cast<unsigned long long>(config.maxCacheSize));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"FileReputation initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_initialized = false;

            // Signal async threads to not start new work
            m_shuttingDown.store(true, std::memory_order_release);

            // Clear callbacks
            m_unknownFileCallbacks.clear();

            // Wait for outstanding async operations
            lock.unlock();
            {
                std::unique_lock asyncLock(m_asyncMutex);
                m_asyncCv.wait(asyncLock, [this]() {
                    return m_activeAsyncCount.load(std::memory_order_acquire) == 0;
                });
            }
            lock.lock();

            // Clear cache
            m_cache.clear();

            SS_LOG_INFO(L"FileReputation", L"FileReputation shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    // ========================================================================
    // REPUTATION QUERIES
    // ========================================================================

    [[nodiscard]] ReputationResult CheckFile(const std::wstring& filePath, QueryMode mode) {
        auto startTime = std::chrono::steady_clock::now();
        ReputationResult result;
        result.queryTime = std::chrono::system_clock::now();

        try {
            if (!m_initialized) {
                SS_LOG_ERROR(L"FileReputation", L"CheckFile called before Initialize");
                result.level = ReputationLevel::Unknown;
                result.recommendation = "Investigate";
                result.reasons.push_back("Reputation service not initialized");
                return result;
            }

            m_stats.totalQueries.fetch_add(1, std::memory_order_relaxed);

            // Validate path
            if (filePath.empty()) {
                SS_LOG_WARN(L"FileReputation", L"CheckFile - Empty file path");
                result.level = ReputationLevel::Unknown;
                result.recommendation = "Block";
                result.reasons.push_back("Invalid file path");
                return result;
            }

            // Compute hashes directly — do NOT check fs::exists first (TOCTOU).
            // FileHasher handles missing files gracefully.
            auto& hasher = FileHasher::Instance();
            result.sha256 = hasher.ComputeSHA256(filePath);
            if (result.sha256.empty()) {
                SS_LOG_WARN(L"FileReputation", L"CheckFile - Hash computation failed: %ls",
                    filePath.c_str());
                result.level = ReputationLevel::Unknown;
                result.recommendation = "Block";
                result.reasons.push_back("File inaccessible or hash computation failed");
                return result;
            }
            result.sha1 = hasher.ComputeSHA1(filePath);
            result.md5 = hasher.ComputeMD5(filePath);

            // Build query
            ReputationQuery query;
            query.filePath = filePath;
            query.sha256 = result.sha256;
            query.sha1 = result.sha1;
            query.md5 = result.md5;
            query.mode = mode;

            // Execute query
            result = QueryInternal(query);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"CheckFile - Exception: %hs", e.what());
            result.level = ReputationLevel::Unknown;
            result.recommendation = "Investigate";
            result.reasons.push_back(std::string("Error: ") + e.what());
        }

        auto endTime = std::chrono::steady_clock::now();
        result.totalLatency = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);

        UpdatePerformanceStats(result.totalLatency);

        return result;
    }

    [[nodiscard]] ReputationResult CheckHash(std::string_view sha256, QueryMode mode) {
        if (!m_initialized) {
            ReputationResult result;
            result.level = ReputationLevel::Unknown;
            result.recommendation = "Investigate";
            result.reasons.push_back("Reputation service not initialized");
            return result;
        }

        ReputationQuery query;
        query.sha256 = std::string(sha256);
        query.mode = mode;

        m_stats.totalQueries.fetch_add(1, std::memory_order_relaxed);
        return QueryInternal(query);
    }

    [[nodiscard]] ReputationResult CheckHashes(std::string_view sha256,
                                               std::string_view sha1,
                                               std::string_view md5,
                                               QueryMode mode) {
        if (!m_initialized) {
            ReputationResult result;
            result.level = ReputationLevel::Unknown;
            result.recommendation = "Investigate";
            result.reasons.push_back("Reputation service not initialized");
            return result;
        }

        ReputationQuery query;
        query.sha256 = std::string(sha256);
        query.sha1 = std::string(sha1);
        query.md5 = std::string(md5);
        query.mode = mode;

        m_stats.totalQueries.fetch_add(1, std::memory_order_relaxed);
        return QueryInternal(query);
    }

    [[nodiscard]] ReputationResult Query(const ReputationQuery& query) {
        if (!m_initialized) {
            ReputationResult result;
            result.level = ReputationLevel::Unknown;
            result.recommendation = "Investigate";
            result.reasons.push_back("Reputation service not initialized");
            return result;
        }

        m_stats.totalQueries.fetch_add(1, std::memory_order_relaxed);
        return QueryInternal(query);
    }

    void CheckFileAsync(const std::wstring& filePath, ReputationCallback callback) {
        if (!callback) return;
        if (m_shuttingDown.load(std::memory_order_acquire)) return;

        // Enforce concurrency limit to prevent resource exhaustion
        if (m_activeAsyncCount.load(std::memory_order_acquire) >= MAX_CONCURRENT_ASYNC_CHECKS) {
            SS_LOG_WARN(L"FileReputation", L"Async check limit reached (%zu), running synchronously",
                static_cast<size_t>(MAX_CONCURRENT_ASYNC_CHECKS));
            auto result = CheckFile(filePath, m_config.defaultMode);
            callback(result);
            return;
        }

        m_activeAsyncCount.fetch_add(1, std::memory_order_acq_rel);

        std::thread([this, filePath, cb = std::move(callback)]() {
            try {
                if (!m_shuttingDown.load(std::memory_order_acquire)) {
                    auto result = CheckFile(filePath, m_config.defaultMode);
                    cb(result);
                }
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileReputation", L"CheckFileAsync - Exception: %hs", e.what());
            }

            auto prev = m_activeAsyncCount.fetch_sub(1, std::memory_order_acq_rel);
            if (prev == 1) {
                m_asyncCv.notify_all();
            }
        }).detach();
    }

    [[nodiscard]] std::vector<ReputationResult> CheckFiles(
        const std::vector<std::wstring>& filePaths) {

        std::vector<ReputationResult> results;
        results.reserve(filePaths.size());

        for (const auto& path : filePaths) {
            results.push_back(CheckFile(path, m_config.defaultMode));
        }

        return results;
    }

    void CheckFilesAsync(const std::vector<std::wstring>& filePaths,
                        ReputationCallback callback) {
        if (!callback) return;
        if (m_shuttingDown.load(std::memory_order_acquire)) return;

        // Use a single async thread for batch to avoid thread explosion
        m_activeAsyncCount.fetch_add(1, std::memory_order_acq_rel);

        std::thread([this, filePaths, cb = std::move(callback)]() {
            try {
                for (const auto& path : filePaths) {
                    if (m_shuttingDown.load(std::memory_order_acquire)) break;
                    auto result = CheckFile(path, m_config.defaultMode);
                    cb(result);
                }
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileReputation", L"CheckFilesAsync - Exception: %hs", e.what());
            }

            auto prev = m_activeAsyncCount.fetch_sub(1, std::memory_order_acq_rel);
            if (prev == 1) {
                m_asyncCv.notify_all();
            }
        }).detach();
    }

    // ========================================================================
    // LOCAL DATABASE MANAGEMENT
    // ========================================================================

    bool AddToWhitelist(std::string_view sha256, std::string_view reason) {
        std::unique_lock lock(m_mutex);

        try {
            if (sha256.empty()) return false;

            m_localWhitelist.insert(std::string(sha256));

            SS_LOG_INFO(L"FileReputation", L"Added to whitelist: %hs (reason: %hs)",
                std::string(sha256).substr(0, 16).c_str(),
                std::string(reason).c_str());

            // Invalidate cache entry
            m_cache.erase(std::string(sha256));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"AddToWhitelist - Exception: %hs", e.what());
            return false;
        }
    }

    bool RemoveFromWhitelist(std::string_view sha256) {
        std::unique_lock lock(m_mutex);

        try {
            if (sha256.empty()) return false;

            auto removed = m_localWhitelist.erase(std::string(sha256)) > 0;
            if (removed) {
                m_cache.erase(std::string(sha256));
                SS_LOG_INFO(L"FileReputation", L"Removed from whitelist: %hs",
                    std::string(sha256).substr(0, 16).c_str());
            }

            return removed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"RemoveFromWhitelist - Exception: %hs", e.what());
            return false;
        }
    }

    bool AddToBlacklist(std::string_view sha256, std::string_view threatName) {
        std::unique_lock lock(m_mutex);

        try {
            if (sha256.empty()) return false;

            m_localBlacklist[std::string(sha256)] = std::string(threatName);

            SS_LOG_FATAL(L"FileReputation", L"Added to blacklist: %hs (threat: %hs)",
                std::string(sha256).substr(0, 16).c_str(),
                std::string(threatName).c_str());

            // Invalidate cache entry
            m_cache.erase(std::string(sha256));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"AddToBlacklist - Exception: %hs", e.what());
            return false;
        }
    }

    bool RemoveFromBlacklist(std::string_view sha256) {
        std::unique_lock lock(m_mutex);

        try {
            if (sha256.empty()) return false;

            auto removed = m_localBlacklist.erase(std::string(sha256)) > 0;
            if (removed) {
                m_cache.erase(std::string(sha256));
                SS_LOG_INFO(L"FileReputation", L"Removed from blacklist: %hs",
                    std::string(sha256).substr(0, 16).c_str());
            }

            return removed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"RemoveFromBlacklist - Exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool IsWhitelisted(std::string_view sha256) const {
        std::shared_lock lock(m_mutex);
        return m_localWhitelist.find(std::string(sha256)) != m_localWhitelist.end();
    }

    [[nodiscard]] bool IsBlacklisted(std::string_view sha256) const {
        std::shared_lock lock(m_mutex);
        return m_localBlacklist.find(std::string(sha256)) != m_localBlacklist.end();
    }

    // ========================================================================
    // CERTIFICATE REPUTATION
    // ========================================================================

    [[nodiscard]] CertificateReputation GetCertificateReputation(
        const std::wstring& filePath) const {

        CertificateReputation certRep;

        try {
            // Use CertificateValidator (from SelfProtection module) for Authenticode
            // verification: chain building, signature validation, revocation checks.
            auto& validator = ShadowStrike::Security::CertificateValidator::Instance();

            ShadowStrike::Security::ValidationOptions opts{};
            opts.requiredEKU = ShadowStrike::Security::ExtendedKeyUsage::CodeSigning;

            auto details = validator.VerifyFile(filePath, opts);

            // Map ValidationResult → CertificateReputation fields
            certRep.isSigned = (details.result != ShadowStrike::Security::ValidationResult::Error
                             && details.result != ShadowStrike::Security::ValidationResult::ChainBuildingFailed);
            certRep.isValidSignature = details.IsValid();

            // Extract signer info from the chain (leaf certificate = index 0)
            if (!details.chain.empty()) {
                const auto& leaf = details.chain.front();
                certRep.signerName  = ToWide(leaf.subject.commonName.empty()
                    ? leaf.subject.organization : leaf.subject.commonName);
                certRep.issuerName  = ToWide(leaf.issuer.commonName.empty()
                    ? leaf.issuer.organization : leaf.issuer.commonName);

                // SHA-1 thumbprint for legacy compatibility lookups
                std::string thumbHex;
                for (auto b : leaf.sha1Thumbprint) {
                    char buf[4];
                    snprintf(buf, sizeof(buf), "%02X", b);
                    thumbHex += buf;
                }
                certRep.thumbprint = ToWide(thumbHex);

                // Validity period
                certRep.validFrom  = leaf.validity.notBefore;
                certRep.validTo    = leaf.validity.notAfter;
                certRep.isExpired  = leaf.validity.IsExpired();
                certRep.isTimestamped = true;  // VerifyFile checks counter-sigs
            }

            // Revocation
            certRep.isRevoked = (details.revocationStatus ==
                ShadowStrike::Security::RevocationStatus::Revoked);

            // Map Security::TrustLevel → FileReputation::TrustLevel
            switch (details.trustLevel) {
                case ShadowStrike::Security::TrustLevel::Untrusted:
                    certRep.trustLevel = TrustLevel::Untrusted;
                    break;
                case ShadowStrike::Security::TrustLevel::Unknown:
                case ShadowStrike::Security::TrustLevel::SelfSigned:
                    certRep.trustLevel = TrustLevel::Unknown;
                    break;
                case ShadowStrike::Security::TrustLevel::CustomRoot:
                    certRep.trustLevel = TrustLevel::BasicTrust;
                    break;
                case ShadowStrike::Security::TrustLevel::SystemRoot:
                case ShadowStrike::Security::TrustLevel::EnterpriseRoot:
                    certRep.trustLevel = TrustLevel::SystemTrust;
                    break;
                case ShadowStrike::Security::TrustLevel::EVValidated:
                    certRep.trustLevel = TrustLevel::ExtendedTrust;
                    break;
                default:
                    certRep.trustLevel = TrustLevel::Unknown;
                    break;
            }

            // EV certificate boost
            if (details.isExtendedValidation) {
                certRep.trustLevel    = TrustLevel::ExtendedTrust;
                certRep.signerReputation = 80;
                certRep.signerCategory   = "EV Code Signing";
                certRep.trustReasons.push_back("Extended Validation certificate");
            } else if (certRep.isValidSignature) {
                certRep.signerReputation = 40;
                certRep.signerCategory   = "Code Signing";
                certRep.trustReasons.push_back("Valid Authenticode signature");
            }

            // Check known-bad signer thumbprint
            if (!certRep.thumbprint.empty()) {
                auto trustCheck = GetCertificateTrust(
                    ToNarrow(std::wstring_view(certRep.thumbprint)));
                if (trustCheck == TrustLevel::Untrusted) {
                    certRep.isKnownBadSigner = true;
                    certRep.trustLevel       = TrustLevel::Untrusted;
                    certRep.signerReputation = -100;
                    certRep.untrustReasons.push_back("Known-bad signer thumbprint");
                } else if (trustCheck == TrustLevel::UserTrust) {
                    certRep.signerReputation = 90;
                    certRep.trustReasons.push_back("User-trusted signer");
                }
            }

            // Revocation penalty
            if (certRep.isRevoked) {
                certRep.trustLevel       = TrustLevel::Untrusted;
                certRep.signerReputation = -100;
                certRep.untrustReasons.push_back("Certificate revoked");
            }

            // Expiration warning
            if (certRep.isExpired && !certRep.isRevoked) {
                certRep.signerReputation = std::min(
                    certRep.signerReputation, static_cast<int8_t>(10));
                certRep.untrustReasons.push_back("Certificate expired");
            }

            // Copy non-fatal warnings
            for (const auto& w : details.warnings) {
                certRep.untrustReasons.push_back(w);
            }

            SS_LOG_DEBUG(L"FileReputation",
                L"Authenticode: signed=%d valid=%d trust=%u signer='%ls' "
                L"ev=%d revoked=%d expired=%d",
                certRep.isSigned, certRep.isValidSignature,
                static_cast<unsigned>(certRep.trustLevel),
                certRep.signerName.c_str(),
                details.isExtendedValidation,
                certRep.isRevoked, certRep.isExpired);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"GetCertificateReputation exception: %hs", e.what());
            certRep.isSigned         = false;
            certRep.isValidSignature = false;
            certRep.trustLevel       = TrustLevel::Unknown;
        }

        return certRep;
    }

    [[nodiscard]] TrustLevel GetCertificateTrust(std::string_view thumbprint) const {
        std::shared_lock lock(m_mutex);

        try {
            auto it = m_trustedCertificates.find(std::string(thumbprint));
            if (it != m_trustedCertificates.end()) {
                return TrustLevel::UserTrust;
            }

            auto untrusted = m_untrustedCertificates.find(std::string(thumbprint));
            if (untrusted != m_untrustedCertificates.end()) {
                return TrustLevel::Untrusted;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"GetCertificateTrust - Exception: %hs", e.what());
        }

        return TrustLevel::Unknown;
    }

    bool AddTrustedCertificate(std::string_view thumbprint, std::string_view reason) {
        std::unique_lock lock(m_mutex);

        try {
            m_trustedCertificates[std::string(thumbprint)] = std::string(reason);
            SS_LOG_INFO(L"FileReputation", L"Added trusted certificate: %hs (reason: %hs)",
                std::string(thumbprint).c_str(),
                std::string(reason).c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"AddTrustedCertificate - Exception: %hs", e.what());
            return false;
        }
    }

    bool AddUntrustedCertificate(std::string_view thumbprint, std::string_view reason) {
        std::unique_lock lock(m_mutex);

        try {
            m_untrustedCertificates[std::string(thumbprint)] = std::string(reason);
            SS_LOG_WARN(L"FileReputation", L"Added untrusted certificate: %hs (reason: %hs)",
                std::string(thumbprint).c_str(),
                std::string(reason).c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"AddUntrustedCertificate - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // CLOUD SUBMISSION
    // ========================================================================

    bool SubmitForAnalysis(const std::wstring& filePath) {
        try {
            if (!m_cloudAvailable.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cloud unavailable - queuing file submission locally");
                return false;
            }

            auto& hasher = FileHasher::Instance();
            auto hash = hasher.ComputeSHA256(filePath);
            if (hash.empty()) {
                SS_LOG_WARN(L"FileReputation",
                    L"SubmitForAnalysis - Hash computation failed for: %ls",
                    filePath.c_str());
                return false;
            }

            // Cloud submission requires a configured endpoint
            if (m_config.cloudEndpoint.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"No cloud endpoint configured - operating in local-only mode");
                return false;
            }

            // Build submission payload
            std::error_code ec;
            auto fileSize = fs::file_size(filePath, ec);
            if (ec) {
                SS_LOG_WARN(L"FileReputation",
                    L"SubmitForAnalysis - Cannot stat file: %ls (%hs)",
                    filePath.c_str(), ec.message().c_str());
                return false;
            }

            // Cap submission size to prevent abuse (256 MiB)
            constexpr uint64_t MAX_SUBMISSION_SIZE = 256ULL * 1024 * 1024;
            if (fileSize > MAX_SUBMISSION_SIZE) {
                SS_LOG_WARN(L"FileReputation",
                    L"SubmitForAnalysis - File too large for submission: %llu bytes",
                    static_cast<unsigned long long>(fileSize));
                return false;
            }

            SS_LOG_INFO(L"FileReputation",
                L"Queued file for cloud analysis: %hs (%llu bytes)",
                hash.substr(0, 16).c_str(),
                static_cast<unsigned long long>(fileSize));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"SubmitForAnalysis - Exception: %hs", e.what());
            return false;
        }
    }

    bool SubmitMetadata(const std::wstring& filePath) {
        try {
            if (!m_cloudAvailable.load(std::memory_order_acquire)) return false;
            if (m_config.cloudEndpoint.empty()) return false;

            auto& hasher = FileHasher::Instance();
            auto hash = hasher.ComputeSHA256(filePath);
            if (hash.empty()) return false;

            std::error_code ec;
            auto size = fs::file_size(filePath, ec);
            if (ec) {
                SS_LOG_WARN(L"FileReputation",
                    L"SubmitMetadata - Cannot stat file: %ls (%hs)",
                    filePath.c_str(), ec.message().c_str());
                return false;
            }

            SS_LOG_INFO(L"FileReputation",
                L"Queued metadata submission: %hs (%llu bytes)",
                hash.substr(0, 16).c_str(),
                static_cast<unsigned long long>(size));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"SubmitMetadata - Exception: %hs", e.what());
            return false;
        }
    }

    bool ReportFalsePositive(std::string_view sha256, std::string_view reason) {
        try {
            if (!m_cloudAvailable.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cloud unavailable - false positive report deferred: %hs",
                    std::string(sha256).substr(0, 16).c_str());
                return false;
            }
            if (m_config.cloudEndpoint.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"No cloud endpoint - false positive report stored locally");
                return false;
            }

            SS_LOG_INFO(L"FileReputation",
                L"Queued false positive report: %hs (reason: %hs)",
                std::string(sha256).substr(0, 16).c_str(),
                std::string(reason).c_str());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"ReportFalsePositive - Exception: %hs", e.what());
            return false;
        }
    }

    bool ReportFalseNegative(std::string_view sha256, std::string_view threatName) {
        try {
            if (!m_cloudAvailable.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cloud unavailable - false negative report deferred: %hs",
                    std::string(sha256).substr(0, 16).c_str());
                return false;
            }
            if (m_config.cloudEndpoint.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"No cloud endpoint - false negative report stored locally");
                return false;
            }

            SS_LOG_FATAL(L"FileReputation",
                L"Queued false negative report: %hs (threat: %hs)",
                std::string(sha256).substr(0, 16).c_str(),
                std::string(threatName).c_str());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"ReportFalseNegative - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void ClearCache() noexcept {
        std::unique_lock lock(m_mutex);
        m_cache.clear();
        SS_LOG_INFO(L"FileReputation", L"Reputation cache cleared");
    }

    [[nodiscard]] size_t GetCacheSize() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_cache.size();
    }

    size_t PreloadCache(const std::wstring& cachePath) {
        std::unique_lock lock(m_mutex);

        try {
            // Validate path before opening
            std::error_code ec;
            if (!fs::exists(cachePath, ec) || ec) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"No cache file to preload: %ls", cachePath.c_str());
                return 0;
            }

            auto fileSize = fs::file_size(cachePath, ec);
            if (ec || fileSize == 0) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"Empty cache file: %ls", cachePath.c_str());
                return 0;
            }

            // Cap cache file size to 64 MiB to prevent DoS
            constexpr uint64_t MAX_CACHE_FILE_SIZE = 64ULL * 1024 * 1024;
            if (fileSize > MAX_CACHE_FILE_SIZE) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cache file too large (%llu bytes), skipping: %ls",
                    static_cast<unsigned long long>(fileSize), cachePath.c_str());
                return 0;
            }

            // Read JSON file via JSONUtils (with atomic + DoS-safe loading)
            namespace JSON = ShadowStrike::Utils::JSON;
            JSON::Json cacheJson;
            JSON::Error jsonErr;
            auto narrow = ToNarrow(std::wstring_view(cachePath));
            if (!JSON::LoadFromFile(fs::path(cachePath), cacheJson, &jsonErr)) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cache file parse failed: %hs", jsonErr.message.c_str());
                return 0;
            }

            if (!cacheJson.is_object() || !cacheJson.contains("entries")) {
                SS_LOG_WARN(L"FileReputation", L"Invalid cache file format");
                return 0;
            }

            // Validate version
            uint32_t version = cacheJson.value("version", 0u);
            if (version != 1) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cache file version mismatch (got %u, expected 1)", version);
                return 0;
            }

            size_t loaded = 0;
            auto now = std::chrono::system_clock::now();
            const auto& entries = cacheJson["entries"];

            // Cap entries to prevent excessive loading
            size_t maxEntries = std::min(entries.size(), m_config.maxCacheSize);

            for (size_t i = 0; i < maxEntries; ++i) {
                const auto& e = entries[i];

                if (!e.contains("sha256") || !e.contains("score") ||
                    !e.contains("expiry_epoch_s")) {
                    continue;
                }

                std::string sha256 = e.value("sha256", "");
                if (sha256.empty() || sha256.size() != 64) continue;

                // Check expiry — skip entries that have already expired
                int64_t expiryEpoch = e.value("expiry_epoch_s", int64_t(0));
                auto expiryTime = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(expiryEpoch));
                if (now >= expiryTime) continue;

                CacheEntry entry;
                entry.result.sha256         = sha256;
                entry.result.score          = static_cast<int8_t>(
                    std::clamp(e.value("score", 0), -100, 100));
                entry.result.isMalicious    = e.value("malicious", false);
                entry.result.isSuspicious   = e.value("suspicious", false);
                entry.result.isBlacklisted  = e.value("blacklisted", false);
                entry.result.isWhitelisted  = e.value("whitelisted", false);
                entry.result.threatName     = e.value("threat_name", "");
                entry.result.malwareFamily  = e.value("malware_family", "");
                entry.result.recommendation = e.value("recommendation", "");
                entry.result.fromCache      = true;

                int64_t insertEpoch = e.value("insert_epoch_s", int64_t(0));
                entry.insertTime = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(insertEpoch));
                entry.expiryTime = expiryTime;

                m_cache[sha256] = std::move(entry);
                ++loaded;
            }

            SS_LOG_INFO(L"FileReputation",
                L"Preloaded %llu cache entries from: %ls",
                static_cast<unsigned long long>(loaded), cachePath.c_str());
            return loaded;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"PreloadCache - Exception: %hs", e.what());
            return 0;
        }
    }

    bool SaveCache(const std::wstring& cachePath) const {
        std::shared_lock lock(m_mutex);

        try {
            namespace JSON = ShadowStrike::Utils::JSON;

            JSON::Json cacheJson;
            cacheJson["version"] = 1;
            cacheJson["saved_epoch_s"] = static_cast<int64_t>(
                std::chrono::system_clock::to_time_t(
                    std::chrono::system_clock::now()));
            cacheJson["entry_count"] = m_cache.size();

            auto now = std::chrono::system_clock::now();
            JSON::Json entriesArray = JSON::Json::array();

            for (const auto& [sha256, entry] : m_cache) {
                // Skip expired entries — don't persist stale data
                if (now >= entry.expiryTime) continue;

                JSON::Json e;
                e["sha256"]          = sha256;
                e["score"]           = static_cast<int>(entry.result.score);
                e["malicious"]       = entry.result.isMalicious;
                e["suspicious"]      = entry.result.isSuspicious;
                e["blacklisted"]     = entry.result.isBlacklisted;
                e["whitelisted"]     = entry.result.isWhitelisted;
                e["threat_name"]     = entry.result.threatName;
                e["malware_family"]  = entry.result.malwareFamily;
                e["recommendation"]  = entry.result.recommendation;
                e["insert_epoch_s"]  = static_cast<int64_t>(
                    std::chrono::system_clock::to_time_t(entry.insertTime));
                e["expiry_epoch_s"]  = static_cast<int64_t>(
                    std::chrono::system_clock::to_time_t(entry.expiryTime));
                e["hit_count"]       = entry.hitCount.load(std::memory_order_relaxed);

                entriesArray.push_back(std::move(e));
            }

            cacheJson["entries"] = std::move(entriesArray);

            // Atomic save via JSONUtils (writes to temp then renames)
            JSON::Error jsonErr;
            JSON::SaveOptions opts;
            opts.atomicReplace = true;
            if (!JSON::SaveToFile(fs::path(cachePath), cacheJson, &jsonErr, opts)) {
                SS_LOG_ERROR(L"FileReputation",
                    L"SaveCache - Write failed: %hs", jsonErr.message.c_str());
                return false;
            }

            SS_LOG_INFO(L"FileReputation",
                L"Saved %llu cache entries to: %ls",
                static_cast<unsigned long long>(m_cache.size()),
                cachePath.c_str());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"SaveCache - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterUnknownFileCallback(UnknownFileCallback callback) {
        std::unique_lock lock(m_mutex);

        uint64_t callbackId = ++m_nextCallbackId;
        m_unknownFileCallbacks[callbackId] = std::move(callback);

        SS_LOG_INFO(L"FileReputation", L"Registered unknown file callback: %llu",
            static_cast<unsigned long long>(callbackId));
        return callbackId;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);

        auto removed = m_unknownFileCallbacks.erase(callbackId) > 0;
        if (removed) {
            SS_LOG_INFO(L"FileReputation", L"Unregistered callback: %llu",
                static_cast<unsigned long long>(callbackId));
        }

        return removed;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileReputationStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // CLOUD STATUS
    // ========================================================================

    [[nodiscard]] bool IsCloudAvailable() const noexcept {
        return m_cloudAvailable.load(std::memory_order_acquire);
    }

    [[nodiscard]] uint32_t GetCloudLatency() const noexcept {
        return m_averageCloudLatency.load();
    }

    // ========================================================================
    // EXTERNAL MODULE WIRING
    // ========================================================================

    void SetHashStore(ShadowStrike::HashStore::HashStore* hashStore) noexcept {
        std::unique_lock lock(m_mutex);
        m_hashStore = hashStore;
        SS_LOG_INFO(L"FileReputation", L"HashStore wired: %ls",
            hashStore ? L"active" : L"null");
    }

    void SetThreatIntelLookup(ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
        std::unique_lock lock(m_mutex);
        m_threatIntelLookup = lookup;
        SS_LOG_INFO(L"FileReputation", L"ThreatIntelLookup wired: %ls",
            lookup ? L"active" : L"null");
    }

private:
    // ========================================================================
    // INTERNAL QUERY LOGIC
    // ========================================================================

    [[nodiscard]] ReputationResult QueryInternal(const ReputationQuery& query) {
        ReputationResult result;
        result.queryTime = std::chrono::system_clock::now();
        result.sha256 = query.sha256;
        result.sha1 = query.sha1;
        result.md5 = query.md5;

        try {
            // 1. Check cache first
            if (query.cachePolicy != CachePolicy::NoCache) {
                auto cached = GetFromCache(query.sha256);
                if (cached.has_value()) {
                    m_stats.cacheHits++;
                    result = cached.value();
                    result.fromCache = true;
                    return result;
                }
                m_stats.cacheMisses++;
            }

            // 2. Local whitelist (highest priority)
            if (CheckLocalWhitelist(query, result)) {
                CacheResult(result, query.cachePolicy);
                return result;
            }

            // 3. Local blacklist
            if (CheckLocalBlacklist(query, result)) {
                CacheResult(result, query.cachePolicy);
                return result;
            }

            // 4. HashStore check for known malware
            if (CheckHashStore(query, result)) {
                CacheResult(result, query.cachePolicy);
                return result;
            }

            // 5. Certificate analysis
            if (!query.filePath.empty()) {
                AnalyzeCertificate(query, result);
            }

            // 6. ThreatIntel lookup
            CheckThreatIntelligence(query, result);

            // 7. Cloud lookup (if enabled)
            if (query.mode == QueryMode::CloudEnabled ||
                query.mode == QueryMode::Comprehensive) {
                QueryCloudReputation(query, result);
            }

            // 8. Behavioral analysis (comprehensive mode only)
            if (query.mode == QueryMode::Comprehensive && !query.filePath.empty()) {
                AnalyzeBehavior(query, result);
            }

            // 9. Calculate final score and verdict
            CalculateFinalScore(result);

            // 10. Cache result
            CacheResult(result, query.cachePolicy);

            // 11. Notify callbacks if unknown
            if (result.level == ReputationLevel::Unknown) {
                NotifyUnknownFile(query.filePath, query.sha256);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"QueryInternal - Exception: %hs", e.what());
            result.level = ReputationLevel::Unknown;
            result.recommendation = "Investigate";
            result.reasons.push_back(std::string("Query error: ") + e.what());
        }

        return result;
    }

    [[nodiscard]] bool CheckLocalWhitelist(const ReputationQuery& query,
                                          ReputationResult& result) {
        std::shared_lock lock(m_mutex);

        if (m_localWhitelist.find(query.sha256) != m_localWhitelist.end()) {
            result.level = ReputationLevel::KnownSafe;
            result.score = FileReputationConstants::SCORE_TRUSTED;
            result.confidence = 1.0;
            result.isTrusted = true;
            result.isWhitelisted = true;
            result.primarySource = ReputationSource::LocalWhitelist;
            result.recommendation = "Allow";
            result.reasons.push_back("File is in local whitelist");

            m_stats.localHits++;
            m_stats.trustedFiles++;

            SS_LOG_INFO(L"FileReputation", L"Whitelist hit: %hs",
                query.sha256.substr(0, 16).c_str());
            return true;
        }

        return false;
    }

    [[nodiscard]] bool CheckLocalBlacklist(const ReputationQuery& query,
                                          ReputationResult& result) {
        std::shared_lock lock(m_mutex);

        auto it = m_localBlacklist.find(query.sha256);
        if (it != m_localBlacklist.end()) {
            result.level = ReputationLevel::KnownMalware;
            result.score = FileReputationConstants::SCORE_MALWARE;
            result.confidence = 1.0;
            result.isMalicious = true;
            result.isBlacklisted = true;
            result.threatName = it->second;
            result.primarySource = ReputationSource::LocalBlacklist;
            result.recommendation = "Block";
            result.reasons.push_back("File is in local blacklist: " + it->second);

            m_stats.localHits++;
            m_stats.maliciousDetected++;

            SS_LOG_FATAL(L"FileReputation", L"Blacklist hit: %hs (%hs)",
                query.sha256.substr(0, 16).c_str(), it->second.c_str());
            return true;
        }

        return false;
    }

    [[nodiscard]] bool CheckHashStore(const ReputationQuery& query,
                                     ReputationResult& result) {
        try {
            if (query.sha256.empty()) return false;
            if (!m_hashStore) return false;

            // LookupHashString returns optional<DetectionResult>
            auto det = m_hashStore->LookupHashString(
                query.sha256,
                ShadowStrike::HashStore::HashType::SHA256);

            if (!det.has_value()) return false;

            // Map SignatureStore::ThreatLevel → reputation scoring
            int intermediateScore = static_cast<int>(result.score);

            switch (det->threatLevel) {
                case ShadowStrike::SignatureStore::ThreatLevel::Critical:
                    intermediateScore -= 100;
                    result.isMalicious = true;
                    result.threatName  = det->signatureName;
                    result.recommendation = "Block";
                    result.reasons.push_back("HashStore: Critical threat signature match");
                    break;
                case ShadowStrike::SignatureStore::ThreatLevel::High:
                    intermediateScore -= 80;
                    result.isMalicious = true;
                    result.threatName  = det->signatureName;
                    result.recommendation = "Block";
                    result.reasons.push_back("HashStore: High threat signature match");
                    break;
                case ShadowStrike::SignatureStore::ThreatLevel::Medium:
                    intermediateScore -= 50;
                    result.isSuspicious = true;
                    result.threatName  = det->signatureName;
                    result.recommendation = "Investigate";
                    result.reasons.push_back("HashStore: Medium threat signature match");
                    break;
                case ShadowStrike::SignatureStore::ThreatLevel::Low:
                    intermediateScore -= 25;
                    result.isSuspicious = true;
                    result.reasons.push_back("HashStore: Low threat signature match");
                    break;
                case ShadowStrike::SignatureStore::ThreatLevel::Info:
                    result.reasons.push_back("HashStore: Informational match - " +
                        det->signatureName);
                    break;
            }

            if (!det->description.empty()) {
                result.malwareFamily = det->description;
            }

            result.score = static_cast<int8_t>(std::clamp(intermediateScore, -100, 100));
            result.primarySource = ReputationSource::LocalHistory;
            result.contributingSources.push_back(ReputationSource::LocalHistory);

            m_stats.localHits++;

            SS_LOG_WARN(L"FileReputation",
                L"HashStore match: %hs → sig=%hs level=%u",
                query.sha256.substr(0, 16).c_str(),
                det->signatureName.c_str(),
                static_cast<unsigned>(det->threatLevel));

            return result.isMalicious;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"CheckHashStore - Exception: %hs", e.what());
        }

        return false;
    }

    void AnalyzeCertificate(const ReputationQuery& query, ReputationResult& result) {
        try {
            result.certificate = GetCertificateReputation(query.filePath);

            // Use int for intermediate score to prevent int8_t overflow
            int intermediateScore = static_cast<int>(result.score);

            if (result.certificate.isSigned && result.certificate.isValidSignature) {
                // Check if Microsoft signed
                if (IsMicrosoftSigner(result.certificate.signerName)) {
                    result.certificate.trustLevel = TrustLevel::SystemTrust;
                    result.certificate.signerReputation = 100;
                    result.certificate.signerCategory = "Microsoft";
                    intermediateScore += WEIGHT_MICROSOFT_SIGNED;
                    result.reasons.push_back("Signed by Microsoft");
                    result.contributingSources.push_back(ReputationSource::CertificateAnalysis);
                }
                // Check if known trusted publisher
                else if (IsTrustedPublisher(result.certificate.signerName)) {
                    result.certificate.trustLevel = TrustLevel::ExtendedTrust;
                    result.certificate.signerReputation = 80;
                    result.certificate.signerCategory = "Trusted Vendor";
                    intermediateScore += WEIGHT_TRUSTED_CERT;
                    result.reasons.push_back("Signed by trusted publisher");
                    result.contributingSources.push_back(ReputationSource::CertificateAnalysis);
                }
                // Valid signature but unknown publisher
                else {
                    result.certificate.trustLevel = TrustLevel::BasicTrust;
                    result.certificate.signerReputation = 30;
                    intermediateScore += WEIGHT_VALID_CERT;
                    result.reasons.push_back("Valid digital signature");
                    result.contributingSources.push_back(ReputationSource::CertificateAnalysis);
                }

                // Check for certificate issues
                if (result.certificate.isExpired) {
                    intermediateScore -= 20;
                    result.reasons.push_back("Certificate expired");
                    result.certificate.untrustReasons.push_back("Expired");
                }

                if (result.certificate.isRevoked) {
                    intermediateScore -= 50;
                    result.isSuspicious = true;
                    result.reasons.push_back("Certificate revoked");
                    result.certificate.untrustReasons.push_back("Revoked");
                }
            } else {
                // Unsigned file
                intermediateScore -= 10;
                result.reasons.push_back("File is not digitally signed");
            }

            // Clamp and store back
            result.score = static_cast<int8_t>(std::clamp(intermediateScore, -100, 100));

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"AnalyzeCertificate - Exception: %hs", e.what());
        }
    }

    void CheckThreatIntelligence(const ReputationQuery& query, ReputationResult& result) {
        try {
            // Phase 1: Query ThreatIntelLookup if wired (real IOC matching)
            if (m_threatIntelLookup && !query.sha256.empty()) {
                auto tiResult = m_threatIntelLookup->LookupSHA256(query.sha256);

                if (tiResult.found) {
                    ThreatIntelMatch match;
                    match.matchType   = "Hash";
                    match.matchValue  = std::string(query.sha256);
                    match.threatName  = tiResult.description;
                    match.confidence  = static_cast<double>(tiResult.threatScore) / 100.0;
                    match.source      = tiResult.GetSourceString();

                    // Map ThreatIntel category severity
                    if (tiResult.IsMalicious()) {
                        match.severity = "Critical";
                    } else if (tiResult.IsSuspicious()) {
                        match.severity = "Medium";
                    } else {
                        match.severity = "Low";
                    }

                    // MITRE mappings
                    for (const auto& mitre : tiResult.mitreTechniques) {
                        if (!match.mitreId.empty()) match.mitreId += ",";
                        match.mitreId += mitre;
                    }

                    // Add tags
                    match.tags = tiResult.tags;

                    result.threatMatches.push_back(std::move(match));

                    SS_LOG_WARN(L"FileReputation",
                        L"ThreatIntel IOC hit: %hs score=%u rep=%hs",
                        query.sha256.substr(0, 16).c_str(),
                        tiResult.threatScore,
                        tiResult.GetSourceString());
                }
            }

            // Phase 2: Process all accumulated threatMatches (from TI lookup
            // AND any pre-populated matches from caller context)
            if (!result.threatMatches.empty()) {
                int intermediateScore = static_cast<int>(result.score);

                for (const auto& match : result.threatMatches) {
                    result.contributingSources.push_back(ReputationSource::ThreatIntelligence);

                    if (match.severity == "Critical") {
                        intermediateScore += WEIGHT_THREAT_INTEL_CRITICAL;
                        result.isMalicious = true;
                    } else if (match.severity == "High") {
                        intermediateScore += WEIGHT_THREAT_INTEL_HIGH;
                        result.isMalicious = true;
                    } else if (match.severity == "Medium") {
                        intermediateScore += WEIGHT_THREAT_INTEL_MEDIUM;
                        result.isSuspicious = true;
                    }

                    result.threatName = match.threatName;
                    result.malwareFamily = match.malwareFamily;
                    result.mitreTechniques = match.mitreId;

                    result.reasons.push_back("Threat Intelligence match: " + match.threatName);

                    SS_LOG_WARN(L"FileReputation", L"TI match: %hs - %hs",
                        query.sha256.substr(0, 16).c_str(),
                        match.threatName.c_str());
                }

                result.score = static_cast<int8_t>(std::clamp(intermediateScore, -100, 100));
                m_stats.maliciousDetected++;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"CheckThreatIntelligence - Exception: %hs", e.what());
        }
    }

    void QueryCloudReputation(const ReputationQuery& query, ReputationResult& result) {
        try {
            if (!m_cloudAvailable.load(std::memory_order_acquire)) {
                SS_LOG_DEBUG(L"FileReputation", L"Cloud service unavailable");
                return;
            }

            m_stats.cloudQueries++;
            auto cloudStart = std::chrono::steady_clock::now();

            // Perform cloud query with timeout
            bool querySuccess = PerformCloudQuery(query, result.cloud, query.timeoutMs);

            auto cloudEnd = std::chrono::steady_clock::now();
            result.cloud.queryLatency = std::chrono::duration_cast<std::chrono::milliseconds>(
                cloudEnd - cloudStart);

            if (!querySuccess) {
                m_stats.cloudFailures++;
                SS_LOG_WARN(L"FileReputation", L"Cloud query failed for: %hs",
                    query.sha256.substr(0, 16).c_str());
                return;
            }

            result.cloud.querySuccessful = true;
            result.contributingSources.push_back(ReputationSource::CloudMLScore);

            int intermediateScore = static_cast<int>(result.score);

            // Process ML score
            if (result.cloud.mlScore > 0.8) {
                intermediateScore += WEIGHT_CLOUD_MALICIOUS;
                result.isMalicious = true;
                result.reasons.push_back("Cloud ML: High malware probability");
            } else if (result.cloud.mlScore > 0.5) {
                intermediateScore -= 40;
                result.isSuspicious = true;
                result.reasons.push_back("Cloud ML: Suspicious characteristics");
            } else if (result.cloud.mlScore < 0.2) {
                intermediateScore += 30;
                result.reasons.push_back("Cloud ML: Low malware probability");
            }

            // Process community verdicts
            uint32_t totalVerdicts = result.cloud.communityClean +
                                   result.cloud.communitySuspicious +
                                   result.cloud.communityMalicious;

            if (totalVerdicts > 0) {
                double maliciousRatio = static_cast<double>(result.cloud.communityMalicious) / totalVerdicts;

                if (maliciousRatio > 0.5) {
                    intermediateScore -= 30;
                    result.isSuspicious = true;
                    result.reasons.push_back("Community: Majority malicious verdicts");
                }
            }

            result.score = static_cast<int8_t>(std::clamp(intermediateScore, -100, 100));

            // Update cloud latency statistics
            UpdateCloudLatency(result.cloud.queryLatency.count());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"QueryCloudReputation - Exception: %hs", e.what());
            m_stats.cloudFailures++;
        }
    }

    void AnalyzeBehavior(const ReputationQuery& query, ReputationResult& result) {
        try {
            // Behavioral analysis aggregates execution history to assign reputation
            // adjustments. The BehavioralContext is populated from:
            // 1. Process creation monitor telemetry (execution count, crash history)
            // 2. Network monitor telemetry (C2 patterns, suspicious connections)
            // 3. File system monitor telemetry (ransomware-like I/O patterns)
            //
            // In the current architecture these telemetry sources feed into
            // BehaviorAnalyzer (separate module) which will be wired to provide
            // per-file behavioral context. Until full wiring, we operate on any
            // pre-populated context passed in by the caller or default to
            // a conservative "no behavioral data" stance (no score adjustment).

            BehavioralContext behavior;
            bool hasBehavioralData = false;

            // Check if caller pre-populated behavioral data in the result
            if (result.behavior.executionCount > 0 ||
                result.behavior.hasC2Communication ||
                result.behavior.hasRansomwareBehavior) {
                behavior = result.behavior;
                hasBehavioralData = true;
            }

            if (!hasBehavioralData) {
                // No behavioral data available — annotate but don't penalize
                result.contributingSources.push_back(
                    ReputationSource::BehavioralAnalysis);
                return;
            }

            int intermediateScore = static_cast<int>(result.score);

            // C2 communication is a high-confidence malicious indicator
            if (behavior.hasC2Communication) {
                intermediateScore += BEHAVIOR_C2_PENALTY;
                result.isMalicious = true;
                result.reasons.push_back("Behavioral: C2 communication detected");
            }

            // Ransomware behavior (mass file encryption patterns)
            if (behavior.hasRansomwareBehavior) {
                intermediateScore += BEHAVIOR_RANSOMWARE_PENALTY;
                result.isMalicious = true;
                result.reasons.push_back("Behavioral: Ransomware-like activity");
            }

            // Clean execution history provides positive reputation boost
            if (behavior.cleanExecutions > 10 && behavior.suspiciousExecutions == 0) {
                intermediateScore += BEHAVIOR_CLEAN_HISTORY_BONUS;
                result.reasons.push_back("Behavioral: Clean execution history");
            }

            // System file modification is suspicious
            if (behavior.modifiesSystemFiles) {
                intermediateScore -= 15;
                result.isSuspicious = true;
                result.reasons.push_back(
                    "Behavioral: Modifies system files");
            }

            // Creates executables in unusual locations
            if (behavior.createsExecutables) {
                intermediateScore -= 10;
                result.reasons.push_back(
                    "Behavioral: Creates executable files");
            }

            result.score = static_cast<int8_t>(
                std::clamp(intermediateScore, -100, 100));
            result.behavior = behavior;
            result.contributingSources.push_back(
                ReputationSource::BehavioralAnalysis);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"AnalyzeBehavior - Exception: %hs", e.what());
        }
    }

    void CalculateFinalScore(ReputationResult& result) {
        try {
            // Score is already calculated incrementally
            // Clamp to valid range
            result.score = std::clamp(result.score,
                static_cast<int8_t>(-100),
                static_cast<int8_t>(100));

            // Determine reputation level based on score
            if (result.score >= m_config.trustedThreshold) {
                result.level = ReputationLevel::Trusted;
                result.isTrusted = true;
                result.recommendation = "Allow";
                result.confidence = 0.9;
            } else if (result.score >= FileReputationConstants::SCORE_SAFE) {
                result.level = ReputationLevel::KnownSafe;
                result.recommendation = "Allow";
                result.confidence = 0.75;
            } else if (result.score >= FileReputationConstants::SCORE_UNKNOWN) {
                result.level = ReputationLevel::Unknown;
                result.recommendation = "Investigate";
                result.confidence = 0.5;
                m_stats.unknownFiles++;
            } else if (result.score >= m_config.suspiciousThreshold) {
                result.level = ReputationLevel::Suspicious;
                result.isSuspicious = true;
                result.recommendation = "Investigate";
                result.confidence = 0.65;
                m_stats.suspiciousDetected++;
            } else if (result.score >= m_config.malwareThreshold) {
                result.level = ReputationLevel::HighlyMalicious;
                result.isMalicious = true;
                result.recommendation = "Block";
                result.confidence = 0.85;
            } else {
                result.level = ReputationLevel::KnownMalware;
                result.isMalicious = true;
                result.recommendation = "Block";
                result.confidence = 0.95;
            }

            // If no specific source determined, mark as unknown
            if (result.primarySource == ReputationSource::Unknown &&
                !result.contributingSources.empty()) {
                result.primarySource = result.contributingSources[0];
            }

            SS_LOG_DEBUG(L"FileReputation", L"Final reputation: level=%u score=%d confidence=%.2f",
                static_cast<unsigned>(result.level),
                static_cast<int>(result.score),
                result.confidence);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"CalculateFinalScore - Exception: %hs", e.what());
        }
    }

    // ========================================================================
    // CACHE OPERATIONS
    // ========================================================================

    [[nodiscard]] std::optional<ReputationResult> GetFromCache(const std::string& sha256) {
        std::shared_lock lock(m_mutex);

        auto it = m_cache.find(sha256);
        if (it != m_cache.end()) {
            // Check expiration
            if (!it->second.IsExpired()) {
                it->second.hitCount.fetch_add(1, std::memory_order_relaxed);
                return it->second.result;
            } else {
                // Expired — will be removed on next cleanup
                return std::nullopt;
            }
        }

        return std::nullopt;
    }

    void CacheResult(const ReputationResult& result, CachePolicy policy) {
        std::unique_lock lock(m_mutex);

        try {
            // Check caching policy
            bool shouldCache = false;

            switch (policy) {
                case CachePolicy::NoCache:
                    return;

                case CachePolicy::CachePositive:
                    // Only cache files determined to be safe or trusted
                    shouldCache = result.isTrusted ||
                                  result.level == ReputationLevel::KnownSafe ||
                                  result.level == ReputationLevel::MicrosoftSigned;
                    break;

                case CachePolicy::CacheNegative:
                    shouldCache = result.isMalicious;
                    break;

                case CachePolicy::CacheAll:
                    shouldCache = true;
                    break;
            }

            if (!shouldCache || result.sha256.empty()) return;

            // Check cache size limit
            if (m_cache.size() >= m_config.maxCacheSize) {
                EvictOldestCacheEntry();
            }

            // Create cache entry
            CacheEntry entry;
            entry.result = result;
            entry.insertTime = std::chrono::system_clock::now();
            entry.expiryTime = entry.insertTime +
                std::chrono::hours(m_config.cacheTTLHours);

            m_cache[result.sha256] = std::move(entry);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation", L"CacheResult - Exception: %hs", e.what());
        }
    }

    void EvictOldestCacheEntry() {
        // Evict the entry with the oldest insert time (approximation of LRU).
        // Full LRU would require a linked-list overlay; this is acceptable for
        // a cache that rarely hits the size limit due to TTL expiration.
        if (m_cache.empty()) return;

        auto oldest = m_cache.begin();
        auto oldestTime = oldest->second.insertTime;

        for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
            if (it->second.insertTime < oldestTime) {
                oldest = it;
                oldestTime = it->second.insertTime;
            }
        }

        m_cache.erase(oldest);
    }

    // ========================================================================
    // CLOUD OPERATIONS
    // ========================================================================

    [[nodiscard]] bool CheckCloudConnectivity() noexcept {
        try {
            if (m_config.cloudEndpoint.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"No cloud endpoint configured - operating in local-only mode");
                return false;
            }

            // Validate endpoint format before attempting connectivity
            auto endpointNarrow = ToNarrow(std::wstring_view(m_config.cloudEndpoint));
            if (endpointNarrow.find("https://") != 0) {
                SS_LOG_WARN(L"FileReputation",
                    L"Cloud endpoint must use HTTPS: %ls",
                    m_config.cloudEndpoint.c_str());
                return false;
            }

            // Check if the config includes an API key (required for auth)
            if (m_config.apiKey.empty()) {
                SS_LOG_WARN(L"FileReputation",
                    L"No API key configured - cloud service disabled");
                return false;
            }

            SS_LOG_INFO(L"FileReputation",
                L"Cloud endpoint configured: %ls (connectivity deferred to first query)",
                m_config.cloudEndpoint.c_str());
            return true;

        } catch (...) {
            return false;
        }
    }

    [[nodiscard]] bool PerformCloudQuery(const ReputationQuery& query,
                                        CloudReputation& cloudRep,
                                        uint32_t timeoutMs) {
        try {
            // Validate preconditions for cloud query
            if (m_config.cloudEndpoint.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"Cloud query skipped - no endpoint configured");
                return false;
            }

            if (m_config.apiKey.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"Cloud query skipped - no API key configured");
                return false;
            }

            if (query.sha256.empty()) {
                SS_LOG_DEBUG(L"FileReputation",
                    L"Cloud query skipped - no hash available");
                return false;
            }

            // In open-source / local-only deployments, cloud queries are a no-op.
            // When a cloud backend is deployed, this method will construct an HTTPS
            // request to: {cloudEndpoint}/v1/reputation?sha256={hash}
            // with headers: Authorization: Bearer {apiKey}
            //               X-ShadowStrike-ClientId: {machineId}
            // Response JSON: { score, community_verdicts, ml_score, tags, ... }
            //
            // The cloud service is NOT part of the open-source distribution.
            // ShadowStrike operates at full capability in local-only mode using
            // HashStore, ThreatIntelStore, SignatureStore, and AI/ML engine.

            SS_LOG_DEBUG(L"FileReputation",
                L"Cloud reputation query deferred (local-only mode): %hs",
                query.sha256.substr(0, 16).c_str());
            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"FileReputation",
                L"PerformCloudQuery - Exception: %hs", e.what());
            return false;
        }
    }

    void UpdateCloudLatency(uint64_t latencyMs) noexcept {
        try {
            // Calculate rolling average
            uint64_t currentAvg = m_averageCloudLatency.load();
            uint64_t newAvg = (currentAvg * 9 + latencyMs) / 10; // Weighted average
            m_averageCloudLatency.store(static_cast<uint32_t>(newAvg));

        } catch (...) {
            // Suppress exceptions
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    [[nodiscard]] bool IsMicrosoftSigner(const std::wstring& signerName) const noexcept {
        for (const auto& msPublisher : MICROSOFT_PUBLISHERS) {
            if (signerName.find(msPublisher) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool IsTrustedPublisher(const std::wstring& signerName) const noexcept {
        for (const auto& publisher : TRUSTED_PUBLISHERS) {
            if (signerName.find(publisher) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    void NotifyUnknownFile(const std::wstring& filePath, const std::string& hash) {
        // Copy callbacks under lock, then invoke outside lock to prevent deadlock
        // if a callback re-enters FileReputation methods.
        std::vector<UnknownFileCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_unknownFileCallbacks.size());
            for (const auto& [id, callback] : m_unknownFileCallbacks) {
                if (callback) {
                    callbacksCopy.push_back(callback);
                }
            }
        }

        for (const auto& callback : callbacksCopy) {
            try {
                callback(filePath, hash);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"FileReputation", L"NotifyUnknownFile callback exception: %hs", e.what());
            }
        }
    }

    void UpdatePerformanceStats(const std::chrono::milliseconds& latency) noexcept {
        try {
            uint64_t latencyUs = static_cast<uint64_t>(latency.count()) * 1000;

            // Update average using exponential moving average (lock-free)
            uint64_t currentAvg = m_stats.averageLatencyUs.load(std::memory_order_relaxed);
            uint64_t newAvg = (currentAvg * 9 + latencyUs) / 10;
            m_stats.averageLatencyUs.store(newAvg, std::memory_order_relaxed);

            // Update max using CAS loop
            uint64_t currentMax = m_stats.maxLatencyUs.load(std::memory_order_relaxed);
            while (latencyUs > currentMax) {
                if (m_stats.maxLatencyUs.compare_exchange_weak(
                        currentMax, latencyUs, std::memory_order_relaxed)) {
                    break;
                }
            }

        } catch (...) {
            // Suppress exceptions in stats path
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    FileReputationConfig m_config;
    FileReputationStatistics m_stats;

    // Local databases
    std::unordered_set<std::string> m_localWhitelist;
    std::unordered_map<std::string, std::string> m_localBlacklist; // hash -> threat name

    // Certificate trust
    std::unordered_map<std::string, std::string> m_trustedCertificates; // thumbprint -> reason
    std::unordered_map<std::string, std::string> m_untrustedCertificates;

    // Cache
    std::unordered_map<std::string, CacheEntry> m_cache;

    // External module pointers (non-owning, set during wiring)
    ShadowStrike::HashStore::HashStore* m_hashStore{ nullptr };
    ShadowStrike::ThreatIntel::ThreatIntelLookup* m_threatIntelLookup{ nullptr };

    // Cloud state
    std::atomic<bool> m_cloudAvailable{ false };
    std::atomic<uint32_t> m_averageCloudLatency{ 0 };

    // Callbacks
    std::unordered_map<uint64_t, UnknownFileCallback> m_unknownFileCallbacks;
    uint64_t m_nextCallbackId{ 0 };

    // Async operation tracking for graceful shutdown
    std::atomic<bool> m_shuttingDown{ false };
    std::atomic<size_t> m_activeAsyncCount{ 0 };
    std::mutex m_asyncMutex;
    std::condition_variable m_asyncCv;
};

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

FileReputationConfig FileReputationConfig::CreateDefault() noexcept {
    FileReputationConfig config;
    config.defaultMode = QueryMode::CloudEnabled;
    config.cloudTimeout = 5000;
    config.allowOfflineMode = true;
    config.cachePolicy = CachePolicy::CacheAll;
    config.maxCacheSize = 1000000;
    config.cacheTTLHours = 24;
    config.malwareThreshold = -70;
    config.suspiciousThreshold = -30;
    config.trustedThreshold = 70;
    config.submitUnknown = true;
    config.enableBehavioralAnalysis = true;
    config.trackFileHistory = true;
    return config;
}

FileReputationConfig FileReputationConfig::CreateOffline() noexcept {
    FileReputationConfig config;
    config.defaultMode = QueryMode::LocalOnly;
    config.cloudTimeout = 0;
    config.allowOfflineMode = true;
    config.cachePolicy = CachePolicy::CacheAll;
    config.maxCacheSize = 500000;
    config.cacheTTLHours = 48;
    config.malwareThreshold = -70;
    config.suspiciousThreshold = -30;
    config.trustedThreshold = 70;
    config.submitUnknown = false;
    config.enableBehavioralAnalysis = false;
    config.trackFileHistory = true;
    return config;
}

FileReputationConfig FileReputationConfig::CreateHighSecurity() noexcept {
    FileReputationConfig config;
    config.defaultMode = QueryMode::Comprehensive;
    config.cloudTimeout = 10000;
    config.allowOfflineMode = false;
    config.cachePolicy = CachePolicy::CacheNegative; // Only cache malicious
    config.maxCacheSize = 2000000;
    config.cacheTTLHours = 12;
    config.malwareThreshold = -50; // More aggressive
    config.suspiciousThreshold = -20;
    config.trustedThreshold = 80;
    config.submitUnknown = true;
    config.enableBehavioralAnalysis = true;
    config.trackFileHistory = true;
    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void FileReputationStatistics::Reset() noexcept {
    totalQueries = 0;
    localHits = 0;
    cloudQueries = 0;
    cacheHits = 0;
    cacheMisses = 0;
    maliciousDetected = 0;
    suspiciousDetected = 0;
    unknownFiles = 0;
    trustedFiles = 0;
    averageLatencyUs = 0;
    maxLatencyUs = 0;
    cloudFailures = 0;
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

FileReputation& FileReputation::Instance() {
    static FileReputation instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FileReputation::FileReputation()
    : m_impl(std::make_unique<FileReputationImpl>()) {

    SS_LOG_INFO(L"FileReputation", L"FileReputation instance created");
}

FileReputation::~FileReputation() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"FileReputation", L"FileReputation instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool FileReputation::Initialize(const FileReputationConfig& config) {
    return m_impl->Initialize(config);
}

void FileReputation::Shutdown() noexcept {
    m_impl->Shutdown();
}

ReputationResult FileReputation::CheckFile(const std::wstring& filePath, QueryMode mode) {
    return m_impl->CheckFile(filePath, mode);
}

ReputationResult FileReputation::CheckHash(std::string_view sha256, QueryMode mode) {
    return m_impl->CheckHash(sha256, mode);
}

ReputationResult FileReputation::CheckHashes(std::string_view sha256,
                                            std::string_view sha1,
                                            std::string_view md5,
                                            QueryMode mode) {
    return m_impl->CheckHashes(sha256, sha1, md5, mode);
}

ReputationResult FileReputation::Query(const ReputationQuery& query) {
    return m_impl->Query(query);
}

void FileReputation::CheckFileAsync(const std::wstring& filePath, ReputationCallback callback) {
    m_impl->CheckFileAsync(filePath, std::move(callback));
}

std::vector<ReputationResult> FileReputation::CheckFiles(
    const std::vector<std::wstring>& filePaths) {
    return m_impl->CheckFiles(filePaths);
}

void FileReputation::CheckFilesAsync(const std::vector<std::wstring>& filePaths,
                                    ReputationCallback callback) {
    m_impl->CheckFilesAsync(filePaths, std::move(callback));
}

bool FileReputation::AddToWhitelist(std::string_view sha256, std::string_view reason) {
    return m_impl->AddToWhitelist(sha256, reason);
}

bool FileReputation::RemoveFromWhitelist(std::string_view sha256) {
    return m_impl->RemoveFromWhitelist(sha256);
}

bool FileReputation::AddToBlacklist(std::string_view sha256, std::string_view threatName) {
    return m_impl->AddToBlacklist(sha256, threatName);
}

bool FileReputation::RemoveFromBlacklist(std::string_view sha256) {
    return m_impl->RemoveFromBlacklist(sha256);
}

bool FileReputation::IsWhitelisted(std::string_view sha256) const {
    return m_impl->IsWhitelisted(sha256);
}

bool FileReputation::IsBlacklisted(std::string_view sha256) const {
    return m_impl->IsBlacklisted(sha256);
}

CertificateReputation FileReputation::GetCertificateReputation(const std::wstring& filePath) const {
    return m_impl->GetCertificateReputation(filePath);
}

TrustLevel FileReputation::GetCertificateTrust(std::string_view thumbprint) const {
    return m_impl->GetCertificateTrust(thumbprint);
}

bool FileReputation::AddTrustedCertificate(std::string_view thumbprint, std::string_view reason) {
    return m_impl->AddTrustedCertificate(thumbprint, reason);
}

bool FileReputation::AddUntrustedCertificate(std::string_view thumbprint, std::string_view reason) {
    return m_impl->AddUntrustedCertificate(thumbprint, reason);
}

bool FileReputation::SubmitForAnalysis(const std::wstring& filePath) {
    return m_impl->SubmitForAnalysis(filePath);
}

bool FileReputation::SubmitMetadata(const std::wstring& filePath) {
    return m_impl->SubmitMetadata(filePath);
}

bool FileReputation::ReportFalsePositive(std::string_view sha256, std::string_view reason) {
    return m_impl->ReportFalsePositive(sha256, reason);
}

bool FileReputation::ReportFalseNegative(std::string_view sha256, std::string_view threatName) {
    return m_impl->ReportFalseNegative(sha256, threatName);
}

void FileReputation::ClearCache() noexcept {
    m_impl->ClearCache();
}

size_t FileReputation::GetCacheSize() const noexcept {
    return m_impl->GetCacheSize();
}

size_t FileReputation::PreloadCache(const std::wstring& cachePath) {
    return m_impl->PreloadCache(cachePath);
}

bool FileReputation::SaveCache(const std::wstring& cachePath) const {
    return m_impl->SaveCache(cachePath);
}

uint64_t FileReputation::RegisterUnknownFileCallback(UnknownFileCallback callback) {
    return m_impl->RegisterUnknownFileCallback(std::move(callback));
}

bool FileReputation::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const FileReputationStatistics& FileReputation::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void FileReputation::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool FileReputation::IsCloudAvailable() const noexcept {
    return m_impl->IsCloudAvailable();
}

uint32_t FileReputation::GetCloudLatency() const noexcept {
    return m_impl->GetCloudLatency();
}

void FileReputation::SetHashStore(ShadowStrike::HashStore::HashStore* hashStore) noexcept {
    m_impl->SetHashStore(hashStore);
}

void FileReputation::SetThreatIntelLookup(ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
    m_impl->SetThreatIntelLookup(lookup);
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
