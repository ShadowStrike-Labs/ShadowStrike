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
 * ShadowStrike Security - DIGITAL SIGNATURE VALIDATION ENGINE
 * ============================================================================
 *
 * @file DigitalSignatureValidator.cpp
 * @brief Enterprise-grade Authenticode and digital signature verification
 *        implementation using Windows WinTrust API and CryptoAPI.
 *
 * Implementation Standards:
 *   - PIMPL pattern for ABI stability
 *   - Meyers' Singleton for thread-safe instantiation
 *   - std::shared_mutex for concurrent read/write access
 *   - Comprehensive error handling with structured logging
 *   - Statistics tracking for all operations
 *   - JSON serialization for diagnostics and reporting
 *   - Full WinTrust API integration for Authenticode verification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "DigitalSignatureValidator.hpp"

// ============================================================================
// WINDOWS SDK LIBRARIES
// ============================================================================

#ifdef _WIN32
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "imagehlp.lib")
#endif

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>
#include <filesystem>
#include <cwctype>
#include <mscat.h>     // Catalog admin APIs: CryptCATAdminAcquireContext2 / CalcHashFromFileHandle2
#include <bcrypt.h>    // BCRYPT_SHA256_ALGORITHM identifier (macro, no bcrypt.lib link needed)

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"DigitalSignatureValidator";

    /// Escape a narrow string for safe JSON embedding (prevent injection via cert CN).
    [[nodiscard]] std::string JsonEscape(std::string_view input) noexcept {
        std::string out;
        out.reserve(input.size() + 8);
        for (char c : input) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                        out += buf;
                    } else {
                        out += c;
                    }
                    break;
            }
        }
        return out;
    }

    /// Max file data we are willing to write into a temp file for memory verification.
    constexpr size_t MAX_MEMORY_VERIFY_SIZE = 256ULL * 1024 * 1024;  // 256 MB

    /// Chunk size for streaming hash calculation to avoid OOM.
    constexpr DWORD HASH_CHUNK_SIZE = 1024 * 1024;  // 1 MB
}

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> DigitalSignatureValidator::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetSignatureResultName(SignatureValidationResult result) noexcept {
    switch (result) {
        case SignatureValidationResult::Valid:              return "Valid";
        case SignatureValidationResult::InvalidSignature:   return "InvalidSignature";
        case SignatureValidationResult::InvalidHash:        return "InvalidHash";
        case SignatureValidationResult::Unsigned:           return "Unsigned";
        case SignatureValidationResult::UntrustedRoot:      return "UntrustedRoot";
        case SignatureValidationResult::Revoked:            return "Revoked";
        case SignatureValidationResult::Expired:            return "Expired";
        case SignatureValidationResult::NotYetValid:        return "NotYetValid";
        case SignatureValidationResult::BadTimestamp:       return "BadTimestamp";
        case SignatureValidationResult::TamperedFile:       return "TamperedFile";
        case SignatureValidationResult::InvalidCertificate: return "InvalidCertificate";
        case SignatureValidationResult::ChainError:         return "ChainError";
        case SignatureValidationResult::PolicyViolation:    return "PolicyViolation";
        case SignatureValidationResult::CatalogError:       return "CatalogError";
        case SignatureValidationResult::BlockedSigner:      return "BlockedSigner";
        case SignatureValidationResult::WeakAlgorithm:      return "WeakAlgorithm";
        case SignatureValidationResult::Error:              return "Error";
        default:                                  return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSignatureTypeName(SignatureType type) noexcept {
    switch (type) {
        case SignatureType::None:       return "None";
        case SignatureType::Embedded:   return "Embedded";
        case SignatureType::Catalog:    return "Catalog";
        case SignatureType::Detached:   return "Detached";
        case SignatureType::PowerShell: return "PowerShell";
        case SignatureType::VBScript:   return "VBScript";
        case SignatureType::MSI:        return "MSI";
        case SignatureType::APPX:       return "APPX";
        case SignatureType::CAB:        return "CAB";
        default:                        return "Unknown";
    }
}

[[nodiscard]] std::string_view GetHashAlgorithmName(SignatureHashAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case SignatureHashAlgorithm::Unknown: return "Unknown";
        case SignatureHashAlgorithm::MD5:     return "MD5";
        case SignatureHashAlgorithm::SHA1:    return "SHA1";
        case SignatureHashAlgorithm::SHA256:  return "SHA256";
        case SignatureHashAlgorithm::SHA384:  return "SHA384";
        case SignatureHashAlgorithm::SHA512:  return "SHA512";
        default:                     return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSignerTrustLevelName(SignerTrustLevel level) noexcept {
    switch (level) {
        case SignerTrustLevel::Untrusted:     return "Untrusted";
        case SignerTrustLevel::Known:         return "Known";
        case SignerTrustLevel::Trusted:       return "Trusted";
        case SignerTrustLevel::HighlyTrusted: return "HighlyTrusted";
        case SignerTrustLevel::EVValidated:   return "EVValidated";
        case SignerTrustLevel::Whitelisted:   return "Whitelisted";
        default:                              return "Unknown";
    }
}

[[nodiscard]] std::string_view GetTimestampStatusName(TimestampStatus status) noexcept {
    switch (status) {
        case TimestampStatus::None:        return "None";
        case TimestampStatus::Valid:       return "Valid";
        case TimestampStatus::Expired:     return "Expired";
        case TimestampStatus::Invalid:     return "Invalid";
        case TimestampStatus::UntrustedTSA:return "UntrustedTSA";
        case TimestampStatus::Future:      return "Future";
        default:                           return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSignedFileTypeName(SignedFileType type) noexcept {
    switch (type) {
        case SignedFileType::Unknown:         return "Unknown";
        case SignedFileType::PEExecutable:    return "PEExecutable";
        case SignedFileType::PELibrary:       return "PELibrary";
        case SignedFileType::PEDriver:        return "PEDriver";
        case SignedFileType::PowerShellScript:return "PowerShellScript";
        case SignedFileType::VBScript:        return "VBScript";
        case SignedFileType::JScript:         return "JScript";
        case SignedFileType::MSIPackage:      return "MSIPackage";
        case SignedFileType::MSPPatch:        return "MSPPatch";
        case SignedFileType::AppxPackage:     return "AppxPackage";
        case SignedFileType::CatalogFile:     return "CatalogFile";
        case SignedFileType::CABArchive:      return "CABArchive";
        default:                              return "Unknown";
    }
}

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

bool SignerInfo::IsValid() const {
    auto now = std::chrono::system_clock::now();
    return now >= validFrom && now <= validTo;
}

std::wstring SignerInfo::ToString() const {
    std::wostringstream oss;
    oss << L"Signer: " << signerName;
    if (!organization.empty()) {
        oss << L" (" << organization << L")";
    }
    oss << L", Issuer: " << issuerName;
    oss << L", Trust: " << Utils::StringUtils::ToWide(
        std::string(GetSignerTrustLevelName(trustLevel)));
    if (isEV) {
        oss << L" [EV]";
    }
    return oss.str();
}

bool SignatureInfo::HasValidTimestamp() const {
    for (const auto& ts : timestamps) {
        if (ts.IsValid()) {
            return true;
        }
    }
    return false;
}

std::optional<TimestampInfo> SignatureInfo::GetNewestTimestamp() const {
    if (timestamps.empty()) {
        return std::nullopt;
    }

    auto newest = std::max_element(timestamps.begin(), timestamps.end(),
        [](const TimestampInfo& a, const TimestampInfo& b) {
            return a.timestamp < b.timestamp;
        });

    return *newest;
}

std::string SignatureInfo::GetSummary() const {
    std::ostringstream oss;
    oss << "Result: " << GetSignatureResultName(result);
    oss << ", Type: " << GetSignatureTypeName(type);
    if (!signer.signerName.empty()) {
        oss << ", Signer: " << Utils::StringUtils::ToNarrow(signer.signerName);
    }
    if (isValid) {
        oss << " [VALID]";
    }
    if (isMicrosoftSigned) {
        oss << " [MICROSOFT]";
    }
    if (isEV) {
        oss << " [EV]";
    }
    return oss.str();
}

std::string SignatureInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"result\":\"" << GetSignatureResultName(result) << "\",";
    oss << "\"isValid\":" << (isValid ? "true" : "false") << ",";
    oss << "\"type\":\"" << GetSignatureTypeName(type) << "\",";
    oss << "\"signerName\":\"" << JsonEscape(Utils::StringUtils::ToNarrow(signer.signerName)) << "\",";
    oss << "\"issuerName\":\"" << JsonEscape(Utils::StringUtils::ToNarrow(signer.issuerName)) << "\",";
    oss << "\"isMicrosoftSigned\":" << (isMicrosoftSigned ? "true" : "false") << ",";
    oss << "\"isEV\":" << (isEV ? "true" : "false") << ",";
    oss << "\"isWHQL\":" << (isWHQL ? "true" : "false") << ",";
    oss << "\"isDualSigned\":" << (isDualSigned ? "true" : "false") << ",";
    oss << "\"hasTimestamp\":" << (HasValidTimestamp() ? "true" : "false") << ",";
    oss << "\"errorCode\":" << errorCode;
    if (!errorMessage.empty()) {
        oss << ",\"errorMessage\":\"" << JsonEscape(errorMessage) << "\"";
    }
    oss << "}";
    return oss.str();
}

bool SignatureValidatorConfiguration::IsValid() const noexcept {
    if (trustedPublishers.size() > SignatureConstants::MAX_TRUSTED_PUBLISHERS) {
        return false;
    }
    if (blockedSigners.size() > SignatureConstants::MAX_BLOCKED_SIGNERS) {
        return false;
    }
    if (cacheDurationSecs == 0) {
        return false;
    }
    return true;
}

// Stats are now plain snapshots. The Reset is done on the Impl's internal atomics.

std::string SignatureValidatorStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalValidations\":" << totalValidations << ",";
    oss << "\"validSignatures\":" << validSignatures << ",";
    oss << "\"invalidSignatures\":" << invalidSignatures << ",";
    oss << "\"unsignedFiles\":" << unsignedFiles << ",";
    oss << "\"cacheHits\":" << cacheHits << ",";
    oss << "\"cacheMisses\":" << cacheMisses << ",";
    oss << "\"revocationChecks\":" << revocationChecks << ",";
    oss << "\"revokedCertificates\":" << revokedCertificates << ",";
    oss << "\"expiredCertificates\":" << expiredCertificates << ",";
    oss << "\"blockedSigners\":" << blockedSigners << ",";
    oss << "\"avgValidationTimeUs\":" << avgValidationTimeUs << ",";
    oss << "\"stolenCertDetections\":" << stolenCertDetections << ",";
    oss << "\"anomalyDetections\":" << anomalyDetections;
    oss << "}";
    return oss.str();
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class DigitalSignatureValidatorImpl {
public:
    // ========================================================================
    // CONSTRUCTION / DESTRUCTION
    // ========================================================================

    DigitalSignatureValidatorImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_initialized(false)
        , m_asyncGuardOwner(std::make_shared<bool>(true))
        , m_asyncGuard(m_asyncGuardOwner)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Creating DigitalSignatureValidator implementation");
    }

    ~DigitalSignatureValidatorImpl() noexcept {
        Shutdown();
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const SignatureValidatorConfiguration& config) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing DigitalSignatureValidator");
        m_status = ModuleStatus::Initializing;

        try {
            // Validate configuration
            if (!config.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
                m_status = ModuleStatus::Error;
                return false;
            }

            m_config = config;

            // Initialize trusted publishers
            for (const auto& thumbprint : config.trustedPublishers) {
                m_trustedPublishers.insert(thumbprint);
            }

            // Initialize blocked signers
            for (const auto& thumbprint : config.blockedSigners) {
                m_blockedSigners[thumbprint] = "Configuration";
            }

            // Initialize catalog cache if using system catalogs
            if (config.useSystemCatalogs) {
                initializeSystemCatalogs();
            }

            // Add additional catalog paths
            for (const auto& path : config.additionalCatalogPaths) {
                m_catalogPaths.push_back(path);
            }

            m_initialized = true;
            m_status = ModuleStatus::Running;
            m_stats.startTime = Clock::now();

            SS_LOG_INFO(LOG_CATEGORY, L"DigitalSignatureValidator initialized successfully");
            return true;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", ex.what());
            m_status = ModuleStatus::Error;
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            return;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down DigitalSignatureValidator");
        m_status = ModuleStatus::Stopping;

        // Invalidate async guard so in-flight threads see expired weak_ptr.
        m_asyncGuardOwner.reset();

        // Clear caches
        m_validationCache.clear();
        m_catalogCache.clear();
        m_trustedPublishers.clear();
        m_blockedSigners.clear();
        m_stolenCertDatabase.clear();

        m_initialized = false;
        m_status = ModuleStatus::Stopped;

        SS_LOG_INFO(LOG_CATEGORY, L"DigitalSignatureValidator shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const SignatureValidatorConfiguration& config) noexcept {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;

        // Update trusted publishers
        m_trustedPublishers.clear();
        for (const auto& thumbprint : config.trustedPublishers) {
            m_trustedPublishers.insert(thumbprint);
        }

        // Update blocked signers
        m_blockedSigners.clear();
        for (const auto& thumbprint : config.blockedSigners) {
            m_blockedSigners[thumbprint] = "Configuration";
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] SignatureValidatorConfiguration GetConfiguration() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // PRIMARY VALIDATION
    // ========================================================================

    [[nodiscard]] SignatureInfo VerifyFile(const std::wstring& filePath) noexcept {
        SignatureValidationOptions options;
        options.flags = m_config.defaultFlags;
        return VerifyFile(filePath, options);
    }

    [[nodiscard]] SignatureInfo VerifyFile(
        std::wstring_view filePath,
        const SignatureValidationOptions& options
    ) noexcept {
        const auto startTime = Clock::now();
        SignatureInfo result;
        result.verificationTime = startTime;

        m_stats.totalValidations++;

        try {
            // Validate path
            if (filePath.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Empty file path");
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Empty file path";
                return finalizeResult(result, startTime);
            }

            std::wstring pathStr(filePath);

            // Check path length
            if (pathStr.length() > 32767) {
                SS_LOG_WARN(LOG_CATEGORY, L"Path too long");
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Path too long";
                return finalizeResult(result, startTime);
            }

            // Check file existence
            if (!std::filesystem::exists(pathStr)) {
                // DEBUG, not WARN: callers legitimately query paths that may not
                // exist as files — OS-loader SxS/MUI/manifest probe misses and
                // synthetic resource identifiers surfaced by kernel image-load
                // events (e.g. "<module>.<id>.Manifest", localized "*.mui.dll").
                // These are expected and non-actionable; the caller receives the
                // Error result and handles it (image-load path treats it as
                // "inapplicable"). Logging every probe miss at WARN produced
                // high-volume, alarming noise for a benign condition.
                SS_LOG_DEBUG(LOG_CATEGORY, L"VerifyFile: path does not exist (skipping): %ls",
                             pathStr.c_str());
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "File does not exist";
                return finalizeResult(result, startTime);
            }

            // Check cache if enabled
            bool useCache = (options.flags & SignatureValidationFlags::CacheResult) != SignatureValidationFlags::None;
            if (useCache) {
                auto cached = getCachedResult(pathStr);
                if (cached.has_value()) {
                    m_stats.cacheHits++;
                    return cached.value();
                }
                m_stats.cacheMisses++;
            }

            // Detect file type
            SignedFileType fileType = options.fileTypeHint;
            if (fileType == SignedFileType::Unknown) {
                fileType = DetectFileType(pathStr);
            }

            // Perform WinTrust verification
            result = verifyWithWinTrust(pathStr, options);

            // If embedded signature not found, try catalog
            if (result.result == SignatureValidationResult::Unsigned &&
                (options.flags & SignatureValidationFlags::AllowCatalogSignatures) != SignatureValidationFlags::None) {
                result = verifyCatalogSignature(pathStr);
            }

            // Check blocked signers
            if (result.isValid && isBlockedSigner(result.signer)) {
                result.result = SignatureValidationResult::BlockedSigner;
                result.isValid = false;
                m_stats.blockedSigners++;

                if (m_blockedSignerCallback) {
                    m_blockedSignerCallback(pathStr, result.signer);
                }
            }

            // Update statistics
            if (result.isValid) {
                m_stats.validSignatures++;
            } else if (result.result == SignatureValidationResult::Unsigned) {
                m_stats.unsignedFiles++;
            } else {
                m_stats.invalidSignatures++;
            }

            // Cache result
            if (useCache && result.result != SignatureValidationResult::Error) {
                cacheResult(pathStr, result);
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during verification: %hs", ex.what());
            result.result = SignatureValidationResult::Error;
            result.errorMessage = ex.what();
        }

        return finalizeResult(result, startTime);
    }

    [[nodiscard]] SignatureInfo VerifyMemory(
        std::span<const uint8_t> fileData,
        SignedFileType fileType
    ) noexcept {
        const auto startTime = Clock::now();
        SignatureInfo result;
        result.verificationTime = startTime;

        m_stats.totalValidations++;

        try {
            if (fileData.empty()) {
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Empty file data";
                return finalizeResult(result, startTime);
            }

            // Cap allocation to prevent OOM from malicious input
            if (fileData.size() > MAX_MEMORY_VERIFY_SIZE) {
                SS_LOG_WARN(LOG_CATEGORY, L"VerifyMemory: data size %zu exceeds %zu limit",
                    fileData.size(), MAX_MEMORY_VERIFY_SIZE);
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "File data exceeds maximum size for memory verification";
                return finalizeResult(result, startTime);
            }

            // WinTrust requires a file path. Create a temp file with
            // FILE_FLAG_DELETE_ON_CLOSE so the OS removes it automatically
            // even if we crash — eliminates orphaned temp file risk.
            wchar_t tempPath[MAX_PATH];
            wchar_t tempFile[MAX_PATH];

            if (GetTempPathW(MAX_PATH, tempPath) == 0) {
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Failed to get temp path";
                return finalizeResult(result, startTime);
            }

            if (GetTempFileNameW(tempPath, L"SIG", 0, tempFile) == 0) {
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Failed to create temp file";
                return finalizeResult(result, startTime);
            }

            // Open with DELETE_ON_CLOSE + TEMPORARY for auto-cleanup
            HANDLE hFile = CreateFileW(tempFile,
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                nullptr);

            if (hFile == INVALID_HANDLE_VALUE) {
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Failed to open temp file";
                DeleteFileW(tempFile);
                return finalizeResult(result, startTime);
            }

            DWORD bytesWritten = 0;
            BOOL writeOk = WriteFile(hFile, fileData.data(),
                static_cast<DWORD>(fileData.size()), &bytesWritten, nullptr);

            if (!writeOk || bytesWritten != fileData.size()) {
                CloseHandle(hFile);  // DELETE_ON_CLOSE removes it
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Failed to write temp file";
                return finalizeResult(result, startTime);
            }

            // Flush before WinTrust reads it
            FlushFileBuffers(hFile);

            // Verify while handle is open (prevents TOCTOU — file
            // cannot be replaced while our handle holds the share lock)
            SignatureValidationOptions options;
            options.fileTypeHint = fileType;
            options.flags = options.flags & ~SignatureValidationFlags::CacheResult; // Don't cache temp files
            result = VerifyFile(tempFile, options);

            // Close handle → DELETE_ON_CLOSE triggers automatic deletion
            CloseHandle(hFile);

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during memory verification: %hs", ex.what());
            result.result = SignatureValidationResult::Error;
            result.errorMessage = ex.what();
        }

        return finalizeResult(result, startTime);
    }

    [[nodiscard]] SignatureInfo VerifyCatalogSignature(
        std::wstring_view filePath,
        std::wstring_view catalogPath
    ) noexcept {
        const auto startTime = Clock::now();
        SignatureInfo result;
        result.verificationTime = startTime;
        result.type = SignatureType::Catalog;

        try {
            std::wstring filePathStr(filePath);
            std::wstring catalogPathStr(catalogPath);

            // First verify the catalog file itself
            auto catalogResult = verifyWithWinTrust(catalogPathStr, {});
            if (!catalogResult.isValid) {
                result.result = SignatureValidationResult::CatalogError;
                result.errorMessage = "Catalog signature invalid";
                return finalizeResult(result, startTime);
            }

            // Compute the catalog-membership hash (NOT a flat file digest) so it
            // matches the member digests stored inside the catalog. Using the
            // wrong hash here is why catalog-signed files failed to validate.
            std::vector<BYTE> memberHash;
            if (!computeCatalogMembershipHash(filePathStr, memberHash) ||
                memberHash.size() != sizeof(FileHash)) {
                result.result = SignatureValidationResult::Error;
                result.errorMessage = "Failed to compute catalog membership hash";
                return finalizeResult(result, startTime);
            }
            FileHash fileHash{};
            std::copy(memberHash.begin(), memberHash.end(), fileHash.begin());

            // Verify hash is in catalog
            if (verifyHashInCatalog(catalogPathStr, fileHash)) {
                result.result = SignatureValidationResult::Valid;
                result.isValid = true;
                result.catalogPath = catalogPathStr;
                result.signer = catalogResult.signer;
                result.fileHash = fileHash;
                result.isMicrosoftSigned = catalogResult.isMicrosoftSigned;
            } else {
                result.result = SignatureValidationResult::InvalidHash;
                result.errorMessage = "File hash not found in catalog";
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during catalog verification: %hs", ex.what());
            result.result = SignatureValidationResult::Error;
            result.errorMessage = ex.what();
        }

        return finalizeResult(result, startTime);
    }

    void VerifyFileAsync(
        std::wstring_view filePath,
        SignatureCallback callback,
        const SignatureValidationOptions& options
    ) noexcept {
        if (!callback) {
            SS_LOG_WARN(LOG_CATEGORY, L"Null callback for async verification");
            return;
        }

        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot enqueue async verification: not initialized");
            SignatureInfo errResult;
            errResult.result = SignatureValidationResult::Error;
            errResult.errorMessage = "Validator not initialized";
            callback(errResult);
            return;
        }

        // Capture a shared shutdown guard. If Shutdown() runs first the weak_ptr
        // expires and the lambda exits without touching 'this'.
        auto guard = m_asyncGuard;

        std::wstring pathCopy(filePath);
        SignatureValidationOptions optionsCopy = options;

        std::thread([this, guard, pathCopy = std::move(pathCopy),
                     callback = std::move(callback), optionsCopy]() {
            // If the validator has been destroyed, bail out safely.
            auto locked = guard.lock();
            if (!locked || !m_initialized.load(std::memory_order_acquire)) {
                return;
            }
            try {
                auto result = VerifyFile(pathCopy, optionsCopy);
                callback(result);
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Exception in async verification thread");
            }
        }).detach();
    }

    // ========================================================================
    // QUICK CHECKS
    // ========================================================================

    [[nodiscard]] bool IsSignedBy(
        const std::wstring& filePath,
        const std::wstring& vendorName
    ) noexcept {
        auto result = VerifyFile(filePath);
        if (!result.isValid) {
            return false;
        }

        // Case-insensitive comparison
        std::wstring signerLower = Utils::StringUtils::ToLowerCopy(result.signer.signerName);
        std::wstring vendorLower = Utils::StringUtils::ToLowerCopy(vendorName);

        return signerLower.find(vendorLower) != std::wstring::npos;
    }

    [[nodiscard]] bool IsSigned(std::wstring_view filePath) noexcept {
        SignatureValidationOptions options;
        options.flags = SignatureValidationFlags::VerifyHashOnly;
        auto result = VerifyFile(filePath, options);
        return result.result != SignatureValidationResult::Unsigned;
    }

    [[nodiscard]] bool IsMicrosoftSigned(std::wstring_view filePath) noexcept {
        auto result = VerifyFile(std::wstring(filePath));
        return result.isValid && result.isMicrosoftSigned;
    }

    [[nodiscard]] bool IsWHQLSigned(std::wstring_view filePath) noexcept {
        auto result = VerifyFile(std::wstring(filePath));
        return result.isValid && result.isWHQL;
    }

    [[nodiscard]] bool IsEVSigned(std::wstring_view filePath) noexcept {
        auto result = VerifyFile(std::wstring(filePath));
        return result.isValid && result.isEV;
    }

    [[nodiscard]] bool HasValidTimestamp(std::wstring_view filePath) noexcept {
        auto result = VerifyFile(std::wstring(filePath));
        return result.HasValidTimestamp();
    }

    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================

    [[nodiscard]] bool VerifyIntegrity(std::wstring_view filePath) noexcept {
        SignatureValidationOptions options;
        options.flags = SignatureValidationFlags::VerifyHashOnly;
        auto result = VerifyFile(filePath, options);
        return result.result != SignatureValidationResult::TamperedFile &&
               result.result != SignatureValidationResult::InvalidHash;
    }

    [[nodiscard]] std::optional<FileHash> CalculateAuthenticodeHash(
        std::wstring_view filePath,
        SignatureHashAlgorithm algorithm
    ) noexcept {
        try {
            std::wstring pathStr(filePath);
            FileHash hash{};

            HANDLE hFile = CreateFileW(pathStr.c_str(), GENERIC_READ,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

            if (hFile == INVALID_HANDLE_VALUE) {
                return std::nullopt;
            }

            LARGE_INTEGER fileSize;
            if (!GetFileSizeEx(hFile, &fileSize)) {
                CloseHandle(hFile);
                return std::nullopt;
            }

            // Reject files that exceed our safety limit
            if (static_cast<uint64_t>(fileSize.QuadPart) > SignatureConstants::MAX_FILE_SIZE) {
                SS_LOG_WARN(LOG_CATEGORY, L"File too large for hash: %ls (%lld bytes)",
                    pathStr.c_str(), fileSize.QuadPart);
                CloseHandle(hFile);
                return std::nullopt;
            }

            // FileHash is fixed at 32 bytes. Reject algorithms that produce
            // larger digests outright rather than silently failing inside
            // CryptGetHashParam with ERROR_MORE_DATA.
            size_t expectedDigestSize = 0;
            switch (algorithm) {
                case SignatureHashAlgorithm::SHA1:   expectedDigestSize = 20; break;
                case SignatureHashAlgorithm::SHA256: expectedDigestSize = 32; break;
                case SignatureHashAlgorithm::SHA384:
                case SignatureHashAlgorithm::SHA512:
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"CalculateAuthenticodeHash: digest size of selected algorithm exceeds FileHash capacity (%zu bytes); refusing",
                        sizeof(FileHash));
                    CloseHandle(hFile);
                    return std::nullopt;
                default:
                    expectedDigestSize = 32;
                    break;
            }

            ALG_ID algId = CALG_SHA_256;
            switch (algorithm) {
                case SignatureHashAlgorithm::SHA1:   algId = CALG_SHA1; break;
                case SignatureHashAlgorithm::SHA256: algId = CALG_SHA_256; break;
                default: algId = CALG_SHA_256; break;
            }

            HCRYPTPROV hProv = 0;
            if (!CryptAcquireContextW(&hProv, nullptr, nullptr,
                                       PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                CloseHandle(hFile);
                return std::nullopt;
            }

            HCRYPTHASH hHash = 0;
            if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                CloseHandle(hFile);
                return std::nullopt;
            }

            // Stream in HASH_CHUNK_SIZE chunks to avoid OOM on large files.
            // Distinguish a real ReadFile() failure from end-of-file so we
            // never finalize a digest over a partial read.
            //
            // The scratch buffer MUST be heap-backed, never a stack array.
            // CalculateAuthenticodeHash runs on IPC worker threads while they
            // service kernel image-load scans; a HASH_CHUNK_SIZE (1 MiB) stack
            // local here overflowed the worker-thread stack in this function's
            // prologue (__chkstk) -> STATUS_STACK_OVERFLOW (0xC00000FD) during
            // RealTimeProtection start. A thread_local buffer removes the stack
            // pressure and keeps the hash hot-path allocation-free after warm-up.
            thread_local std::vector<uint8_t> chunkStorage;
            if (chunkStorage.size() != HASH_CHUNK_SIZE) {
                chunkStorage.resize(HASH_CHUNK_SIZE);
            }
            uint8_t* const chunk = chunkStorage.data();
            bool hashOk = true;

            for (;;) {
                DWORD bytesRead = 0;
                if (!ReadFile(hFile, chunk, HASH_CHUNK_SIZE, &bytesRead, nullptr)) {
                    const DWORD err = GetLastError();
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"CalculateAuthenticodeHash: ReadFile failed for '%ls' (GLE=%lu)",
                        pathStr.c_str(), err);
                    hashOk = false;
                    break;
                }
                if (bytesRead == 0) {
                    break;  // EOF
                }
                if (!CryptHashData(hHash, chunk, bytesRead, 0)) {
                    hashOk = false;
                    break;
                }
            }

            CloseHandle(hFile);

            if (!hashOk) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return std::nullopt;
            }

            DWORD hashLen = static_cast<DWORD>(sizeof(hash));
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return std::nullopt;
            }

            if (hashLen != static_cast<DWORD>(expectedDigestSize)) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"CalculateAuthenticodeHash: digest length mismatch (got %lu, expected %zu)",
                    hashLen, expectedDigestSize);
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return std::nullopt;
            }

            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            return hash;

        } catch (...) {
            return std::nullopt;
        }
    }

    [[nodiscard]] bool VerifyHash(
        std::wstring_view filePath,
        std::span<const uint8_t> expectedHash,
        SignatureHashAlgorithm algorithm
    ) noexcept {
        // Require the caller to supply exactly the digest size for the
        // requested algorithm. Accepting any prefix would let an attacker
        // forge a match using only a few leading bytes of the real digest.
        size_t expectedDigestSize = 0;
        switch (algorithm) {
            case SignatureHashAlgorithm::SHA1:   expectedDigestSize = 20; break;
            case SignatureHashAlgorithm::SHA256: expectedDigestSize = 32; break;
            case SignatureHashAlgorithm::SHA384: expectedDigestSize = 48; break;
            case SignatureHashAlgorithm::SHA512: expectedDigestSize = 64; break;
            default: return false;
        }
        if (expectedHash.size() != expectedDigestSize) {
            return false;
        }

        auto calculatedHash = CalculateAuthenticodeHash(filePath, algorithm);
        if (!calculatedHash.has_value()) {
            return false;
        }

        if (expectedHash.size() > calculatedHash->size()) {
            return false;
        }

        // Constant-time comparison over exactly expectedDigestSize bytes.
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < expectedDigestSize; ++i) {
            diff |= static_cast<uint8_t>(expectedHash[i] ^ (*calculatedHash)[i]);
        }
        return diff == 0;
    }

    // ========================================================================
    // TRUSTED PUBLISHER MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddTrustedPublisher(
        const std::array<uint8_t, 20>& thumbprint
    ) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_trustedPublishers.size() >= SignatureConstants::MAX_TRUSTED_PUBLISHERS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Max trusted publishers reached");
            return false;
        }

        auto [_, inserted] = m_trustedPublishers.insert(thumbprint);
        if (inserted) {
            SS_LOG_INFO(LOG_CATEGORY, L"Added trusted publisher: %hs",
                ThumbprintToHex(thumbprint).c_str());
        }
        return inserted;
    }

    [[nodiscard]] bool RemoveTrustedPublisher(
        const std::array<uint8_t, 20>& thumbprint
    ) noexcept {
        std::unique_lock lock(m_mutex);
        size_t removed = m_trustedPublishers.erase(thumbprint);
        if (removed > 0) {
            SS_LOG_INFO(LOG_CATEGORY, L"Removed trusted publisher: %hs",
                ThumbprintToHex(thumbprint).c_str());
        }
        return removed > 0;
    }

    [[nodiscard]] bool IsTrustedPublisher(const SignerInfo& signer) const noexcept {
        std::shared_lock lock(m_mutex);
        return m_trustedPublishers.count(signer.thumbprint) > 0;
    }

    [[nodiscard]] std::vector<std::array<uint8_t, 20>> GetTrustedPublishers() const noexcept {
        std::shared_lock lock(m_mutex);
        return std::vector<std::array<uint8_t, 20>>(
            m_trustedPublishers.begin(), m_trustedPublishers.end());
    }

    // ========================================================================
    // BLOCKED SIGNER MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool BlockSigner(
        const std::array<uint8_t, 20>& thumbprint,
        std::string_view reason
    ) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_blockedSigners.size() >= SignatureConstants::MAX_BLOCKED_SIGNERS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Max blocked signers reached");
            return false;
        }

        m_blockedSigners[thumbprint] = std::string(reason);
        SS_LOG_INFO(LOG_CATEGORY, L"Blocked signer: %hs (reason: %hs)",
            ThumbprintToHex(thumbprint).c_str(),
            std::string(reason).c_str());
        return true;
    }

    [[nodiscard]] bool UnblockSigner(
        const std::array<uint8_t, 20>& thumbprint
    ) noexcept {
        std::unique_lock lock(m_mutex);
        size_t removed = m_blockedSigners.erase(thumbprint);
        if (removed > 0) {
            SS_LOG_INFO(LOG_CATEGORY, L"Unblocked signer: %hs",
                ThumbprintToHex(thumbprint).c_str());
        }
        return removed > 0;
    }

    [[nodiscard]] bool IsBlockedSigner(const SignerInfo& signer) const noexcept {
        std::shared_lock lock(m_mutex);
        return m_blockedSigners.count(signer.thumbprint) > 0;
    }

    [[nodiscard]] std::vector<std::pair<std::array<uint8_t, 20>, std::string>>
        GetBlockedSigners() const noexcept {
        std::shared_lock lock(m_mutex);
        return std::vector<std::pair<std::array<uint8_t, 20>, std::string>>(
            m_blockedSigners.begin(), m_blockedSigners.end());
    }

    // ========================================================================
    // CATALOG MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddCatalog(std::wstring_view catalogPath) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_catalogPaths.size() >= SignatureConstants::MAX_CATALOG_CACHE) {
            SS_LOG_WARN(LOG_CATEGORY, L"Max catalogs reached");
            return false;
        }

        m_catalogPaths.push_back(std::wstring(catalogPath));
        SS_LOG_INFO(LOG_CATEGORY, L"Added catalog: %ls", std::wstring(catalogPath).c_str());
        return true;
    }

    [[nodiscard]] bool RemoveCatalog(std::wstring_view catalogPath) noexcept {
        std::unique_lock lock(m_mutex);
        std::wstring path(catalogPath);

        auto it = std::find(m_catalogPaths.begin(), m_catalogPaths.end(), path);
        if (it != m_catalogPaths.end()) {
            m_catalogPaths.erase(it);
            m_catalogCache.erase(path);
            SS_LOG_INFO(LOG_CATEGORY, L"Removed catalog: %ls", path.c_str());
            return true;
        }
        return false;
    }

    [[nodiscard]] std::optional<std::wstring> FindCatalogForFile(
        std::wstring_view filePath
    ) noexcept {
        // Primary: the system catalog database, resolved via the correct
        // catalog-membership hash (see resolveCatalogForFile). The previous
        // implementation hashed the file with a flat whole-file digest, which
        // never matches CryptCATAdminEnumCatalogFromHash and therefore failed
        // to find the catalog for catalog-signed OS binaries.
        std::wstring catalogPath;
        std::vector<BYTE> catHash;
        if (resolveCatalogForFile(std::wstring(filePath), catalogPath, catHash) &&
            !catalogPath.empty()) {
            return catalogPath;
        }

        // Secondary: honor explicitly-registered custom catalogs, using the same
        // (correct) membership hash we just computed.
        if (catHash.size() == sizeof(FileHash)) {
            FileHash fh{};
            std::copy(catHash.begin(), catHash.end(), fh.begin());
            std::shared_lock lock(m_mutex);
            for (const auto& regCatalog : m_catalogPaths) {
                if (verifyHashInCatalog(regCatalog, fh)) {
                    return regCatalog;
                }
            }
        }

        return std::nullopt;
    }

    void RefreshCatalogCache() noexcept {
        std::unique_lock lock(m_mutex);
        m_catalogCache.clear();
        initializeSystemCatalogs();
        SS_LOG_INFO(LOG_CATEGORY, L"Catalog cache refreshed");
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetBlockedSignerCallback(BlockedSignerCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        m_blockedSignerCallback = std::move(callback);
    }

    void SetUnknownSignerCallback(UnknownSignerCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        m_unknownSignerCallback = std::move(callback);
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void ClearCache() noexcept {
        std::unique_lock lock(m_mutex);
        m_validationCache.clear();
        SS_LOG_INFO(LOG_CATEGORY, L"Validation cache cleared");
    }

    void InvalidateCache(std::wstring_view filePath) noexcept {
        std::unique_lock lock(m_mutex);
        m_validationCache.erase(std::wstring(filePath));
    }

    [[nodiscard]] std::unordered_map<std::string, size_t> GetCacheStats() const noexcept {
        std::shared_lock lock(m_mutex);
        return {
            {"validationCacheSize", m_validationCache.size()},
            {"catalogCacheSize", m_catalogCache.size()},
            {"trustedPublishers", m_trustedPublishers.size()},
            {"blockedSigners", m_blockedSigners.size()},
            {"stolenCertDatabaseSize", m_stolenCertDatabase.size()},
            {"cacheHits", static_cast<size_t>(m_stats.cacheHits.load())},
            {"cacheMisses", static_cast<size_t>(m_stats.cacheMisses.load())},
            {"stolenCertDetections", static_cast<size_t>(m_stats.stolenCertDetections.load())},
            {"anomalyDetections", static_cast<size_t>(m_stats.anomalyDetections.load())}
        };
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    [[nodiscard]] SignedFileType DetectFileType(std::wstring_view filePath) noexcept {
        std::wstring path(filePath);
        std::wstring ext = std::filesystem::path(path).extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

        if (ext == L".exe") return SignedFileType::PEExecutable;
        if (ext == L".dll") return SignedFileType::PELibrary;
        if (ext == L".sys") return SignedFileType::PEDriver;
        if (ext == L".ps1") return SignedFileType::PowerShellScript;
        if (ext == L".vbs") return SignedFileType::VBScript;
        if (ext == L".js")  return SignedFileType::JScript;
        if (ext == L".msi") return SignedFileType::MSIPackage;
        if (ext == L".msp") return SignedFileType::MSPPatch;
        if (ext == L".appx" || ext == L".msix") return SignedFileType::AppxPackage;
        if (ext == L".cat") return SignedFileType::CatalogFile;
        if (ext == L".cab") return SignedFileType::CABArchive;

        return SignedFileType::Unknown;
    }

    [[nodiscard]] SignerInfo ExtractSignerInfo(PCCERT_CONTEXT certContext) noexcept {
        SignerInfo info;

        if (!certContext) {
            return info;
        }

        try {
            // Get subject name
            DWORD nameLen = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0, nullptr, nullptr, 0);
            if (nameLen > 1) {
                std::vector<wchar_t> name(nameLen);
                CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0, nullptr, name.data(), nameLen);
                info.signerName = name.data();
            }

            // Get issuer name
            nameLen = CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);
            if (nameLen > 1) {
                std::vector<wchar_t> issuer(nameLen);
                CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG, nullptr, issuer.data(), nameLen);
                info.issuerName = issuer.data();
            }

            // Get thumbprint (SHA-1)
            DWORD thumbprintLen = static_cast<DWORD>(info.thumbprint.size());
            CryptHashCertificate(0, CALG_SHA1, 0,
                certContext->pbCertEncoded, certContext->cbCertEncoded,
                info.thumbprint.data(), &thumbprintLen);

            // Get fingerprint (SHA-256)
            DWORD fingerprintLen = static_cast<DWORD>(info.fingerprint.size());
            CryptHashCertificate(0, CALG_SHA_256, 0,
                certContext->pbCertEncoded, certContext->cbCertEncoded,
                info.fingerprint.data(), &fingerprintLen);

            // Get validity dates
            info.validFrom = fileTimeToSystemTimePoint(certContext->pCertInfo->NotBefore);
            info.validTo = fileTimeToSystemTimePoint(certContext->pCertInfo->NotAfter);

            // Check for Microsoft signer
            std::wstring signerLower = Utils::StringUtils::ToLowerCopy(info.signerName);
            if (signerLower.find(L"microsoft") != std::wstring::npos) {
                info.trustLevel = SignerTrustLevel::HighlyTrusted;
            }

            // EV Code Signing OIDs (CA/Browser Forum + major CAs)
            static constexpr const char* evOids[] = {
                "2.23.140.1.3",                 // CA/BF EV Code Signing
                "2.23.140.1.1",                 // CA/BF EV SSL (chain indicator)
                "2.16.840.1.114028.10.1.2",     // Entrust EV
                "2.16.840.1.114412.2.1",        // DigiCert EV
                "2.16.840.1.114413.1.7.23.3",   // GoDaddy EV
                "1.3.6.1.4.1.14370.1.6",        // GeoTrust EV
                "1.3.6.1.4.1.6449.1.2.1.5.1",   // Comodo/Sectigo EV
                "2.16.840.1.113733.1.7.23.6",   // Symantec/VeriSign EV
                "2.16.840.1.113733.1.7.48.1",   // Thawte EV
                "2.16.756.1.89.1.2.1.1",        // SwissSign EV
                "1.3.6.1.4.1.34697.2.1",        // AffirmTrust EV
                "1.3.6.1.4.1.8024.0.2.100.1.2", // QuoVadis EV
                "2.16.840.1.114414.1.7.23.3",   // Starfield EV
                "1.2.616.1.113527.2.5.1.1",     // Certum EV
                "2.16.528.1.1003.1.2.7",        // KPN EV
            };

            if (certContext->pCertInfo->cExtension > 0) {
                for (DWORD i = 0; i < certContext->pCertInfo->cExtension; i++) {
                    if (strcmp(certContext->pCertInfo->rgExtension[i].pszObjId,
                               szOID_CERT_POLICIES) == 0) {
                        // Check for EV OIDs in certificate policies
                        CERT_POLICIES_INFO* policyInfo = nullptr;
                        DWORD policySize = 0;

                        if (CryptDecodeObjectEx(X509_ASN_ENCODING,
                            X509_CERT_POLICIES,
                            certContext->pCertInfo->rgExtension[i].Value.pbData,
                            certContext->pCertInfo->rgExtension[i].Value.cbData,
                            CRYPT_DECODE_ALLOC_FLAG,
                            nullptr,
                            &policyInfo,
                            &policySize)) {

                            for (DWORD j = 0; j < policyInfo->cPolicyInfo; j++) {
                                for (const char* evOid : evOids) {
                                    if (strcmp(policyInfo->rgPolicyInfo[j].pszPolicyIdentifier,
                                               evOid) == 0) {
                                        info.isEV = true;
                                        info.trustLevel = SignerTrustLevel::EVValidated;
                                        break;
                                    }
                                }
                            }
                            LocalFree(policyInfo);
                        }
                    }
                }
            }

        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception extracting signer info");
        }

        return info;
    }

    [[nodiscard]] static std::string ThumbprintToHex(
        const std::array<uint8_t, 20>& thumbprint
    ) noexcept {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : thumbprint) {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    [[nodiscard]] static std::optional<std::array<uint8_t, 20>>
        ParseThumbprint(std::string_view hexString) noexcept {
        if (hexString.length() != 40) {
            return std::nullopt;
        }

        std::array<uint8_t, 20> result{};
        for (size_t i = 0; i < 20; i++) {
            char hex[3] = {hexString[i * 2], hexString[i * 2 + 1], 0};
            char* end = nullptr;
            result[i] = static_cast<uint8_t>(std::strtoul(hex, &end, 16));
            if (end != hex + 2) {
                return std::nullopt;
            }
        }
        return result;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] SignatureValidatorStatistics GetStatistics() const noexcept {
        return m_stats.Snapshot();
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    [[nodiscard]] std::string ExportReport() const noexcept {
        std::ostringstream oss;
        oss << "DigitalSignatureValidator Report\n";
        oss << "================================\n\n";
        oss << "Statistics:\n" << m_stats.Snapshot().ToJson() << "\n\n";
        oss << "Configuration:\n";
        oss << "  Caching: " << (m_config.enableCaching ? "enabled" : "disabled") << "\n";
        oss << "  Revocation Check: " << (m_config.enableRevocationCheck ? "enabled" : "disabled") << "\n";
        oss << "  Trusted Publishers: " << m_trustedPublishers.size() << "\n";
        oss << "  Blocked Signers: " << m_blockedSigners.size() << "\n";
        return oss.str();
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    [[nodiscard]] bool SelfTest() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

        bool passed = true;

        // Test 1: Verify a known Microsoft file
        try {
            std::wstring ntdll = L"C:\\Windows\\System32\\ntdll.dll";
            if (std::filesystem::exists(ntdll)) {
                auto result = VerifyFile(ntdll);
                if (result.result != SignatureValidationResult::Valid) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Self-test: ntdll.dll verification unexpected result");
                    // Don't fail - system may have modified files
                }
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Exception during file verification");
            passed = false;
        }

        // Test 2: Verify thumbprint conversion
        try {
            std::array<uint8_t, 20> testThumb = {
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
                0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67
            };
            std::string hex = ThumbprintToHex(testThumb);
            auto parsed = ParseThumbprint(hex);
            if (!parsed.has_value() || parsed.value() != testThumb) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Thumbprint conversion failed");
                passed = false;
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Exception during thumbprint test");
            passed = false;
        }

        // Test 3: Verify file type detection
        try {
            if (DetectFileType(L"test.exe") != SignedFileType::PEExecutable) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: File type detection failed");
                passed = false;
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Exception during file type detection");
            passed = false;
        }

        if (passed) {
            SS_LOG_INFO(LOG_CATEGORY, L"Self-test passed");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed");
        }

        return passed;
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] SignatureInfo verifyWithWinTrust(
        const std::wstring& filePath,
        const SignatureValidationOptions& options
    ) noexcept {
        SignatureInfo result;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = nullptr;
        fileInfo.pgKnownSubject = nullptr;

        GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.pPolicyCallbackData = nullptr;
        winTrustData.pSIPClientData = nullptr;
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.pFile = &fileInfo;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
        winTrustData.hWVTStateData = nullptr;
        winTrustData.pwszURLReference = nullptr;
        winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        // Set revocation check if enabled
        if ((options.flags & SignatureValidationFlags::CheckRevocation) != SignatureValidationFlags::None) {
            winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            winTrustData.dwProvFlags |= WTD_REVOCATION_CHECK_CHAIN;
            m_stats.revocationChecks++;
        }

        // Set online check if enabled
        if ((options.flags & SignatureValidationFlags::OnlineCheck) != SignatureValidationFlags::None) {
            winTrustData.dwProvFlags &= ~WTD_CACHE_ONLY_URL_RETRIEVAL;
        }

        // Call WinVerifyTrust
        LONG status = WinVerifyTrust(nullptr, &actionGuid, &winTrustData);

        // Extract signer information regardless of result
        if (winTrustData.hWVTStateData) {
            CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(
                winTrustData.hWVTStateData);

            if (provData) {
                CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(
                    provData, 0, FALSE, 0);

                if (signer && signer->csCertChain > 0) {
                    CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(signer, 0);
                    if (cert && cert->pCert) {
                        result.signer = ExtractSignerInfo(cert->pCert);
                        result.type = SignatureType::Embedded;

                        // Check for Microsoft signature
                        std::wstring signerLower = Utils::StringUtils::ToLowerCopy(
                            result.signer.signerName);
                        if (signerLower.find(L"microsoft") != std::wstring::npos) {
                            result.isMicrosoftSigned = true;
                        }

                        // Build certificate chain
                        for (DWORD i = 0; i < signer->csCertChain; i++) {
                            CRYPT_PROVIDER_CERT* chainCert = WTHelperGetProvCertFromChain(signer, i);
                            if (chainCert && chainCert->pCert) {
                                result.chain.push_back(ExtractSignerInfo(chainCert->pCert));
                            }
                        }
                    }

                    // Extract timestamp if present
                    if (signer->csCounterSigners > 0) {
                        for (DWORD i = 0; i < signer->csCounterSigners; i++) {
                            CRYPT_PROVIDER_SGNR* counterSigner = &signer->pasCounterSigners[i];
                            if (counterSigner) {
                                TimestampInfo tsInfo;
                                tsInfo.status = TimestampStatus::Valid;
                                tsInfo.timestamp = fileTimeToSystemTimePoint(
                                    counterSigner->sftVerifyAsOf);

                                if (counterSigner->csCertChain > 0) {
                                    CRYPT_PROVIDER_CERT* tsCert = WTHelperGetProvCertFromChain(
                                        counterSigner, 0);
                                    if (tsCert && tsCert->pCert) {
                                        SignerInfo tsSignerInfo = ExtractSignerInfo(tsCert->pCert);
                                        tsInfo.tsaName = tsSignerInfo.signerName;
                                        tsInfo.tsaIssuer = tsSignerInfo.issuerName;
                                    }
                                }
                                result.timestamps.push_back(tsInfo);
                            }
                        }
                    }
                }

                // Check for WHQL signature via EKU OIDs in the leaf certificate.
                // Microsoft WHQL uses specific OIDs:
                //   1.3.6.1.4.1.311.10.3.5  = Windows Hardware Quality Labs
                //   1.3.6.1.4.1.311.10.3.5.1 = Windows Hardware Quality Labs (attestation)
                //   1.3.6.1.4.1.311.10.3.39  = Windows Hardware Driver Attestation
                if (signer && signer->csCertChain > 0) {
                    CRYPT_PROVIDER_CERT* leafCert = WTHelperGetProvCertFromChain(signer, 0);
                    if (leafCert && leafCert->pCert && leafCert->pCert->pCertInfo) {
                        PCERT_EXTENSION ekuExt = CertFindExtension(
                            szOID_ENHANCED_KEY_USAGE,
                            leafCert->pCert->pCertInfo->cExtension,
                            leafCert->pCert->pCertInfo->rgExtension);
                        if (ekuExt) {
                            CERT_ENHKEY_USAGE* pUsage = nullptr;
                            DWORD usageSize = 0;
                            if (CryptDecodeObjectEx(X509_ASN_ENCODING,
                                    X509_ENHANCED_KEY_USAGE,
                                    ekuExt->Value.pbData, ekuExt->Value.cbData,
                                    CRYPT_DECODE_ALLOC_FLAG,
                                    nullptr, &pUsage, &usageSize) && pUsage) {
                                static const char* whqlOids[] = {
                                    "1.3.6.1.4.1.311.10.3.5",
                                    "1.3.6.1.4.1.311.10.3.5.1",
                                    "1.3.6.1.4.1.311.10.3.39"
                                };
                                for (DWORD eku = 0; eku < pUsage->cUsageIdentifier; ++eku) {
                                    for (const char* whqlOid : whqlOids) {
                                        if (strcmp(pUsage->rgpszUsageIdentifier[eku], whqlOid) == 0) {
                                            result.isWHQL = true;
                                            break;
                                        }
                                    }
                                    if (result.isWHQL) break;
                                }
                                LocalFree(pUsage);
                            }
                        }
                    }
                }
            }
        }

        // Interpret WinVerifyTrust result
        switch (status) {
            case ERROR_SUCCESS:
                result.result = SignatureValidationResult::Valid;
                result.isValid = true;
                result.isEV = result.signer.isEV;
                break;

            case TRUST_E_NOSIGNATURE:
                result.result = SignatureValidationResult::Unsigned;
                break;

            case TRUST_E_EXPLICIT_DISTRUST:
                result.result = SignatureValidationResult::BlockedSigner;
                break;

            case TRUST_E_SUBJECT_NOT_TRUSTED:
                result.result = SignatureValidationResult::UntrustedRoot;
                break;

            case CRYPT_E_SECURITY_SETTINGS:
                result.result = SignatureValidationResult::PolicyViolation;
                break;

            case TRUST_E_BAD_DIGEST:
                result.result = SignatureValidationResult::TamperedFile;
                break;

            case CERT_E_EXPIRED:
                result.result = SignatureValidationResult::Expired;
                m_stats.expiredCertificates++;
                break;

            case CERT_E_REVOKED:
                result.result = SignatureValidationResult::Revoked;
                m_stats.revokedCertificates++;
                break;

            case CERT_E_CHAINING:
                result.result = SignatureValidationResult::ChainError;
                break;

            default:
                result.result = SignatureValidationResult::InvalidSignature;
                result.errorCode = static_cast<int32_t>(status);
                break;
        }

        // Close WinTrust state
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &actionGuid, &winTrustData);

        return result;
    }

    // Computes the *catalog-membership hash* Windows keys its security catalogs
    // by -- the PE/Authenticode hash produced by CryptCATAdminCalcHashFromFileHandle
    // /2, NOT a flat whole-file digest. This is the ONLY hash that matches
    // CryptCATAdminEnumCatalogFromHash and the member digests inside a .cat, so
    // it MUST be used for every catalog lookup. Prefers the modern SHA-256 (v2)
    // context and falls back to the legacy context on older systems. The value
    // is deterministic for a given algorithm, so it is safe to reuse across a
    // subsequent same-algorithm enumeration.
    [[nodiscard]] bool computeCatalogMembershipHash(
        const std::wstring& filePath,
        std::vector<BYTE>& outHash
    ) noexcept {
        outHash.clear();

        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        HCATADMIN hCatAdmin = nullptr;
        GUID driverActionGuid = DRIVER_ACTION_VERIFY;
        bool useV2 = true;
        if (!CryptCATAdminAcquireContext2(&hCatAdmin, &driverActionGuid,
                                          BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
            useV2 = false;
            if (!CryptCATAdminAcquireContext(&hCatAdmin, &driverActionGuid, 0)) {
                CloseHandle(hFile);
                return false;
            }
        }

        BYTE hashBytes[64];
        DWORD hashLen = sizeof(hashBytes);
        const BOOL calcOk = useV2
            ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &hashLen, hashBytes, 0)
            : CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hashBytes, 0);

        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);

        if (!calcOk || hashLen == 0) {
            return false;
        }
        outHash.assign(hashBytes, hashBytes + hashLen);
        return true;
    }

    // Resolves the security catalog that vouches for `filePath`, if any, using
    // the correct catalog-membership hash. `outHash` is populated whenever the
    // hash could be computed (even if no catalog matched) so callers can reuse
    // it. See computeCatalogMembershipHash for why the hash choice matters:
    // catalog-signed OS binaries (most of System32 -- msxml3, imageres,
    // wscinterop, ntdll, ...) were previously mis-classified as unsigned and
    // pushed through the full detection pipeline on every access.
    [[nodiscard]] bool resolveCatalogForFile(
        const std::wstring& filePath,
        std::wstring& outCatalogPath,
        std::vector<BYTE>& outHash
    ) noexcept {
        outCatalogPath.clear();

        if (!computeCatalogMembershipHash(filePath, outHash) || outHash.empty()) {
            return false;
        }

        // Enumerate with the same algorithm preference used to hash. The hash is
        // deterministic, so a fresh same-algorithm context matches identically.
        HCATADMIN hCatAdmin = nullptr;
        GUID driverActionGuid = DRIVER_ACTION_VERIFY;
        if (!CryptCATAdminAcquireContext2(&hCatAdmin, &driverActionGuid,
                                          BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
            if (!CryptCATAdminAcquireContext(&hCatAdmin, &driverActionGuid, 0)) {
                return false;
            }
        }

        bool found = false;
        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, outHash.data(), static_cast<DWORD>(outHash.size()), 0, nullptr);
        if (hCatInfo) {
            CATALOG_INFO catInfo = {};
            catInfo.cbStruct = sizeof(catInfo);
            if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
                outCatalogPath = catInfo.wszCatalogFile;
                found = true;
            }
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }

        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return found;
    }

    [[nodiscard]] SignatureInfo verifyCatalogSignature(
        const std::wstring& filePath
    ) noexcept {
        SignatureInfo result;
        result.type = SignatureType::Catalog;

        // Resolve the catalog via the correct catalog-membership hash.
        std::wstring catalogPath;
        std::vector<BYTE> catHash;
        if (!resolveCatalogForFile(filePath, catalogPath, catHash)) {
            // Not a member of any installed catalog => genuinely not
            // catalog-signed. Unsigned/non-MS/tampered files land here and
            // continue to receive the full detection pipeline upstream.
            result.result = SignatureValidationResult::Unsigned;
            return result;
        }

        result.catalogPath = catalogPath;

        // Membership is proven above; now verify the catalog's own Authenticode
        // signature + signer chain. Membership in a validly-signed catalog ==
        // the file is validly catalog-signed by that catalog's signer. A
        // tampered file produces a different membership hash and never reaches
        // here, so this remains tamper-safe.
        //
        // Chain-validate WITHOUT mandatory revocation: the catalog still fully
        // verifies to a trusted (Microsoft) root, but we do not hard-fail an
        // OS-trust decision on unreachable CRL/OCSP. Revocation here is at best
        // cache-only (offline endpoints/VMs cannot reach responders), and a
        // hard failure would send every catalog-signed OS binary back through
        // the full pipeline -- reintroducing the very false-positive/CPU storm
        // this path exists to prevent. Publisher chain trust is preserved.
        SignatureValidationOptions catOpts;
        catOpts.flags = SignatureValidationFlags::VerifyChain |
                        SignatureValidationFlags::CacheResult;
        auto catalogResult = verifyWithWinTrust(catalogPath, catOpts);
        if (catalogResult.isValid) {
            result.result = SignatureValidationResult::Valid;
            result.isValid = true;
            result.signer = catalogResult.signer;
            result.isMicrosoftSigned = catalogResult.isMicrosoftSigned;
            result.timestamps = catalogResult.timestamps;
            if (catHash.size() == result.fileHash.size()) {
                std::copy(catHash.begin(), catHash.end(), result.fileHash.begin());
            }
        } else {
            result.result = SignatureValidationResult::CatalogError;
            result.errorMessage = "Catalog signature invalid";
        }

        return result;
    }

    [[nodiscard]] bool verifyHashInCatalog(
        const std::wstring& catalogPath,
        const FileHash& hash
    ) noexcept {
        HANDLE hCat = CryptCATOpen(
            const_cast<LPWSTR>(catalogPath.c_str()),
            CRYPTCAT_OPEN_EXISTING,
            0,
            CRYPTCAT_VERSION_1,
            0);

        if (hCat == INVALID_HANDLE_VALUE) {
            return false;
        }

        bool found = false;
        CRYPTCATMEMBER* member = nullptr;

        while ((member = CryptCATEnumerateMember(hCat, member)) != nullptr) {
            if (member->pIndirectData && member->pIndirectData->Digest.cbData > 0) {
                if (member->pIndirectData->Digest.cbData == hash.size() &&
                    memcmp(member->pIndirectData->Digest.pbData, hash.data(), hash.size()) == 0) {
                    found = true;
                    break;
                }
            }
        }

        CryptCATClose(hCat);
        return found;
    }

    [[nodiscard]] std::optional<SignatureInfo> getCachedResult(
        const std::wstring& filePath
    ) const noexcept {
        std::shared_lock lock(m_mutex);

        auto it = m_validationCache.find(filePath);
        if (it == m_validationCache.end()) {
            return std::nullopt;
        }

        // Check cache expiration
        auto now = Clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.sigInfo.verificationTime);

        if (age.count() > static_cast<long long>(m_config.cacheDurationSecs)) {
            return std::nullopt;
        }

        // TOCTOU protection: verify file hasn't been modified since cache entry was created
        std::error_code ec;
        auto currentWriteTime = std::filesystem::last_write_time(filePath, ec);
        if (ec || currentWriteTime != it->second.lastWriteTime) {
            return std::nullopt;  // File was modified — stale cache entry
        }

        return it->second.sigInfo;
    }

    void cacheResult(const std::wstring& filePath, const SignatureInfo& result) noexcept {
        std::unique_lock lock(m_mutex);

        // Limit cache size
        if (m_validationCache.size() >= SignatureConstants::MAX_CACHED_VALIDATIONS) {
            auto oldest = m_validationCache.begin();
            for (auto it = m_validationCache.begin(); it != m_validationCache.end(); ++it) {
                if (it->second.sigInfo.verificationTime < oldest->second.sigInfo.verificationTime) {
                    oldest = it;
                }
            }
            m_validationCache.erase(oldest);
        }

        // Record file modification time for TOCTOU-safe cache validation
        CacheEntry entry;
        entry.sigInfo = result;
        std::error_code ec;
        entry.lastWriteTime = std::filesystem::last_write_time(filePath, ec);
        if (ec) {
            // Force stale on next lookup — min() is guaranteed never to match a real mtime
            entry.lastWriteTime = std::filesystem::file_time_type::min();
        }
        m_validationCache[filePath] = std::move(entry);
    }

    void initializeSystemCatalogs() noexcept {
        // System catalogs are automatically used via CryptCATAdmin APIs
        SS_LOG_DEBUG(LOG_CATEGORY, L"System catalog access initialized");
    }

    [[nodiscard]] bool isBlockedSigner(const SignerInfo& signer) const noexcept {
        std::shared_lock lock(m_mutex);
        return m_blockedSigners.count(signer.thumbprint) > 0;
    }

    [[nodiscard]] SignatureInfo finalizeResult(
        SignatureInfo& result,
        const TimePoint& startTime
    ) noexcept {
        auto endTime = Clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime);

        // Update average time with exponential moving average (lock-free).
        // EMA avoids the read-modify-write race of the old cumulative average.
        // α = 1/16 ≈ 6.25% — smooths without requiring a CAS loop.
        uint64_t durationUs = static_cast<uint64_t>(duration.count());
        uint64_t prev = m_stats.avgValidationTimeUs.load(std::memory_order_relaxed);
        uint64_t ema = (prev == 0) ? durationUs : prev - (prev >> 4) + (durationUs >> 4);
        m_stats.avgValidationTimeUs.store(ema, std::memory_order_relaxed);

        return result;
    }

    [[nodiscard]] static SystemTimePoint fileTimeToSystemTimePoint(
        const FILETIME& ft
    ) noexcept {
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;

        // Windows FILETIME is 100ns intervals since Jan 1, 1601
        // Convert to Unix epoch (Jan 1, 1970)
        constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;

        if (uli.QuadPart < EPOCH_DIFF) {
            return SystemTimePoint{};
        }

        auto duration = std::chrono::duration<uint64_t, std::ratio<1, 10000000>>(
            uli.QuadPart - EPOCH_DIFF);

        return SystemTimePoint(std::chrono::duration_cast<
            std::chrono::system_clock::duration>(duration));
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status;
    std::atomic<bool> m_initialized;

    SignatureValidatorConfiguration m_config;

    // Internal atomic counters (never cross API boundary)
    struct InternalStats {
        std::atomic<uint64_t> totalValidations{0};
        std::atomic<uint64_t> validSignatures{0};
        std::atomic<uint64_t> invalidSignatures{0};
        std::atomic<uint64_t> unsignedFiles{0};
        std::atomic<uint64_t> cacheHits{0};
        std::atomic<uint64_t> cacheMisses{0};
        std::atomic<uint64_t> revocationChecks{0};
        std::atomic<uint64_t> revokedCertificates{0};
        std::atomic<uint64_t> expiredCertificates{0};
        std::atomic<uint64_t> blockedSigners{0};
        std::atomic<uint64_t> avgValidationTimeUs{0};
        std::atomic<uint64_t> stolenCertDetections{0};
        std::atomic<uint64_t> anomalyDetections{0};
        TimePoint startTime = Clock::now();

        void Reset() noexcept {
            totalValidations = 0; validSignatures = 0; invalidSignatures = 0;
            unsignedFiles = 0; cacheHits = 0; cacheMisses = 0;
            revocationChecks = 0; revokedCertificates = 0; expiredCertificates = 0;
            blockedSigners = 0; avgValidationTimeUs = 0;
            stolenCertDetections = 0; anomalyDetections = 0;
            startTime = Clock::now();
        }

        [[nodiscard]] SignatureValidatorStatistics Snapshot() const noexcept {
            SignatureValidatorStatistics s;
            s.totalValidations    = totalValidations.load(std::memory_order_relaxed);
            s.validSignatures     = validSignatures.load(std::memory_order_relaxed);
            s.invalidSignatures   = invalidSignatures.load(std::memory_order_relaxed);
            s.unsignedFiles       = unsignedFiles.load(std::memory_order_relaxed);
            s.cacheHits           = cacheHits.load(std::memory_order_relaxed);
            s.cacheMisses         = cacheMisses.load(std::memory_order_relaxed);
            s.revocationChecks    = revocationChecks.load(std::memory_order_relaxed);
            s.revokedCertificates = revokedCertificates.load(std::memory_order_relaxed);
            s.expiredCertificates = expiredCertificates.load(std::memory_order_relaxed);
            s.blockedSigners      = blockedSigners.load(std::memory_order_relaxed);
            s.avgValidationTimeUs = avgValidationTimeUs.load(std::memory_order_relaxed);
            s.stolenCertDetections = stolenCertDetections.load(std::memory_order_relaxed);
            s.anomalyDetections   = anomalyDetections.load(std::memory_order_relaxed);
            s.startTime           = startTime;
            return s;
        }
    } m_stats;

    // Cache entry with file modification time for TOCTOU protection
    struct CacheEntry {
        SignatureInfo sigInfo;
        std::filesystem::file_time_type lastWriteTime;
    };

    // Caches (keyed by path + validated against file write time)
    std::unordered_map<std::wstring, CacheEntry> m_validationCache;
    std::unordered_map<std::wstring, std::vector<FileHash>> m_catalogCache;
    std::vector<std::wstring> m_catalogPaths;

    // Trust management
    std::set<std::array<uint8_t, 20>> m_trustedPublishers;
    std::map<std::array<uint8_t, 20>, std::string> m_blockedSigners;

    // APT: Stolen/compromised certificate database
    std::map<std::array<uint8_t, 20>, StolenCertEntry> m_stolenCertDatabase;

    // Callbacks
    BlockedSignerCallback m_blockedSignerCallback;
    UnknownSignerCallback m_unknownSignerCallback;
    SignatureAnomalyCallback m_anomalyCallback;

    // Async thread safety: shared_ptr kept alive while Impl exists.
    // Async lambdas capture the weak_ptr; if Impl is destroyed, they bail.
    std::shared_ptr<bool> m_asyncGuardOwner;
    std::weak_ptr<bool> m_asyncGuard;

    // ========================================================================
    // APT HUNTING ENGINE (inside Impl)
    // ========================================================================
public:

    [[nodiscard]] bool AddStolenCertificate(const StolenCertEntry& entry) noexcept {
        std::unique_lock lock(m_mutex);
        auto [it, inserted] = m_stolenCertDatabase.emplace(entry.thumbprint, entry);
        if (inserted) {
            SS_LOG_INFO(LOG_CATEGORY, L"Added stolen cert: %hs [%hs]",
                entry.threatActorName.c_str(), entry.campaignName.c_str());
        }
        return inserted;
    }

    [[nodiscard]] size_t LoadStolenCertDatabase(std::span<const StolenCertEntry> entries) noexcept {
        std::unique_lock lock(m_mutex);
        size_t loaded = 0;
        for (const auto& entry : entries) {
            auto [it, inserted] = m_stolenCertDatabase.emplace(entry.thumbprint, entry);
            if (inserted) ++loaded;
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Loaded %zu stolen certificates from threat intel feed", loaded);
        return loaded;
    }

    [[nodiscard]] std::optional<StolenCertEntry> CheckStolenCertificate(
        const std::array<uint8_t, 20>& thumbprint
    ) const noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_stolenCertDatabase.find(thumbprint);
        if (it != m_stolenCertDatabase.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void SetAnomalyCallback(SignatureAnomalyCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        m_anomalyCallback = std::move(callback);
    }

    [[nodiscard]] SignatureAnalysisResult AnalyzeSignature(std::wstring_view filePath) noexcept {
        SignatureAnalysisResult analysis;
        analysis.signatureInfo = VerifyFile(std::wstring(filePath));

        if (analysis.signatureInfo.result == SignatureValidationResult::Error) {
            return analysis;
        }

        const auto& sigInfo = analysis.signatureInfo;
        const auto& signer = sigInfo.signer;

        // === Check 1: Stolen certificate database ===
        {
            std::shared_lock lock(m_mutex);
            auto it = m_stolenCertDatabase.find(signer.thumbprint);
            if (it != m_stolenCertDatabase.end()) {
                analysis.isStolenCert = true;
                analysis.threatActorName = it->second.threatActorName;
                analysis.riskScore = 100;
                m_stats.stolenCertDetections++;

                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::StolenCertificate;
                anomaly.severity = AnomalySeverity::Critical;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "Known APT stolen certificate: " +
                    it->second.threatActorName + " / " + it->second.campaignName;
                anomaly.mitreAttackId = "T1553.002";
                analysis.anomalies.push_back(std::move(anomaly));
            }

            // Also check each cert in the chain
            for (const auto& chainCert : sigInfo.chain) {
                auto chainIt = m_stolenCertDatabase.find(chainCert.thumbprint);
                if (chainIt != m_stolenCertDatabase.end()) {
                    analysis.isStolenCert = true;
                    analysis.riskScore = 100;
                    m_stats.stolenCertDetections++;

                    SignatureAnomaly anomaly;
                    anomaly.type = AnomalyType::StolenCertificate;
                    anomaly.severity = AnomalySeverity::Critical;
                    anomaly.filePath = std::wstring(filePath);
                    anomaly.signerName = chainCert.signerName;
                    anomaly.description = "APT cert in chain: " +
                        chainIt->second.threatActorName;
                    anomaly.mitreAttackId = "T1553.002";
                    analysis.anomalies.push_back(std::move(anomaly));
                }
            }
        }

        // === Check 2: Self-signed executable in non-system location ===
        if (sigInfo.isValid && sigInfo.chain.size() <= 1 &&
            signer.signerName == signer.issuerName) {
            std::wstring pathLower(filePath);
            std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
            bool isSystemPath = (pathLower.find(L"\\windows\\") != std::wstring::npos);
            if (!isSystemPath) {
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::SelfSignedExecutable;
                anomaly.severity = AnomalySeverity::High;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "Self-signed executable outside system directory";
                anomaly.mitreAttackId = "T1553.002";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 70u);
            }
        }

        // === Check 3: Short validity cert (burner cert — APT staging) ===
        if (signer.validTo > signer.validFrom) {
            auto validity = std::chrono::duration_cast<std::chrono::hours>(
                signer.validTo - signer.validFrom);
            if (validity.count() < 30 * 24) {  // Less than 30 days
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::ShortValidityCert;
                anomaly.severity = AnomalySeverity::High;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "Certificate validity < 30 days (possible burner cert)";
                anomaly.mitreAttackId = "T1588.003";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 65u);
            }
        }

        // === Check 4: Recently issued certificate (< 7 days old) ===
        {
            auto now = std::chrono::system_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - signer.validFrom);
            if (age.count() >= 0 && age.count() < 7 * 24 && sigInfo.isValid) {
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::RecentlyIssuedCert;
                anomaly.severity = AnomalySeverity::Medium;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "Certificate issued less than 7 days ago";
                anomaly.mitreAttackId = "T1588.003";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 50u);
            }
        }

        // === Check 5: Weak algorithm (MD5 or SHA-1 only) ===
        if (sigInfo.fileHashAlgorithm == SignatureHashAlgorithm::MD5 ||
            sigInfo.fileHashAlgorithm == SignatureHashAlgorithm::SHA1) {
            if (!m_config.allowWeakAlgorithms) {
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::WeakHashAlgorithm;
                anomaly.severity = AnomalySeverity::Medium;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "Signature uses deprecated hash algorithm";
                anomaly.mitreAttackId = "T1553.002";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 40u);
            }
        }

        // === Check 6: Test signature in production ===
        // Detect test-signed binaries via multiple heuristics:
        // (a) Untrusted root with valid signature structure
        // (b) Known test-signing certificate CN patterns
        // (c) Microsoft-specific test cert thumbprints
        {
            bool isTestSigned = false;
            std::string testReason;

            // (a) Untrusted root with structurally valid signature
            if (sigInfo.result == SignatureValidationResult::UntrustedRoot && sigInfo.isValid) {
                isTestSigned = true;
                testReason = "Untrusted root certificate";
            }

            // (b) Signer CN contains test-signing indicators
            if (!isTestSigned) {
                std::string lowerCN;
                lowerCN.reserve(signer.signerName.size());
                for (wchar_t c : signer.signerName) {
                    const wchar_t lowered = static_cast<wchar_t>(std::towlower(c));
                    if (lowered >= L'\0' && lowered <= L'\x7F') {
                        lowerCN.push_back(static_cast<char>(lowered));
                    }
                }
                static constexpr std::array testPatterns = {
                    "test sign", "testsign", "test cert", "testcert",
                    "test root", "testroot", "development sign", "devsign",
                    "do not ship", "do not trust", "internal test",
                    "self-test", "selftest"
                };
                for (const char* pat : testPatterns) {
                    if (lowerCN.find(pat) != std::string::npos) {
                        isTestSigned = true;
                        testReason = "Signer CN contains test indicator: '";
                        testReason += pat;
                        testReason += "'";
                        break;
                    }
                }
            }

            // (c) Known Microsoft test cert thumbprints (SHA-1)
            if (!isTestSigned) {
                // Microsoft Test Root Authority (used by TESTSIGNING BCD mode)
                static const std::array<std::array<uint8_t, 20>, 3> knownTestThumbprints = {{
                    // Microsoft Testing Root Certificate Authority 2010
                    {0x2B, 0xD6, 0x3D, 0x28, 0xD7, 0xBC, 0xD0, 0xE2,
                     0x51, 0x19, 0x5A, 0xEB, 0x51, 0x9C, 0x2A, 0xE9,
                     0x56, 0x37, 0x55, 0xC4},
                    // Microsoft Code Verification Root (test)
                    {0xF5, 0x3F, 0x74, 0xE1, 0xAF, 0xEC, 0xDA, 0x30,
                     0x2E, 0x6F, 0x11, 0x7E, 0xFB, 0x0E, 0x8C, 0x56,
                     0x2D, 0xA7, 0x49, 0x75},
                    // WDK test-signing cert
                    {0xD4, 0x11, 0xA8, 0x0D, 0x2E, 0x06, 0x9D, 0xB7,
                     0x4F, 0x3F, 0x32, 0x1F, 0xF9, 0x5E, 0x53, 0xF4,
                     0x52, 0x3B, 0x88, 0x23}
                }};

                for (const auto& cert : sigInfo.chain) {
                    for (const auto& testThumb : knownTestThumbprints) {
                        if (cert.thumbprint == testThumb) {
                            isTestSigned = true;
                            testReason = "Known Microsoft test certificate in chain";
                            break;
                        }
                    }
                    if (isTestSigned) break;
                }
            }

            if (isTestSigned) {
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::TestSignatureInProd;
                anomaly.severity = AnomalySeverity::High;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "Test-signed binary in production environment: " + testReason;
                anomaly.mitreAttackId = "T1553.006";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 75u);
            }
        }

        // === Check 7: Catalog-only signature (no embedded — evasion technique) ===
        if (sigInfo.type == SignatureType::Catalog && sigInfo.isValid) {
            std::wstring ext = std::filesystem::path(std::wstring(filePath)).extension().wstring();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
            if (ext == L".exe" || ext == L".dll") {
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::CatalogOnlyNoEmbedded;
                anomaly.severity = AnomalySeverity::Low;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = signer.signerName;
                anomaly.description = "PE has catalog-only signature (no embedded Authenticode)";
                anomaly.mitreAttackId = "T1553.002";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 25u);
            }
        }

        // === Check 8: Timestamp in the future ===
        for (const auto& ts : sigInfo.timestamps) {
            auto now = std::chrono::system_clock::now();
            auto tolerance = std::chrono::seconds(SignatureConstants::CLOCK_SKEW_TOLERANCE_SECS);
            if (ts.timestamp > now + tolerance) {
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::TimestampInFuture;
                anomaly.severity = AnomalySeverity::High;
                anomaly.filePath = std::wstring(filePath);
                anomaly.signerName = ts.tsaName;
                anomaly.description = "Counter-signature timestamp is in the future";
                anomaly.mitreAttackId = "T1070.006";
                analysis.anomalies.push_back(std::move(anomaly));
                analysis.riskScore = std::max(analysis.riskScore, 70u);
            }
        }

        // === Check 9: Revoked certificate still being loaded ===
        if (sigInfo.result == SignatureValidationResult::Revoked) {
            SignatureAnomaly anomaly;
            anomaly.type = AnomalyType::RevokedButStillUsed;
            anomaly.severity = AnomalySeverity::Critical;
            anomaly.filePath = std::wstring(filePath);
            anomaly.signerName = signer.signerName;
            anomaly.description = "Revoked certificate binary attempting execution";
            anomaly.mitreAttackId = "T1553.002";
            analysis.anomalies.push_back(std::move(anomaly));
            analysis.riskScore = 95;
        }

        // Fire anomaly callbacks
        if (!analysis.anomalies.empty()) {
            m_stats.anomalyDetections += static_cast<uint64_t>(analysis.anomalies.size());
            SignatureAnomalyCallback cb;
            {
                std::shared_lock lock(m_mutex);
                cb = m_anomalyCallback;
            }
            if (cb) {
                for (const auto& anomaly : analysis.anomalies) {
                    try { cb(anomaly); } catch (...) {}
                }
            }
        }

        return analysis;
    }

    // ========================================================================
    // KERNEL INTEGRATION METHODS (inside Impl)
    // ========================================================================

    [[nodiscard]] SignatureAnalysisResult OnKernelImageLoad(
        uint32_t processId,
        std::wstring_view imagePath,
        uint64_t /*imageBase*/,
        uint64_t /*imageSize*/,
        uint8_t kernelSigLevel,
        bool isSystemImage
    ) noexcept {
        // Fast path: kernel already reports system images as signed at level >= 8
        // (SE_SIGNING_LEVEL_WINDOWS / SE_SIGNING_LEVEL_MICROSOFT).
        // Still run anomaly analysis to catch stolen certs.
        if (isSystemImage && kernelSigLevel >= 8) {
            // Even for system images, check against stolen cert database
            auto analysis = AnalyzeSignature(imagePath);
            if (!analysis.isStolenCert && analysis.anomalies.empty()) {
                // Trusted system image with no anomalies — fast path
                analysis.riskScore = 0;
            }
            return analysis;
        }

        // Full analysis for non-system images or low signature levels
        auto analysis = AnalyzeSignature(imagePath);

        // Unsigned driver loading is always Critical
        if (analysis.signatureInfo.result == SignatureValidationResult::Unsigned) {
            std::wstring ext = std::filesystem::path(std::wstring(imagePath)).extension().wstring();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
            if (ext == L".sys") {
                analysis.riskScore = 100;
                SignatureAnomaly anomaly;
                anomaly.type = AnomalyType::TestSignatureInProd;
                anomaly.severity = AnomalySeverity::Critical;
                anomaly.filePath = std::wstring(imagePath);
                anomaly.description = "Unsigned driver loaded — possible rootkit (PID " +
                    std::to_string(processId) + ")";
                anomaly.mitreAttackId = "T1014";
                analysis.anomalies.push_back(std::move(anomaly));
            }
        }

        // Kernel signature level mismatch detection
        if (kernelSigLevel == 0 && analysis.signatureInfo.isValid) {
            // Kernel says unsigned but usermode WinTrust says valid →
            // possible catalog-only or cross-signed bypass
            SignatureAnomaly anomaly;
            anomaly.type = AnomalyType::SupplyChainAnomaly;
            anomaly.severity = AnomalySeverity::High;
            anomaly.filePath = std::wstring(imagePath);
            anomaly.description = "Kernel reports unsigned but usermode detects valid signature — "
                "possible signing policy bypass";
            anomaly.mitreAttackId = "T1553.006";
            analysis.anomalies.push_back(std::move(anomaly));
            analysis.riskScore = std::max(analysis.riskScore, 80u);
        }

        SS_LOG_DEBUG(LOG_CATEGORY,
            L"ImageLoad analysis: PID=%u path=%ls risk=%u anomalies=%zu",
            processId, std::wstring(imagePath).c_str(),
            analysis.riskScore,
            analysis.anomalies.size());

        return analysis;
    }

    [[nodiscard]] SignatureAnalysisResult ValidateProcessImage(
        uint32_t processId,
        uint32_t parentProcessId,
        std::wstring_view imagePath
    ) noexcept {
        auto analysis = AnalyzeSignature(imagePath);

        // Additional process-specific checks:
        // If the process image is unsigned AND the parent is a signed system process,
        // this is suspicious (possible process hollowing / injection).
        if (analysis.signatureInfo.result == SignatureValidationResult::Unsigned) {
            analysis.riskScore = std::max(analysis.riskScore, 60u);

            SS_LOG_WARN(LOG_CATEGORY,
                L"Unsigned process image: PID=%u ParentPID=%u Path=%ls",
                processId, parentProcessId, std::wstring(imagePath).c_str());
        }

        return analysis;
    }
};

// ============================================================================
// DIGITALSIGNATUREVALIDATOR PUBLIC IMPLEMENTATION
// ============================================================================

DigitalSignatureValidator& DigitalSignatureValidator::Instance() noexcept {
    static DigitalSignatureValidator instance;
    return instance;
}

bool DigitalSignatureValidator::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

DigitalSignatureValidator::DigitalSignatureValidator()
    : m_impl(std::make_unique<DigitalSignatureValidatorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"DigitalSignatureValidator instance created");
}

DigitalSignatureValidator::~DigitalSignatureValidator() {
    SS_LOG_INFO(LOG_CATEGORY, L"DigitalSignatureValidator instance destroyed");
}

bool DigitalSignatureValidator::Initialize(const SignatureValidatorConfiguration& config) {
    return m_impl->Initialize(config);
}

void DigitalSignatureValidator::Shutdown() {
    m_impl->Shutdown();
}

bool DigitalSignatureValidator::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus DigitalSignatureValidator::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool DigitalSignatureValidator::SetConfiguration(const SignatureValidatorConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

SignatureValidatorConfiguration DigitalSignatureValidator::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

SignatureInfo DigitalSignatureValidator::VerifyFile(const std::wstring& filePath) {
    return m_impl->VerifyFile(filePath);
}

SignatureInfo DigitalSignatureValidator::VerifyFile(
    std::wstring_view filePath,
    const SignatureValidationOptions& options
) {
    return m_impl->VerifyFile(filePath, options);
}

SignatureInfo DigitalSignatureValidator::VerifyMemory(
    std::span<const uint8_t> fileData,
    SignedFileType fileType
) {
    return m_impl->VerifyMemory(fileData, fileType);
}

SignatureInfo DigitalSignatureValidator::VerifyCatalogSignature(
    std::wstring_view filePath,
    std::wstring_view catalogPath
) {
    return m_impl->VerifyCatalogSignature(filePath, catalogPath);
}

void DigitalSignatureValidator::VerifyFileAsync(
    std::wstring_view filePath,
    SignatureCallback callback,
    const SignatureValidationOptions& options
) {
    m_impl->VerifyFileAsync(filePath, callback, options);
}

bool DigitalSignatureValidator::IsSignedBy(
    const std::wstring& filePath,
    const std::wstring& vendorName
) {
    return m_impl->IsSignedBy(filePath, vendorName);
}

bool DigitalSignatureValidator::IsSigned(std::wstring_view filePath) {
    return m_impl->IsSigned(filePath);
}

bool DigitalSignatureValidator::IsMicrosoftSigned(std::wstring_view filePath) {
    return m_impl->IsMicrosoftSigned(filePath);
}

bool DigitalSignatureValidator::IsWHQLSigned(std::wstring_view filePath) {
    return m_impl->IsWHQLSigned(filePath);
}

bool DigitalSignatureValidator::IsEVSigned(std::wstring_view filePath) {
    return m_impl->IsEVSigned(filePath);
}

bool DigitalSignatureValidator::HasValidTimestamp(std::wstring_view filePath) {
    return m_impl->HasValidTimestamp(filePath);
}

bool DigitalSignatureValidator::VerifyIntegrity(std::wstring_view filePath) {
    return m_impl->VerifyIntegrity(filePath);
}

std::optional<FileHash> DigitalSignatureValidator::CalculateAuthenticodeHash(
    std::wstring_view filePath,
    SignatureHashAlgorithm algorithm
) {
    return m_impl->CalculateAuthenticodeHash(filePath, algorithm);
}

bool DigitalSignatureValidator::VerifyHash(
    std::wstring_view filePath,
    std::span<const uint8_t> expectedHash,
    SignatureHashAlgorithm algorithm
) {
    return m_impl->VerifyHash(filePath, expectedHash, algorithm);
}

bool DigitalSignatureValidator::AddTrustedPublisher(
    const std::array<uint8_t, 20>& thumbprint
) {
    return m_impl->AddTrustedPublisher(thumbprint);
}

bool DigitalSignatureValidator::RemoveTrustedPublisher(
    const std::array<uint8_t, 20>& thumbprint
) {
    return m_impl->RemoveTrustedPublisher(thumbprint);
}

bool DigitalSignatureValidator::IsTrustedPublisher(const SignerInfo& signer) const {
    return m_impl->IsTrustedPublisher(signer);
}

std::vector<std::array<uint8_t, 20>> DigitalSignatureValidator::GetTrustedPublishers() const {
    return m_impl->GetTrustedPublishers();
}

bool DigitalSignatureValidator::BlockSigner(
    const std::array<uint8_t, 20>& thumbprint,
    std::string_view reason
) {
    return m_impl->BlockSigner(thumbprint, reason);
}

bool DigitalSignatureValidator::UnblockSigner(
    const std::array<uint8_t, 20>& thumbprint
) {
    return m_impl->UnblockSigner(thumbprint);
}

bool DigitalSignatureValidator::IsBlockedSigner(const SignerInfo& signer) const {
    return m_impl->IsBlockedSigner(signer);
}

std::vector<std::pair<std::array<uint8_t, 20>, std::string>>
    DigitalSignatureValidator::GetBlockedSigners() const {
    return m_impl->GetBlockedSigners();
}

bool DigitalSignatureValidator::AddCatalog(std::wstring_view catalogPath) {
    return m_impl->AddCatalog(catalogPath);
}

bool DigitalSignatureValidator::RemoveCatalog(std::wstring_view catalogPath) {
    return m_impl->RemoveCatalog(catalogPath);
}

std::optional<std::wstring> DigitalSignatureValidator::FindCatalogForFile(
    std::wstring_view filePath
) {
    return m_impl->FindCatalogForFile(filePath);
}

void DigitalSignatureValidator::RefreshCatalogCache() {
    m_impl->RefreshCatalogCache();
}

void DigitalSignatureValidator::SetBlockedSignerCallback(BlockedSignerCallback callback) {
    m_impl->SetBlockedSignerCallback(std::move(callback));
}

void DigitalSignatureValidator::SetUnknownSignerCallback(UnknownSignerCallback callback) {
    m_impl->SetUnknownSignerCallback(std::move(callback));
}

void DigitalSignatureValidator::ClearCache() {
    m_impl->ClearCache();
}

void DigitalSignatureValidator::InvalidateCache(std::wstring_view filePath) {
    m_impl->InvalidateCache(filePath);
}

std::unordered_map<std::string, size_t> DigitalSignatureValidator::GetCacheStats() const {
    return m_impl->GetCacheStats();
}

SignedFileType DigitalSignatureValidator::DetectFileType(std::wstring_view filePath) {
    return m_impl->DetectFileType(filePath);
}

SignerInfo DigitalSignatureValidator::ExtractSignerInfo(PCCERT_CONTEXT certContext) {
    return m_impl->ExtractSignerInfo(certContext);
}

std::string DigitalSignatureValidator::ThumbprintToHex(
    const std::array<uint8_t, 20>& thumbprint
) {
    return DigitalSignatureValidatorImpl::ThumbprintToHex(thumbprint);
}

std::optional<std::array<uint8_t, 20>> DigitalSignatureValidator::ParseThumbprint(
    std::string_view hexString
) {
    return DigitalSignatureValidatorImpl::ParseThumbprint(hexString);
}

SignatureValidatorStatistics DigitalSignatureValidator::GetStatistics() const {
    return m_impl->GetStatistics();
}

void DigitalSignatureValidator::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::string DigitalSignatureValidator::ExportReport() const {
    return m_impl->ExportReport();
}

bool DigitalSignatureValidator::SelfTest() {
    return m_impl->SelfTest();
}

std::string DigitalSignatureValidator::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << SignatureConstants::VERSION_MAJOR << "."
        << SignatureConstants::VERSION_MINOR << "."
        << SignatureConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// APT HUNTING PUBLIC WRAPPERS
// ============================================================================

SignatureAnalysisResult DigitalSignatureValidator::AnalyzeSignature(std::wstring_view filePath) {
    return m_impl->AnalyzeSignature(filePath);
}

bool DigitalSignatureValidator::AddStolenCertificate(const StolenCertEntry& entry) {
    return m_impl->AddStolenCertificate(entry);
}

size_t DigitalSignatureValidator::LoadStolenCertDatabase(std::span<const StolenCertEntry> entries) {
    return m_impl->LoadStolenCertDatabase(entries);
}

std::optional<StolenCertEntry> DigitalSignatureValidator::CheckStolenCertificate(
    const std::array<uint8_t, 20>& thumbprint
) const {
    return m_impl->CheckStolenCertificate(thumbprint);
}

void DigitalSignatureValidator::SetAnomalyCallback(SignatureAnomalyCallback callback) {
    m_impl->SetAnomalyCallback(std::move(callback));
}

SignatureAnalysisResult DigitalSignatureValidator::OnKernelImageLoad(
    uint32_t processId,
    std::wstring_view imagePath,
    uint64_t imageBase,
    uint64_t imageSize,
    uint8_t kernelSigLevel,
    bool isSystemImage
) {
    return m_impl->OnKernelImageLoad(processId, imagePath, imageBase, imageSize,
                                      kernelSigLevel, isSystemImage);
}

SignatureAnalysisResult DigitalSignatureValidator::ValidateProcessImage(
    uint32_t processId,
    uint32_t parentProcessId,
    std::wstring_view imagePath
) {
    return m_impl->ValidateProcessImage(processId, parentProcessId, imagePath);
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

TrustedPublisherGuard::TrustedPublisherGuard(
    const std::array<uint8_t, 20>& thumbprint
)
    : m_thumbprint(thumbprint)
    , m_added(false)
{
    m_added = DigitalSignatureValidator::Instance().AddTrustedPublisher(thumbprint);
}

TrustedPublisherGuard::~TrustedPublisherGuard() {
    if (m_added) {
        if (!DigitalSignatureValidator::Instance().RemoveTrustedPublisher(m_thumbprint)) {
            SS_LOG_WARN(LOG_CATEGORY, L"TrustedPublisherGuard cleanup could not remove trusted publisher");
        }
    }
}

}  // namespace Security
}  // namespace ShadowStrike
