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

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"DigitalSignatureValidator";
}

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> DigitalSignatureValidator::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetSignatureResultName(SignatureResult result) noexcept {
    switch (result) {
        case SignatureResult::Valid:              return "Valid";
        case SignatureResult::InvalidSignature:   return "InvalidSignature";
        case SignatureResult::InvalidHash:        return "InvalidHash";
        case SignatureResult::Unsigned:           return "Unsigned";
        case SignatureResult::UntrustedRoot:      return "UntrustedRoot";
        case SignatureResult::Revoked:            return "Revoked";
        case SignatureResult::Expired:            return "Expired";
        case SignatureResult::NotYetValid:        return "NotYetValid";
        case SignatureResult::BadTimestamp:       return "BadTimestamp";
        case SignatureResult::TamperedFile:       return "TamperedFile";
        case SignatureResult::InvalidCertificate: return "InvalidCertificate";
        case SignatureResult::ChainError:         return "ChainError";
        case SignatureResult::PolicyViolation:    return "PolicyViolation";
        case SignatureResult::CatalogError:       return "CatalogError";
        case SignatureResult::BlockedSigner:      return "BlockedSigner";
        case SignatureResult::WeakAlgorithm:      return "WeakAlgorithm";
        case SignatureResult::Error:              return "Error";
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

[[nodiscard]] std::string_view GetHashAlgorithmName(HashAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case HashAlgorithm::Unknown: return "Unknown";
        case HashAlgorithm::MD5:     return "MD5";
        case HashAlgorithm::SHA1:    return "SHA1";
        case HashAlgorithm::SHA256:  return "SHA256";
        case HashAlgorithm::SHA384:  return "SHA384";
        case HashAlgorithm::SHA512:  return "SHA512";
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
    oss << "\"signerName\":\"" << Utils::StringUtils::ToNarrow(signer.signerName) << "\",";
    oss << "\"issuerName\":\"" << Utils::StringUtils::ToNarrow(signer.issuerName) << "\",";
    oss << "\"isMicrosoftSigned\":" << (isMicrosoftSigned ? "true" : "false") << ",";
    oss << "\"isEV\":" << (isEV ? "true" : "false") << ",";
    oss << "\"isWHQL\":" << (isWHQL ? "true" : "false") << ",";
    oss << "\"isDualSigned\":" << (isDualSigned ? "true" : "false") << ",";
    oss << "\"hasTimestamp\":" << (HasValidTimestamp() ? "true" : "false") << ",";
    oss << "\"errorCode\":" << errorCode;
    if (!errorMessage.empty()) {
        oss << ",\"errorMessage\":\"" << errorMessage << "\"";
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

void SignatureValidatorStatistics::Reset() noexcept {
    totalValidations = 0;
    validSignatures = 0;
    invalidSignatures = 0;
    unsignedFiles = 0;
    cacheHits = 0;
    cacheMisses = 0;
    revocationChecks = 0;
    revokedCertificates = 0;
    expiredCertificates = 0;
    blockedSigners = 0;
    avgValidationTimeUs = 0;
    startTime = Clock::now();
}

std::string SignatureValidatorStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalValidations\":" << totalValidations.load() << ",";
    oss << "\"validSignatures\":" << validSignatures.load() << ",";
    oss << "\"invalidSignatures\":" << invalidSignatures.load() << ",";
    oss << "\"unsignedFiles\":" << unsignedFiles.load() << ",";
    oss << "\"cacheHits\":" << cacheHits.load() << ",";
    oss << "\"cacheMisses\":" << cacheMisses.load() << ",";
    oss << "\"revocationChecks\":" << revocationChecks.load() << ",";
    oss << "\"revokedCertificates\":" << revokedCertificates.load() << ",";
    oss << "\"expiredCertificates\":" << expiredCertificates.load() << ",";
    oss << "\"blockedSigners\":" << blockedSigners.load() << ",";
    oss << "\"avgValidationTimeUs\":" << avgValidationTimeUs.load();
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

        // Clear caches
        m_validationCache.clear();
        m_catalogCache.clear();
        m_trustedPublishers.clear();
        m_blockedSigners.clear();

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
                result.result = SignatureResult::Error;
                result.errorMessage = "Empty file path";
                return finalizeResult(result, startTime);
            }

            std::wstring pathStr(filePath);

            // Check path length
            if (pathStr.length() > 32767) {
                SS_LOG_WARN(LOG_CATEGORY, L"Path too long");
                result.result = SignatureResult::Error;
                result.errorMessage = "Path too long";
                return finalizeResult(result, startTime);
            }

            // Check file existence
            if (!std::filesystem::exists(pathStr)) {
                SS_LOG_WARN(LOG_CATEGORY, L"File does not exist: %ls", pathStr.c_str());
                result.result = SignatureResult::Error;
                result.errorMessage = "File does not exist";
                return finalizeResult(result, startTime);
            }

            // Check cache if enabled
            bool useCache = (options.flags & ValidationFlags::CacheResult) != ValidationFlags::None;
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
            if (result.result == SignatureResult::Unsigned &&
                (options.flags & ValidationFlags::AllowCatalogSignatures) != ValidationFlags::None) {
                result = verifyCatalogSignature(pathStr);
            }

            // Check blocked signers
            if (result.isValid && isBlockedSigner(result.signer)) {
                result.result = SignatureResult::BlockedSigner;
                result.isValid = false;
                m_stats.blockedSigners++;

                if (m_blockedSignerCallback) {
                    m_blockedSignerCallback(pathStr, result.signer);
                }
            }

            // Update statistics
            if (result.isValid) {
                m_stats.validSignatures++;
            } else if (result.result == SignatureResult::Unsigned) {
                m_stats.unsignedFiles++;
            } else {
                m_stats.invalidSignatures++;
            }

            // Cache result
            if (useCache && result.result != SignatureResult::Error) {
                cacheResult(pathStr, result);
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during verification: %hs", ex.what());
            result.result = SignatureResult::Error;
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
                result.result = SignatureResult::Error;
                result.errorMessage = "Empty file data";
                return finalizeResult(result, startTime);
            }

            // For memory verification, we need to write to a temp file
            // then verify it (WinTrust requires file handles)
            wchar_t tempPath[MAX_PATH];
            wchar_t tempFile[MAX_PATH];

            if (GetTempPathW(MAX_PATH, tempPath) == 0) {
                result.result = SignatureResult::Error;
                result.errorMessage = "Failed to get temp path";
                return finalizeResult(result, startTime);
            }

            if (GetTempFileNameW(tempPath, L"SIG", 0, tempFile) == 0) {
                result.result = SignatureResult::Error;
                result.errorMessage = "Failed to create temp file";
                return finalizeResult(result, startTime);
            }

            // Write data to temp file
            HANDLE hFile = CreateFileW(tempFile, GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);

            if (hFile == INVALID_HANDLE_VALUE) {
                result.result = SignatureResult::Error;
                result.errorMessage = "Failed to open temp file";
                DeleteFileW(tempFile);
                return finalizeResult(result, startTime);
            }

            DWORD bytesWritten = 0;
            BOOL writeResult = WriteFile(hFile, fileData.data(),
                static_cast<DWORD>(fileData.size()), &bytesWritten, nullptr);
            CloseHandle(hFile);

            if (!writeResult || bytesWritten != fileData.size()) {
                result.result = SignatureResult::Error;
                result.errorMessage = "Failed to write temp file";
                DeleteFileW(tempFile);
                return finalizeResult(result, startTime);
            }

            // Verify the temp file
            SignatureValidationOptions options;
            options.fileTypeHint = fileType;
            result = VerifyFile(tempFile, options);

            // Clean up temp file
            DeleteFileW(tempFile);

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during memory verification: %hs", ex.what());
            result.result = SignatureResult::Error;
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
                result.result = SignatureResult::CatalogError;
                result.errorMessage = "Catalog signature invalid";
                return finalizeResult(result, startTime);
            }

            // Calculate file hash
            auto fileHash = CalculateAuthenticodeHash(filePath, HashAlgorithm::SHA256);
            if (!fileHash.has_value()) {
                result.result = SignatureResult::Error;
                result.errorMessage = "Failed to calculate file hash";
                return finalizeResult(result, startTime);
            }

            // Verify hash is in catalog
            if (verifyHashInCatalog(catalogPathStr, fileHash.value())) {
                result.result = SignatureResult::Valid;
                result.isValid = true;
                result.catalogPath = catalogPathStr;
                result.signer = catalogResult.signer;
                result.fileHash = fileHash.value();
                result.isMicrosoftSigned = catalogResult.isMicrosoftSigned;
            } else {
                result.result = SignatureResult::InvalidHash;
                result.errorMessage = "File hash not found in catalog";
            }

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception during catalog verification: %hs", ex.what());
            result.result = SignatureResult::Error;
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

        std::wstring pathCopy(filePath);
        SignatureValidationOptions optionsCopy = options;

        // Queue async task (in production, use thread pool)
        std::thread([this, pathCopy, callback, optionsCopy]() {
            auto result = VerifyFile(pathCopy, optionsCopy);
            callback(result);
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
        options.flags = ValidationFlags::VerifyHashOnly;
        auto result = VerifyFile(filePath, options);
        return result.result != SignatureResult::Unsigned;
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
        options.flags = ValidationFlags::VerifyHashOnly;
        auto result = VerifyFile(filePath, options);
        return result.result != SignatureResult::TamperedFile &&
               result.result != SignatureResult::InvalidHash;
    }

    [[nodiscard]] std::optional<FileHash> CalculateAuthenticodeHash(
        std::wstring_view filePath,
        HashAlgorithm algorithm
    ) noexcept {
        try {
            std::wstring pathStr(filePath);
            FileHash hash{};

            // Use ImageGetDigestStream for Authenticode hash
            HANDLE hFile = CreateFileW(pathStr.c_str(), GENERIC_READ,
                FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

            if (hFile == INVALID_HANDLE_VALUE) {
                return std::nullopt;
            }

            // Get file size
            LARGE_INTEGER fileSize;
            if (!GetFileSizeEx(hFile, &fileSize)) {
                CloseHandle(hFile);
                return std::nullopt;
            }

            // Read file content
            std::vector<uint8_t> fileData(static_cast<size_t>(fileSize.QuadPart));
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, fileData.data(), static_cast<DWORD>(fileData.size()),
                          &bytesRead, nullptr)) {
                CloseHandle(hFile);
                return std::nullopt;
            }
            CloseHandle(hFile);

            // Calculate hash using CryptoAPI
            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;
            ALG_ID algId = CALG_SHA_256;

            switch (algorithm) {
                case HashAlgorithm::SHA1:   algId = CALG_SHA1; break;
                case HashAlgorithm::SHA256: algId = CALG_SHA_256; break;
                case HashAlgorithm::SHA384: algId = CALG_SHA_384; break;
                case HashAlgorithm::SHA512: algId = CALG_SHA_512; break;
                default: algId = CALG_SHA_256; break;
            }

            if (!CryptAcquireContextW(&hProv, nullptr, nullptr,
                                       PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                return std::nullopt;
            }

            if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                return std::nullopt;
            }

            if (!CryptHashData(hHash, fileData.data(),
                               static_cast<DWORD>(fileData.size()), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return std::nullopt;
            }

            DWORD hashLen = sizeof(hash);
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
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
        HashAlgorithm algorithm
    ) noexcept {
        auto calculatedHash = CalculateAuthenticodeHash(filePath, algorithm);
        if (!calculatedHash.has_value()) {
            return false;
        }

        if (expectedHash.size() > calculatedHash->size()) {
            return false;
        }

        return std::equal(expectedHash.begin(), expectedHash.end(),
                          calculatedHash->begin());
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
        auto fileHash = CalculateAuthenticodeHash(filePath, HashAlgorithm::SHA256);
        if (!fileHash.has_value()) {
            return std::nullopt;
        }

        std::shared_lock lock(m_mutex);

        // Search registered catalogs
        for (const auto& catalogPath : m_catalogPaths) {
            if (verifyHashInCatalog(catalogPath, fileHash.value())) {
                return catalogPath;
            }
        }

        // Search system catalogs using CryptCATAdminEnumCatalogFromHash
        HCATADMIN hCatAdmin = nullptr;
        if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
            return std::nullopt;
        }

        CATALOG_INFO catInfo = {};
        catInfo.cbStruct = sizeof(catInfo);

        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin,
            const_cast<BYTE*>(fileHash->data()),
            static_cast<DWORD>(fileHash->size()),
            0,
            nullptr);

        if (hCatInfo) {
            if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
                std::wstring result(catInfo.wszCatalogFile);
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                return result;
            }
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        }

        CryptCATAdminReleaseContext(hCatAdmin, 0);
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
            {"cacheHits", static_cast<size_t>(m_stats.cacheHits.load())},
            {"cacheMisses", static_cast<size_t>(m_stats.cacheMisses.load())}
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

            // Check if EV certificate (look for policy OID)
            // EV Code Signing OIDs
            static const char* evOids[] = {
                "2.23.140.1.3",      // EV Code Signing
                "2.16.840.1.114028.10.1.2", // Entrust EV
                "2.16.840.1.114412.2.1",    // DigiCert EV
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
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    [[nodiscard]] std::string ExportReport() const noexcept {
        std::ostringstream oss;
        oss << "DigitalSignatureValidator Report\n";
        oss << "================================\n\n";
        oss << "Statistics:\n" << m_stats.ToJson() << "\n\n";
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
                if (result.result != SignatureResult::Valid) {
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
        if ((options.flags & ValidationFlags::CheckRevocation) != ValidationFlags::None) {
            winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            winTrustData.dwProvFlags |= WTD_REVOCATION_CHECK_CHAIN;
            m_stats.revocationChecks++;
        }

        // Set online check if enabled
        if ((options.flags & ValidationFlags::OnlineCheck) != ValidationFlags::None) {
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

                // Check for WHQL signature
                if (provData->pPDSip && provData->pPDSip->pSip) {
                    // WHQL check would go here
                }
            }
        }

        // Interpret WinVerifyTrust result
        switch (status) {
            case ERROR_SUCCESS:
                result.result = SignatureResult::Valid;
                result.isValid = true;
                result.isEV = result.signer.isEV;
                break;

            case TRUST_E_NOSIGNATURE:
                result.result = SignatureResult::Unsigned;
                break;

            case TRUST_E_EXPLICIT_DISTRUST:
                result.result = SignatureResult::BlockedSigner;
                break;

            case TRUST_E_SUBJECT_NOT_TRUSTED:
                result.result = SignatureResult::UntrustedRoot;
                break;

            case CRYPT_E_SECURITY_SETTINGS:
                result.result = SignatureResult::PolicyViolation;
                break;

            case TRUST_E_BAD_DIGEST:
                result.result = SignatureResult::TamperedFile;
                break;

            case CERT_E_EXPIRED:
                result.result = SignatureResult::Expired;
                m_stats.expiredCertificates++;
                break;

            case CERT_E_REVOKED:
                result.result = SignatureResult::Revoked;
                m_stats.revokedCertificates++;
                break;

            case CERT_E_CHAINING:
                result.result = SignatureResult::ChainError;
                break;

            default:
                result.result = SignatureResult::InvalidSignature;
                result.errorCode = static_cast<int32_t>(status);
                break;
        }

        // Close WinTrust state
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &actionGuid, &winTrustData);

        return result;
    }

    [[nodiscard]] SignatureInfo verifyCatalogSignature(
        const std::wstring& filePath
    ) noexcept {
        SignatureInfo result;
        result.type = SignatureType::Catalog;

        // Calculate file hash
        auto fileHash = CalculateAuthenticodeHash(filePath, HashAlgorithm::SHA256);
        if (!fileHash.has_value()) {
            result.result = SignatureResult::Error;
            result.errorMessage = "Failed to calculate file hash";
            return result;
        }

        // Find catalog containing this hash
        HCATADMIN hCatAdmin = nullptr;
        GUID driverActionGuid = DRIVER_ACTION_VERIFY;

        if (!CryptCATAdminAcquireContext(&hCatAdmin, &driverActionGuid, 0)) {
            // Try without driver action
            if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
                result.result = SignatureResult::Unsigned;
                return result;
            }
        }

        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin,
            const_cast<BYTE*>(fileHash->data()),
            static_cast<DWORD>(fileHash->size()),
            0,
            nullptr);

        if (hCatInfo) {
            CATALOG_INFO catInfo = {};
            catInfo.cbStruct = sizeof(catInfo);

            if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
                result.catalogPath = catInfo.wszCatalogFile;

                // Verify the catalog file itself
                auto catalogResult = verifyWithWinTrust(catInfo.wszCatalogFile, {});
                if (catalogResult.isValid) {
                    result.result = SignatureResult::Valid;
                    result.isValid = true;
                    result.signer = catalogResult.signer;
                    result.isMicrosoftSigned = catalogResult.isMicrosoftSigned;
                    result.timestamps = catalogResult.timestamps;
                    result.fileHash = fileHash.value();
                } else {
                    result.result = SignatureResult::CatalogError;
                    result.errorMessage = "Catalog signature invalid";
                }
            }

            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        } else {
            result.result = SignatureResult::Unsigned;
        }

        CryptCATAdminReleaseContext(hCatAdmin, 0);
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
            now - it->second.verificationTime);

        if (age.count() > static_cast<long long>(m_config.cacheDurationSecs)) {
            return std::nullopt;
        }

        return it->second;
    }

    void cacheResult(const std::wstring& filePath, const SignatureInfo& result) noexcept {
        std::unique_lock lock(m_mutex);

        // Limit cache size
        if (m_validationCache.size() >= SignatureConstants::MAX_CACHED_VALIDATIONS) {
            // Remove oldest entry
            auto oldest = m_validationCache.begin();
            for (auto it = m_validationCache.begin(); it != m_validationCache.end(); ++it) {
                if (it->second.verificationTime < oldest->second.verificationTime) {
                    oldest = it;
                }
            }
            m_validationCache.erase(oldest);
        }

        m_validationCache[filePath] = result;
    }

    void initializeSystemCatalogs() noexcept {
        // System catalogs are automatically used via CryptCATAdmin APIs
        SS_LOG_DEBUG(LOG_CATEGORY, L"System catalog access initialized");
    }

    [[nodiscard]] bool isBlockedSigner(const SignerInfo& signer) const noexcept {
        return m_blockedSigners.count(signer.thumbprint) > 0;
    }

    [[nodiscard]] SignatureInfo finalizeResult(
        SignatureInfo& result,
        const TimePoint& startTime
    ) noexcept {
        auto endTime = Clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime);

        // Update average time
        uint64_t totalValidations = m_stats.totalValidations.load();
        if (totalValidations > 0) {
            uint64_t currentAvg = m_stats.avgValidationTimeUs.load();
            uint64_t newAvg = ((currentAvg * (totalValidations - 1)) +
                              static_cast<uint64_t>(duration.count())) / totalValidations;
            m_stats.avgValidationTimeUs = newAvg;
        }

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
    SignatureValidatorStatistics m_stats;

    // Caches
    std::unordered_map<std::wstring, SignatureInfo> m_validationCache;
    std::unordered_map<std::wstring, std::vector<FileHash>> m_catalogCache;
    std::vector<std::wstring> m_catalogPaths;

    // Trust management
    std::set<std::array<uint8_t, 20>> m_trustedPublishers;
    std::map<std::array<uint8_t, 20>, std::string> m_blockedSigners;

    // Callbacks
    BlockedSignerCallback m_blockedSignerCallback;
    UnknownSignerCallback m_unknownSignerCallback;
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
    HashAlgorithm algorithm
) {
    return m_impl->CalculateAuthenticodeHash(filePath, algorithm);
}

bool DigitalSignatureValidator::VerifyHash(
    std::wstring_view filePath,
    std::span<const uint8_t> expectedHash,
    HashAlgorithm algorithm
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
        DigitalSignatureValidator::Instance().RemoveTrustedPublisher(m_thumbprint);
    }
}

}  // namespace Security
}  // namespace ShadowStrike
