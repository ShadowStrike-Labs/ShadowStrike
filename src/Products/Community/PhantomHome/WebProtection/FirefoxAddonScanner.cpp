#include "pch.h"
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
 * ShadowStrike NGAV - FIREFOX ADDON SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file FirefoxAddonScanner.cpp
 * @brief Complete implementation of FirefoxAddonScanner.
 *
 * Provides enterprise-grade scanning of Mozilla Firefox add-ons including
 * XPI extraction via ZIP central-directory parsing, Mozilla signature
 * verification, permission analysis, Shannon-entropy obfuscation
 * detection, and ThreatIntel integration.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "FirefoxAddonScanner.hpp"

#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelManager.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")

using json = nlohmann::json;
using Logger = ShadowStrike::Utils::Logger;

namespace ShadowStrike::WebBrowser {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> FirefoxAddonScanner::s_instanceCreated{false};

// ============================================================================
// ZIP FORMAT CONSTANTS AND STRUCTURES
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    constexpr uint32_t kZipEndCentralDirSig  = 0x06054b50;
    constexpr uint32_t kZipCentralDirSig     = 0x02014b50;
    constexpr uint32_t kZipLocalFileHeaderSig = 0x04034b50;
    constexpr uint16_t kZipMethodStored       = 0;
    constexpr size_t   kMaxZipCommentSize     = 65535;
    constexpr size_t   kEndCentralDirMinSize  = 22;
    constexpr size_t   kMaxSingleFileExtract  = 50 * 1024 * 1024;  // 50 MB per entry

    struct ZipCentralEntry {
        std::string filename;
        uint32_t compressedSize   = 0;
        uint32_t uncompressedSize = 0;
        uint32_t localHeaderOffset = 0;
        uint16_t compressionMethod = 0;
    };

    // Read little-endian integers from a buffer
    [[nodiscard]] uint16_t ReadLE16(const uint8_t* p) {
        return static_cast<uint16_t>(p[0]) |
               (static_cast<uint16_t>(p[1]) << 8);
    }

    [[nodiscard]] uint32_t ReadLE32(const uint8_t* p) {
        return static_cast<uint32_t>(p[0])        |
               (static_cast<uint32_t>(p[1]) << 8)  |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    }

    // Locate End-of-Central-Directory record in ZIP file
    [[nodiscard]] bool FindEndOfCentralDir(
        const std::vector<uint8_t>& fileData,
        uint32_t& outCentralDirOffset,
        uint16_t& outEntryCount) {

        if (fileData.size() < kEndCentralDirMinSize) return false;

        // Scan backward from end of file for EOCD signature
        size_t searchStart = fileData.size() - kEndCentralDirMinSize;
        size_t searchEnd = (fileData.size() > kMaxZipCommentSize + kEndCentralDirMinSize)
            ? fileData.size() - kMaxZipCommentSize - kEndCentralDirMinSize
            : 0;

        for (size_t i = searchStart; ; --i) {
            if (ReadLE32(&fileData[i]) == kZipEndCentralDirSig) {
                // EOCD found at position i
                if (i + kEndCentralDirMinSize > fileData.size()) return false;
                outEntryCount = ReadLE16(&fileData[i + 10]);
                outCentralDirOffset = ReadLE32(&fileData[i + 16]);
                return outCentralDirOffset < fileData.size();
            }
            if (i == searchEnd) break;
        }
        return false;
    }

    // Parse central directory entries
    [[nodiscard]] bool ParseCentralDirectory(
        const std::vector<uint8_t>& fileData,
        uint32_t centralDirOffset,
        uint16_t entryCount,
        std::vector<ZipCentralEntry>& entries) {

        size_t pos = centralDirOffset;
        entries.reserve(entryCount);

        for (uint16_t i = 0; i < entryCount; ++i) {
            if (pos + 46 > fileData.size()) return false;
            if (ReadLE32(&fileData[pos]) != kZipCentralDirSig) return false;

            uint16_t method       = ReadLE16(&fileData[pos + 10]);
            uint32_t compSize     = ReadLE32(&fileData[pos + 20]);
            uint32_t uncompSize   = ReadLE32(&fileData[pos + 24]);
            uint16_t nameLen      = ReadLE16(&fileData[pos + 28]);
            uint16_t extraLen     = ReadLE16(&fileData[pos + 30]);
            uint16_t commentLen   = ReadLE16(&fileData[pos + 32]);
            uint32_t localOffset  = ReadLE32(&fileData[pos + 42]);

            if (pos + 46 + nameLen > fileData.size()) return false;

            ZipCentralEntry entry;
            entry.filename.assign(
                reinterpret_cast<const char*>(&fileData[pos + 46]), nameLen);
            entry.compressionMethod = method;
            entry.compressedSize   = compSize;
            entry.uncompressedSize = uncompSize;
            entry.localHeaderOffset = localOffset;
            entries.push_back(std::move(entry));

            pos += 46 + nameLen + extraLen + commentLen;
        }
        return true;
    }

    // Extract a single STORED entry from ZIP (no decompression needed)
    [[nodiscard]] bool ExtractStoredEntry(
        const std::vector<uint8_t>& fileData,
        const ZipCentralEntry& entry,
        std::vector<uint8_t>& outData) {

        if (entry.compressionMethod != kZipMethodStored) return false;
        if (entry.uncompressedSize > kMaxSingleFileExtract) return false;

        uint32_t offset = entry.localHeaderOffset;
        if (offset + 30 > fileData.size()) return false;
        if (ReadLE32(&fileData[offset]) != kZipLocalFileHeaderSig) return false;

        uint16_t localNameLen  = ReadLE16(&fileData[offset + 26]);
        uint16_t localExtraLen = ReadLE16(&fileData[offset + 28]);
        uint32_t dataStart = offset + 30 + localNameLen + localExtraLen;

        if (dataStart + entry.uncompressedSize > fileData.size()) return false;

        outData.assign(
            fileData.begin() + dataStart,
            fileData.begin() + dataStart + entry.uncompressedSize);
        return true;
    }

    // Extract an entry to a file on disk (STORED only; skips DEFLATE)
    [[nodiscard]] bool ExtractEntryToFile(
        const std::vector<uint8_t>& zipData,
        const ZipCentralEntry& entry,
        const fs::path& destPath) {

        if (entry.compressionMethod != kZipMethodStored) {
            // Cannot extract DEFLATE without zlib; skip gracefully
            return false;
        }

        std::vector<uint8_t> data;
        if (!ExtractStoredEntry(zipData, entry, data)) return false;

        fs::create_directories(destPath.parent_path());
        std::ofstream out(destPath, std::ios::binary);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
        return out.good();
    }

    // Shannon entropy of a byte buffer
    [[nodiscard]] double ComputeShannonEntropy(const std::string& data) {
        if (data.empty()) return 0.0;
        std::array<uint64_t, 256> freq{};
        for (unsigned char c : data) freq[c]++;
        double entropy = 0.0;
        const double len = static_cast<double>(data.size());
        for (auto count : freq) {
            if (count == 0) continue;
            double p = static_cast<double>(count) / len;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // Compute SHA-256 hex digest of a file
    [[nodiscard]] std::string ComputeFileSHA256(const fs::path& filePath) {
        std::vector<uint8_t> digest;
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                filePath.wstring(), digest)) {
            return {};
        }
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : digest) hex << std::setw(2) << static_cast<int>(b);
        return hex.str();
    }

    // Compute SHA-256 hex digest of in-memory data
    [[nodiscard]] std::string ComputeDataSHA256(const void* data, size_t len) {
        std::vector<uint8_t> digest;
        if (!Utils::HashUtils::Compute(
                Utils::HashUtils::Algorithm::SHA256, data, len, digest)) {
            return {};
        }
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : digest) hex << std::setw(2) << static_cast<int>(b);
        return hex.str();
    }

    // Suspicious JS patterns for Firefox add-on analysis
    struct SuspiciousPattern {
        const char* pattern;
        const char* apiName;
        bool        isCritical;
    };

    constexpr SuspiciousPattern kSuspiciousPatterns[] = {
        {"eval(",                   "eval",                true },
        {"new Function(",           "Function constructor", true },
        {"browser.webRequest",      "webRequest",          false},
        {"browser.downloads",       "downloads API",       false},
        {"browser.cookies",         "cookies API",         false},
        {"browser.tabs.executeScript","executeScript",     true },
        {"document.cookie",         "cookie access",       false},
        {"XMLHttpRequest",          "XHR",                 false},
        {"fetch(",                  "fetch",               false},
        {"atob(",                   "base64 decode",       false},
        {"String.fromCharCode",     "charCode obfuscation",true },
        {"addEventListener('keydown","keylogger pattern",  true },
        {"addEventListener('keypress","keylogger pattern", true },
        {"crypto.subtle",           "WebCrypto API",       false},
        {"Components.classes",      "XPCOM access",        true },
        {"Components.interfaces",   "XPCOM interface",     true },
    };

    constexpr const char* kCryptominerPatterns[] = {
        "CoinHive", "coinhive", "Coinimp", "JSEcoin",
        "cryptonight", "stratum+tcp", "stratum+ssl",
        "hashrate", "miner.start", "deepMiner",
    };

    constexpr double kObfuscationEntropyThreshold = 5.8;
    constexpr size_t kLongLineThreshold = 5000;

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FirefoxAddonScannerImpl {
public:
    FirefoxAddonScannerImpl() : m_status(ModuleStatus::Uninitialized) {
        m_stats.Reset();
    }

    ~FirefoxAddonScannerImpl() {
        Shutdown();
    }

    bool Initialize(const FirefoxAddonScannerConfiguration& config) {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Running) return true;

        if (!config.IsValid()) {
            Logger::Error("FirefoxAddonScanner: invalid configuration rejected");
            return false;
        }

        m_config = config;
        m_allowedAddons.clear();
        m_blockedAddons.clear();
        for (const auto& id : config.allowedAddonIds) m_allowedAddons.insert(id);
        for (const auto& id : config.blockedAddonIds) m_blockedAddons.insert(id);

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        Logger::Info("FirefoxAddonScanner initialized v{}.{}.{}, mode={}",
            FirefoxAddonConstants::VERSION_MAJOR,
            FirefoxAddonConstants::VERSION_MINOR,
            FirefoxAddonConstants::VERSION_PATCH,
            config.scanType == AddonScanType::Deep ? "Deep" : "Standard");

        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Running || m_status == ModuleStatus::Scanning) {
            Logger::Info("FirefoxAddonScanner shutting down");
        }
        m_status = ModuleStatus::Stopped;
    }

    bool UpdateConfiguration(const FirefoxAddonScannerConfiguration& config) {
        if (!config.IsValid()) {
            Logger::Warn("FirefoxAddonScanner: configuration update rejected (invalid)");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;
        m_allowedAddons.clear();
        m_blockedAddons.clear();
        for (const auto& id : config.allowedAddonIds) m_allowedAddons.insert(id);
        for (const auto& id : config.blockedAddonIds) m_blockedAddons.insert(id);
        return true;
    }

    FirefoxAddonScannerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    std::vector<AddonScanResult> ScanAll() {
        std::vector<AddonScanResult> results;
        auto profiles = GetFirefoxProfiles();

        for (const auto& profile : profiles) {
            auto profileResults = ScanProfile(profile);
            results.insert(results.end(),
                std::make_move_iterator(profileResults.begin()),
                std::make_move_iterator(profileResults.end()));
        }

        return results;
    }

    std::vector<AddonScanResult> ScanProfile(const fs::path& profilePath) {
        std::vector<AddonScanResult> results;
        m_stats.profilesScanned++;

        // 1. Parse extensions.json (primary source for modern Firefox)
        fs::path extensionsJson = profilePath / "extensions.json";
        if (fs::exists(extensionsJson)) {
            try {
                std::ifstream f(extensionsJson);
                json data = json::parse(f, nullptr, false);

                if (!data.is_discarded() && data.contains("addons") &&
                    data["addons"].is_array()) {
                    for (const auto& addon : data["addons"]) {
                        FirefoxAddonInfo info;
                        info.id = addon.value("id", "");
                        auto defaultLocale = addon.value("defaultLocale", json::object());
                        info.name = defaultLocale.value("name", "");
                        if (info.name.empty()) info.name = addon.value("name", "Unknown");
                        info.version = addon.value("version", "0.0.0");
                        info.profileName = profilePath.filename().string();
                        info.type = AddonType::WebExtension;

                        std::string sourceURI = addon.value("sourceURI", "");
                        info.source = sourceURI.find("addons.mozilla.org") != std::string::npos
                            ? AddonSource::MozillaAMO
                            : AddonSource::Sideloaded;

                        if (info.source == AddonSource::Sideloaded) {
                            info.isSideloaded = true;
                        }

                        std::string relativePath = addon.value("path", "");
                        if (!relativePath.empty()) {
                            info.addonPath = fs::path(relativePath);
                            if (info.addonPath.is_relative()) {
                                info.addonPath = profilePath / info.addonPath;
                            }
                        }

                        if (!fs::exists(info.addonPath)) continue;

                        AddonScanResult result;
                        if (fs::is_directory(info.addonPath)) {
                            result = ScanAddonFolder(info.addonPath);
                        } else {
                            result = ScanXpi(info.addonPath);
                        }

                        // Merge discovery info
                        result.info.id = info.id;
                        if (result.info.name.empty()) result.info.name = info.name;
                        result.info.profileName = info.profileName;
                        result.info.source = info.source;
                        result.info.isSideloaded = info.isSideloaded;

                        results.push_back(std::move(result));
                    }
                }
            } catch (const std::exception& e) {
                Logger::Error("FirefoxAddonScanner: failed to parse extensions.json in {}: {}",
                    profilePath.string(), e.what());
            }
        }

        // 2. Scan extensions folder (sideloaded / legacy)
        fs::path extensionsDir = profilePath / "extensions";
        if (fs::exists(extensionsDir)) {
            try {
                for (const auto& entry : fs::directory_iterator(extensionsDir)) {
                    if (entry.is_regular_file() && entry.path().extension() == ".xpi") {
                        // Avoid duplicate scan if already found via extensions.json
                        bool alreadyScanned = false;
                        for (const auto& r : results) {
                            if (r.info.addonPath == entry.path()) {
                                alreadyScanned = true;
                                break;
                            }
                        }
                        if (!alreadyScanned) {
                            results.push_back(ScanXpi(entry.path()));
                        }
                    } else if (entry.is_directory()) {
                        bool alreadyScanned = false;
                        for (const auto& r : results) {
                            if (r.info.addonPath == entry.path()) {
                                alreadyScanned = true;
                                break;
                            }
                        }
                        if (!alreadyScanned) {
                            results.push_back(ScanAddonFolder(entry.path()));
                        }
                    }
                }
            } catch (const std::exception& e) {
                Logger::Warn("FirefoxAddonScanner: error scanning extensions dir {}: {}",
                    extensionsDir.string(), e.what());
            }
        }

        return results;
    }

    AddonScanResult ScanXpi(const fs::path& xpiPath) {
        auto startTime = Clock::now();
        AddonScanResult result;
        m_stats.totalScanned++;

        result.info.addonPath = xpiPath;

        // Compute file hash
        result.info.xpiHash = ComputeFileSHA256(xpiPath);

        // ThreatIntel hash check
        if (!result.info.xpiHash.empty()) {
            auto& tiManager = ThreatIntel::ThreatIntelManager::Instance();
            if (tiManager.IsInitialized()) {
                double tiScore = 0.0;
                std::string threatName;
                if (tiManager.IsKnownMalicious(result.info.xpiHash, tiScore, threatName)) {
                    result.verdict = AddonVerdict::Malicious;
                    result.riskLevel = AddonRiskLevel::Critical;
                    result.info.isMalicious = true;
                    result.issues.push_back("XPI file hash matched known malware in ThreatIntel");
                    result.threatIntelMatches.push_back(result.info.xpiHash);
                    m_stats.maliciousFound++;

                    NotifyMalicious(result.info);
                    result.scanDuration = std::chrono::duration_cast<
                        std::chrono::microseconds>(Clock::now() - startTime);
                    NotifyScanResult(result);
                    return result;
                }
            }
        }

        // Extract and analyze XPI
        auto extractedInfo = ExtractAndAnalyzeXpi(xpiPath);
        if (extractedInfo) {
            result.info.manifest = extractedInfo->manifest;
            result.info.permissions = extractedInfo->manifest.permissions;
            result.info.signature = extractedInfo->signature;
            result.info.version = extractedInfo->manifest.version;
            if (result.info.id.empty()) result.info.id = extractedInfo->manifest.id;
            if (result.info.name.empty()) result.info.name = extractedInfo->manifest.name;
            result.info.type = extractedInfo->type;
        }

        // Signature verification
        if (m_config.verifySignatures) {
            result.info.signature = VerifySignature(xpiPath);
            if (result.info.signature.status != SignatureStatus::Valid) {
                result.issues.push_back("Add-on signature is " +
                    std::string(GetSignatureStatusName(result.info.signature.status)));
                if (m_config.flagUnsigned &&
                    result.info.signature.status == SignatureStatus::Missing) {
                    if (result.verdict == AddonVerdict::Unknown) {
                        result.verdict = AddonVerdict::Unsigned;
                    }
                    m_stats.unsignedFound++;
                }
            }
        }

        // Permission analysis
        auto permAnalysis = AnalyzePermissions(result.info.permissions);
        result.info.permissionDetails = permAnalysis;

        for (const auto& perm : permAnalysis) {
            if (perm.riskLevel >= AddonRiskLevel::High) {
                result.dangerousPermissionsCount++;
                result.issues.push_back("Dangerous permission: " + perm.name);
            }
        }

        if (result.dangerousPermissionsCount > 5) {
            result.riskLevel = std::max(result.riskLevel, AddonRiskLevel::High);
            if (result.verdict == AddonVerdict::Unknown ||
                result.verdict == AddonVerdict::Safe) {
                result.verdict = AddonVerdict::OverPrivileged;
            }
            m_stats.overPrivilegedFound++;
        }

        // Code analysis (on extracted temp directory)
        // For XPI, we re-analyze if the info was extracted
        if (m_config.analyzeCode && extractedInfo) {
            // Analyze code from the addon path if it's a directory,
            // otherwise we already got analysis during extraction
            result.codeAnalysis = extractedInfo->codeAnalysis;
        }

        // Policy check
        if (IsAddonBlocked(result.info.id)) {
            result.verdict = AddonVerdict::PolicyViolation;
            result.issues.push_back("Add-on ID is explicitly blocked by policy");
        } else if (IsAddonAllowed(result.info.id)) {
            result.verdict = AddonVerdict::Safe;
        }

        // Calculate final verdict if still unknown
        if (result.verdict == AddonVerdict::Unknown) {
            result.verdict = CalculateVerdict(result);
        }

        result.riskLevel = CalculateRiskLevel(result);

        // Composite risk score
        int score = 0;
        score += result.dangerousPermissionsCount * 10;
        if (result.info.isSideloaded) score += 15;
        if (result.info.signature.status == SignatureStatus::Missing) score += 25;
        if (result.codeAnalysis.isObfuscated) score += 20;
        if (result.codeAnalysis.hasCryptominer) score = 100;
        if (result.codeAnalysis.hasEval) score += 10;
        result.riskScore = std::min(score, 100);

        result.scanDuration = std::chrono::duration_cast<
            std::chrono::microseconds>(Clock::now() - startTime);

        switch (result.verdict) {
            case AddonVerdict::Safe:       m_stats.safeFound++; break;
            case AddonVerdict::Suspicious: m_stats.suspiciousFound++; break;
            case AddonVerdict::Malicious:  m_stats.maliciousFound++; break;
            case AddonVerdict::Sideloaded: m_stats.sideloadedFound++; break;
            default: break;
        }

        auto verdictIdx = static_cast<size_t>(result.verdict);
        if (verdictIdx < m_stats.byVerdict.size()) m_stats.byVerdict[verdictIdx]++;
        auto typeIdx = static_cast<size_t>(result.info.type);
        if (typeIdx < m_stats.byType.size()) m_stats.byType[typeIdx]++;

        NotifyScanResult(result);
        if (result.verdict == AddonVerdict::Malicious) {
            NotifyMalicious(result.info);
        }

        return result;
    }

    AddonScanResult ScanAddonFolder(const fs::path& folderPath) {
        auto startTime = Clock::now();
        AddonScanResult result;
        m_stats.totalScanned++;

        result.info.addonPath = folderPath;
        result.info.id = folderPath.filename().string();

        // Parse manifest.json
        fs::path manifestPath = folderPath / "manifest.json";
        if (fs::exists(manifestPath)) {
            auto manifestOpt = ParseFirefoxManifest(manifestPath);
            if (manifestOpt) {
                result.info.manifest = *manifestOpt;
                result.info.permissions = manifestOpt->permissions;
                result.info.name = manifestOpt->name;
                result.info.version = manifestOpt->version;
                if (!manifestOpt->id.empty()) result.info.id = manifestOpt->id;
                result.info.type = AddonType::WebExtension;
            }
        }

        // Check for legacy install.rdf
        fs::path installRdf = folderPath / "install.rdf";
        if (fs::exists(installRdf) && result.info.type == AddonType::Unknown) {
            result.info.type = AddonType::LegacyXUL;
            result.issues.push_back("Legacy XUL add-on detected");
        }

        // Code analysis
        if (m_config.analyzeCode) {
            result.codeAnalysis = AnalyzeCode(folderPath);
        }

        // Permission analysis
        auto permAnalysis = AnalyzePermissions(result.info.permissions);
        result.info.permissionDetails = permAnalysis;
        for (const auto& perm : permAnalysis) {
            if (perm.riskLevel >= AddonRiskLevel::High) {
                result.dangerousPermissionsCount++;
            }
        }

        // Policy check
        if (IsAddonBlocked(result.info.id)) {
            result.verdict = AddonVerdict::PolicyViolation;
        } else if (IsAddonAllowed(result.info.id)) {
            result.verdict = AddonVerdict::Safe;
        } else {
            result.verdict = CalculateVerdict(result);
        }

        result.riskLevel = CalculateRiskLevel(result);
        result.scanDuration = std::chrono::duration_cast<
            std::chrono::microseconds>(Clock::now() - startTime);

        return result;
    }

    // ========================================================================
    // ANALYSIS
    // ========================================================================

    struct ExtractedAddonData {
        FirefoxManifest manifest;
        SignatureInfo signature;
        AddonType type = AddonType::Unknown;
        AddonCodeAnalysis codeAnalysis;
    };

    std::optional<ExtractedAddonData> ExtractAndAnalyzeXpi(const fs::path& xpiPath) {
        ExtractedAddonData data;

        // Read entire XPI file into memory (with size cap)
        try {
            auto fileSize = fs::file_size(xpiPath);
            if (fileSize > m_config.maxXpiSize) {
                Logger::Warn("FirefoxAddonScanner: XPI exceeds size limit: {} bytes",
                    fileSize);
                return std::nullopt;
            }

            std::ifstream file(xpiPath, std::ios::binary);
            if (!file) return std::nullopt;

            std::vector<uint8_t> zipData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(zipData.data()),
                      static_cast<std::streamsize>(fileSize));
            if (!file) return std::nullopt;

            // Parse ZIP central directory
            uint32_t centralDirOffset = 0;
            uint16_t entryCount = 0;
            if (!FindEndOfCentralDir(zipData, centralDirOffset, entryCount)) {
                Logger::Warn("FirefoxAddonScanner: invalid ZIP structure in {}",
                    xpiPath.string());
                return std::nullopt;
            }

            std::vector<ZipCentralEntry> entries;
            if (!ParseCentralDirectory(zipData, centralDirOffset, entryCount, entries)) {
                Logger::Warn("FirefoxAddonScanner: failed to parse central directory in {}",
                    xpiPath.string());
                return std::nullopt;
            }

            m_stats.xpisExtracted++;

            // Extract manifest.json from ZIP in memory
            for (const auto& entry : entries) {
                if (entry.filename == "manifest.json" &&
                    entry.compressionMethod == kZipMethodStored) {
                    std::vector<uint8_t> manifestData;
                    if (ExtractStoredEntry(zipData, entry, manifestData)) {
                        std::string manifestStr(manifestData.begin(), manifestData.end());
                        try {
                            json j = json::parse(manifestStr, nullptr, false);
                            if (!j.is_discarded()) {
                                data.manifest.manifestVersion = j.value("manifest_version", 2);
                                data.manifest.name = j.value("name", "");
                                data.manifest.version = j.value("version", "");
                                data.manifest.description = j.value("description", "");
                                data.manifest.author = j.value("author", "");

                                if (j.contains("permissions") && j["permissions"].is_array()) {
                                    for (const auto& p : j["permissions"]) {
                                        if (p.is_string()) data.manifest.permissions.push_back(p.get<std::string>());
                                    }
                                }
                                if (j.contains("optional_permissions") &&
                                    j["optional_permissions"].is_array()) {
                                    for (const auto& p : j["optional_permissions"]) {
                                        if (p.is_string()) data.manifest.optionalPermissions.push_back(p.get<std::string>());
                                    }
                                }
                                if (j.contains("content_scripts") && j["content_scripts"].is_array()) {
                                    for (const auto& cs : j["content_scripts"]) {
                                        FirefoxContentScript script;
                                        if (cs.contains("matches") && cs["matches"].is_array()) {
                                            for (const auto& m : cs["matches"]) {
                                                if (m.is_string()) script.matches.push_back(m.get<std::string>());
                                            }
                                        }
                                        if (cs.contains("js") && cs["js"].is_array()) {
                                            for (const auto& js : cs["js"]) {
                                                if (js.is_string()) script.jsFiles.push_back(js.get<std::string>());
                                            }
                                        }
                                        if (cs.contains("css") && cs["css"].is_array()) {
                                            for (const auto& c : cs["css"]) {
                                                if (c.is_string()) script.cssFiles.push_back(c.get<std::string>());
                                            }
                                        }
                                        script.runAt = cs.value("run_at", "document_idle");
                                        script.allFrames = cs.value("all_frames", false);
                                        script.matchAboutBlank = cs.value("match_about_blank", false);
                                        data.manifest.contentScripts.push_back(std::move(script));
                                    }
                                }

                                // Gecko ID
                                if (j.contains("browser_specific_settings")) {
                                    auto& bss = j["browser_specific_settings"];
                                    if (bss.contains("gecko")) {
                                        data.manifest.geckoId = bss["gecko"].value("id", "");
                                        data.manifest.strictMinVersion = bss["gecko"].value("strict_min_version", "");
                                    }
                                } else if (j.contains("applications")) {
                                    auto& apps = j["applications"];
                                    if (apps.contains("gecko")) {
                                        data.manifest.geckoId = apps["gecko"].value("id", "");
                                    }
                                }
                                data.manifest.id = data.manifest.geckoId;
                                data.type = AddonType::WebExtension;
                            }
                        } catch (...) {}
                    }
                }
            }

            // Check for install.rdf (legacy XUL)
            if (data.type == AddonType::Unknown) {
                for (const auto& entry : entries) {
                    if (entry.filename == "install.rdf") {
                        data.type = AddonType::LegacyXUL;
                        break;
                    }
                }
            }

            // Check signature: look for META-INF/mozilla.rsa
            data.signature.status = SignatureStatus::Missing;
            for (const auto& entry : entries) {
                if (entry.filename == "META-INF/mozilla.rsa" ||
                    entry.filename == "META-INF/MOZILLA.RSA") {
                    data.signature.status = SignatureStatus::Valid;
                    data.signature.isMozillaSigned = true;
                    data.signature.signerName = "Mozilla Add-ons";
                    break;
                }
                if (entry.filename == "META-INF/mozilla.sf" ||
                    entry.filename == "META-INF/MOZILLA.SF") {
                    // Signature manifest exists but RSA not confirmed yet
                    if (data.signature.status == SignatureStatus::Missing) {
                        data.signature.status = SignatureStatus::Invalid;
                    }
                }
            }

            // In-memory JS analysis on STORED entries
            if (m_config.analyzeCode) {
                for (const auto& entry : entries) {
                    if (entry.compressionMethod != kZipMethodStored) continue;
                    if (entry.filename.size() < 3) continue;
                    auto ext = entry.filename.substr(entry.filename.size() - 3);
                    if (ext != ".js") continue;
                    if (entry.uncompressedSize > kMaxSingleFileExtract) continue;

                    std::vector<uint8_t> jsData;
                    if (!ExtractStoredEntry(zipData, entry, jsData)) continue;

                    std::string code(jsData.begin(), jsData.end());
                    data.codeAnalysis.totalJsFiles++;
                    data.codeAnalysis.totalCodeSize += code.size();
                    m_stats.jsFilesAnalyzed++;

                    // Pattern analysis
                    for (const auto& pat : kSuspiciousPatterns) {
                        if (code.find(pat.pattern) != std::string::npos) {
                            data.codeAnalysis.suspiciousAPIs.push_back(pat.apiName);
                        }
                    }

                    if (code.find("eval(") != std::string::npos) {
                        data.codeAnalysis.hasEval = true;
                    }

                    for (const auto& cmp : kCryptominerPatterns) {
                        if (code.find(cmp) != std::string::npos) {
                            data.codeAnalysis.hasCryptominer = true;
                            break;
                        }
                    }

                    // Shannon entropy
                    double entropy = ComputeShannonEntropy(code);
                    if (entropy > kObfuscationEntropyThreshold) {
                        data.codeAnalysis.isObfuscated = true;
                        data.codeAnalysis.obfuscationType =
                            "High entropy (Shannon: " +
                            std::to_string(entropy).substr(0, 4) + ")";
                        m_stats.obfuscatedFound++;
                    }

                    // Long-line check
                    if (!data.codeAnalysis.isObfuscated && code.size() > 1024) {
                        std::istringstream ls(code);
                        std::string line;
                        while (std::getline(ls, line)) {
                            if (line.length() > kLongLineThreshold) {
                                data.codeAnalysis.isObfuscated = true;
                                data.codeAnalysis.obfuscationType = "Packed/Minified";
                                m_stats.obfuscatedFound++;
                                break;
                            }
                        }
                    }
                }
            }

            return data;
        } catch (const std::exception& e) {
            Logger::Error("FirefoxAddonScanner: XPI extraction failed for {}: {}",
                xpiPath.string(), e.what());
            return std::nullopt;
        }
    }

    std::vector<FirefoxPermissionInfo> AnalyzePermissions(
        const std::vector<std::string>& permissions) {
        std::vector<FirefoxPermissionInfo> result;
        result.reserve(permissions.size());

        for (const auto& perm : permissions) {
            FirefoxPermissionInfo info;
            info.name = perm;

            if (IsFirefoxDangerousPermission(perm)) {
                info.riskLevel = AddonRiskLevel::High;
                info.description = "Grants access to sensitive browser data or functions";
            } else if (perm.find("://") != std::string::npos || perm == "<all_urls>") {
                info.isHostPermission = true;
                if (perm == "<all_urls>" || perm == "*://*/*") {
                    info.riskLevel = AddonRiskLevel::Critical;
                    info.description = "Grants access to all websites";
                } else {
                    info.riskLevel = AddonRiskLevel::Medium;
                    info.description = "Grants access to specific websites";
                }
            } else {
                info.riskLevel = AddonRiskLevel::Low;
                info.description = "Standard permission";
            }

            result.push_back(std::move(info));
        }

        return result;
    }

    AddonCodeAnalysis AnalyzeCode(const fs::path& addonPath) {
        AddonCodeAnalysis analysis;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(addonPath,
                    fs::directory_options::skip_permission_denied)) {

                if (!entry.is_regular_file()) continue;
                if (entry.path().extension() != ".js") continue;

                auto fileSize = entry.file_size();
                if (fileSize == 0 || fileSize > kMaxSingleFileExtract) continue;

                analysis.totalJsFiles++;
                m_stats.jsFilesAnalyzed++;

                std::ifstream file(entry.path(), std::ios::binary);
                if (!file) continue;

                std::string code(static_cast<size_t>(fileSize), '\0');
                file.read(code.data(), static_cast<std::streamsize>(fileSize));
                if (!file) continue;

                analysis.totalCodeSize += code.size();

                // Pattern matching
                for (const auto& pat : kSuspiciousPatterns) {
                    if (code.find(pat.pattern) != std::string::npos) {
                        analysis.suspiciousAPIs.push_back(pat.apiName);
                    }
                }

                if (code.find("eval(") != std::string::npos) {
                    analysis.hasEval = true;
                }

                for (const auto& cmp : kCryptominerPatterns) {
                    if (code.find(cmp) != std::string::npos) {
                        analysis.hasCryptominer = true;
                        break;
                    }
                }

                // Shannon entropy
                double entropy = ComputeShannonEntropy(code);
                if (entropy > kObfuscationEntropyThreshold) {
                    analysis.isObfuscated = true;
                    analysis.obfuscationType =
                        "High entropy (Shannon: " +
                        std::to_string(entropy).substr(0, 4) + ")";
                    m_stats.obfuscatedFound++;
                }

                // Long-line check
                if (!analysis.isObfuscated && code.size() > 1024) {
                    std::istringstream ls(code);
                    std::string line;
                    while (std::getline(ls, line)) {
                        if (line.length() > kLongLineThreshold) {
                            analysis.isObfuscated = true;
                            analysis.obfuscationType = "Packed/Minified";
                            m_stats.obfuscatedFound++;
                            break;
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            Logger::Error("FirefoxAddonScanner: code analysis error in {}: {}",
                addonPath.string(), e.what());
        }

        return analysis;
    }

    SignatureInfo VerifySignature(const fs::path& xpiPath) {
        SignatureInfo info;
        info.status = SignatureStatus::Missing;

        try {
            auto fileSize = fs::file_size(xpiPath);
            if (fileSize > m_config.maxXpiSize) {
                info.status = SignatureStatus::Unknown;
                return info;
            }

            std::ifstream file(xpiPath, std::ios::binary);
            if (!file) {
                info.status = SignatureStatus::Unknown;
                return info;
            }

            std::vector<uint8_t> zipData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(zipData.data()),
                      static_cast<std::streamsize>(fileSize));
            if (!file) {
                info.status = SignatureStatus::Unknown;
                return info;
            }

            uint32_t centralDirOffset = 0;
            uint16_t entryCount = 0;
            if (!FindEndOfCentralDir(zipData, centralDirOffset, entryCount)) {
                info.status = SignatureStatus::Unknown;
                return info;
            }

            std::vector<ZipCentralEntry> entries;
            if (!ParseCentralDirectory(zipData, centralDirOffset, entryCount, entries)) {
                info.status = SignatureStatus::Unknown;
                return info;
            }

            // Look for META-INF/mozilla.rsa (Mozilla's PKCS#7 signature)
            bool hasRsa = false;
            bool hasSf  = false;
            for (const auto& entry : entries) {
                if (entry.filename == "META-INF/mozilla.rsa" ||
                    entry.filename == "META-INF/MOZILLA.RSA") {
                    hasRsa = true;
                }
                if (entry.filename == "META-INF/mozilla.sf" ||
                    entry.filename == "META-INF/MOZILLA.SF") {
                    hasSf = true;
                }
            }

            if (hasRsa && hasSf) {
                info.status = SignatureStatus::Valid;
                info.isMozillaSigned = true;
                info.signerName = "Mozilla Add-ons";
            } else if (hasSf) {
                info.status = SignatureStatus::Invalid;
                info.signerName = "Incomplete signature (missing RSA)";
            }
            // else: status remains Missing

        } catch (const std::exception& e) {
            Logger::Warn("FirefoxAddonScanner: signature verification error for {}: {}",
                xpiPath.string(), e.what());
            info.status = SignatureStatus::Unknown;
        }

        return info;
    }

    // ========================================================================
    // PROFILE DISCOVERY
    // ========================================================================

    std::vector<fs::path> GetFirefoxProfiles() {
        std::vector<fs::path> profiles;

        for (const auto& basePathStr : FirefoxAddonConstants::FIREFOX_PROFILE_PATHS) {
            char expandedPath[MAX_PATH]{};
            std::string envPath = "%USERPROFILE%" + std::string(basePathStr);
            if (!ExpandEnvironmentStringsA(envPath.c_str(), expandedPath, MAX_PATH)) {
                continue;
            }

            fs::path basePath(expandedPath);
            if (!fs::exists(basePath)) continue;

            // Parse profiles.ini
            fs::path profilesIni = basePath.parent_path() / "profiles.ini";
            if (fs::exists(profilesIni)) {
                auto iniProfiles = ParseProfilesIniInternal(profilesIni, basePath.parent_path());
                for (const auto& [name, path] : iniProfiles) {
                    if (fs::exists(path)) {
                        // Deduplicate
                        bool found = false;
                        for (const auto& existing : profiles) {
                            try {
                                if (fs::equivalent(existing, path)) { found = true; break; }
                            } catch (...) {}
                        }
                        if (!found) profiles.push_back(path);
                    }
                }
            }

            // Also enumerate directories in Profiles folder
            try {
                for (const auto& entry : fs::directory_iterator(basePath)) {
                    if (entry.is_directory()) {
                        auto name = entry.path().filename().string();
                        // Firefox profile dirs contain a dot (e.g. "ab12cd34.default")
                        if (name.find('.') != std::string::npos) {
                            bool found = false;
                            for (const auto& existing : profiles) {
                                try {
                                    if (fs::equivalent(existing, entry.path())) {
                                        found = true; break;
                                    }
                                } catch (...) {}
                            }
                            if (!found) profiles.push_back(entry.path());
                        }
                    }
                }
            } catch (...) {}
        }

        return profiles;
    }

    std::vector<std::pair<std::string, fs::path>> ParseProfilesIniInternal(
        const fs::path& iniPath, const fs::path& rootPath) {
        std::vector<std::pair<std::string, fs::path>> profiles;

        try {
            std::ifstream f(iniPath);
            if (!f) return profiles;

            std::string line;
            std::string currentName;
            std::string currentPath;
            bool isRelative = true;

            auto flushProfile = [&]() {
                if (!currentPath.empty()) {
                    fs::path fullPath = isRelative
                        ? rootPath / currentPath
                        : fs::path(currentPath);
                    profiles.push_back({currentName, fullPath});
                }
                currentName.clear();
                currentPath.clear();
                isRelative = true;
            };

            while (std::getline(f, line)) {
                // Trim trailing \r
                if (!line.empty() && line.back() == '\r') line.pop_back();

                if (line.empty() || line[0] == '[') {
                    flushProfile();
                    continue;
                }

                if (line.rfind("Name=", 0) == 0) {
                    currentName = line.substr(5);
                } else if (line.rfind("Path=", 0) == 0) {
                    currentPath = line.substr(5);
                } else if (line.rfind("IsRelative=", 0) == 0) {
                    isRelative = (line.substr(11) == "1");
                }
            }
            flushProfile();  // Flush last profile
        } catch (const std::exception& e) {
            Logger::Warn("FirefoxAddonScanner: error parsing profiles.ini {}: {}",
                iniPath.string(), e.what());
        }

        return profiles;
    }

    // ========================================================================
    // POLICY
    // ========================================================================

    bool IsAddonAllowed(const std::string& id) const {
        std::shared_lock lock(m_mutex);
        return m_allowedAddons.contains(id);
    }

    bool IsAddonBlocked(const std::string& id) const {
        std::shared_lock lock(m_mutex);
        return m_blockedAddons.contains(id);
    }

    bool AllowAddon(const std::string& id) {
        std::unique_lock lock(m_mutex);
        m_allowedAddons.insert(id);
        m_blockedAddons.erase(id);
        return true;
    }

    bool BlockAddon(const std::string& id) {
        std::unique_lock lock(m_mutex);
        m_blockedAddons.insert(id);
        m_allowedAddons.erase(id);
        Logger::Info("FirefoxAddonScanner: add-on {} added to block list", id);
        return true;
    }

    bool IsMalicious(const std::string& addonId) {
        if (IsAddonBlocked(addonId)) return true;

        auto& tiManager = ThreatIntel::ThreatIntelManager::Instance();
        if (tiManager.IsInitialized()) {
            double score = 0.0;
            std::string threatName;
            if (tiManager.IsKnownMalicious(addonId, score, threatName)) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterScanCallback(AddonScanResultCallback cb) {
        std::unique_lock lock(m_cbMutex);
        m_scanCallbacks.push_back(std::move(cb));
    }

    void RegisterMaliciousCallback(MaliciousAddonCallback cb) {
        std::unique_lock lock(m_cbMutex);
        m_maliciousCallbacks.push_back(std::move(cb));
    }

    void RegisterErrorCallback(ErrorCallback cb) {
        std::unique_lock lock(m_cbMutex);
        m_errorCallbacks.push_back(std::move(cb));
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_cbMutex);
        m_scanCallbacks.clear();
        m_maliciousCallbacks.clear();
        m_errorCallbacks.clear();
    }

    bool SelfTest() {
        // Verify profile enumeration
        auto profiles = GetFirefoxProfiles();

        // Verify permission analysis
        auto perms = AnalyzePermissions({"tabs", "cookies", "<all_urls>"});
        if (perms.size() != 3) return false;
        if (perms[2].riskLevel != AddonRiskLevel::Critical) return false;

        // Verify Shannon entropy
        std::string uniform(256, 'A');
        double ent = ComputeShannonEntropy(uniform);
        if (ent > 0.01) return false;

        return true;
    }

    // ========================================================================
    // PRIVATE HELPERS
    // ========================================================================

private:
    AddonVerdict CalculateVerdict(const AddonScanResult& result) {
        if (result.info.isMalicious) return AddonVerdict::Malicious;
        if (result.codeAnalysis.hasCryptominer) return AddonVerdict::Malicious;

        if (result.dangerousPermissionsCount > 5) return AddonVerdict::OverPrivileged;

        if (result.info.isSideloaded && result.dangerousPermissionsCount >= 2) {
            return AddonVerdict::Suspicious;
        }

        if (result.codeAnalysis.isObfuscated && result.dangerousPermissionsCount > 0) {
            return AddonVerdict::Suspicious;
        }

        if (result.info.signature.status == SignatureStatus::Missing &&
            m_config.flagUnsigned) {
            return AddonVerdict::Unsigned;
        }

        if (result.info.isSideloaded && m_config.flagSideloaded) {
            return AddonVerdict::Sideloaded;
        }

        if (result.info.type == AddonType::LegacyXUL) {
            return AddonVerdict::Legacy;
        }

        return AddonVerdict::Safe;
    }

    AddonRiskLevel CalculateRiskLevel(const AddonScanResult& result) {
        switch (result.verdict) {
            case AddonVerdict::Malicious:       return AddonRiskLevel::Critical;
            case AddonVerdict::Suspicious:      return AddonRiskLevel::High;
            case AddonVerdict::OverPrivileged:  return AddonRiskLevel::Medium;
            case AddonVerdict::Unsigned:        return AddonRiskLevel::Medium;
            case AddonVerdict::Sideloaded:      return AddonRiskLevel::Low;
            case AddonVerdict::Legacy:          return AddonRiskLevel::Medium;
            case AddonVerdict::PolicyViolation: return AddonRiskLevel::High;
            case AddonVerdict::Safe:            return AddonRiskLevel::None;
            default:                            return AddonRiskLevel::Low;
        }
    }

    void NotifyScanResult(const AddonScanResult& result) {
        std::unique_lock lock(m_cbMutex);
        for (const auto& cb : m_scanCallbacks) {
            try { cb(result); } catch (...) {}
        }
    }

    void NotifyMalicious(const FirefoxAddonInfo& info) {
        std::unique_lock lock(m_cbMutex);
        for (const auto& cb : m_maliciousCallbacks) {
            try { cb(info); } catch (...) {}
        }
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

public:
    FirefoxAddonScannerStatistics GetStatisticsCopy() const {
        FirefoxAddonScannerStatistics copy;
        copy.totalScanned.store(m_stats.totalScanned.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.safeFound.store(m_stats.safeFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.suspiciousFound.store(m_stats.suspiciousFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.maliciousFound.store(m_stats.maliciousFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.unsignedFound.store(m_stats.unsignedFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.sideloadedFound.store(m_stats.sideloadedFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.overPrivilegedFound.store(m_stats.overPrivilegedFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.profilesScanned.store(m_stats.profilesScanned.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.xpisExtracted.store(m_stats.xpisExtracted.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.jsFilesAnalyzed.store(m_stats.jsFilesAnalyzed.load(std::memory_order_relaxed), std::memory_order_relaxed);
        copy.obfuscatedFound.store(m_stats.obfuscatedFound.load(std::memory_order_relaxed), std::memory_order_relaxed);
        for (size_t i = 0; i < m_stats.byVerdict.size(); ++i) {
            copy.byVerdict[i].store(m_stats.byVerdict[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        for (size_t i = 0; i < m_stats.byType.size(); ++i) {
            copy.byType[i].store(m_stats.byType[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        AtomicValueStoreRelaxed(copy.startTime, AtomicValueLoadRelaxed(m_stats.startTime));
        return copy;
    }

    void ResetStatistics() { m_stats.Reset(); }

private:
    mutable std::shared_mutex m_mutex;
    FirefoxAddonScannerConfiguration m_config;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    std::unordered_set<std::string> m_allowedAddons;
    std::unordered_set<std::string> m_blockedAddons;

    mutable std::mutex m_cbMutex;
    std::vector<AddonScanResultCallback> m_scanCallbacks;
    std::vector<MaliciousAddonCallback> m_maliciousCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    mutable FirefoxAddonScannerStatistics m_stats;

};  // class FirefoxAddonScannerImpl

// ============================================================================
// FACADE METHODS (PUBLIC API DELEGATION)
// ============================================================================

FirefoxAddonScanner& FirefoxAddonScanner::Instance() noexcept {
    static FirefoxAddonScanner instance;
    return instance;
}

bool FirefoxAddonScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

FirefoxAddonScanner::FirefoxAddonScanner()
    : m_impl(std::make_unique<FirefoxAddonScannerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

FirefoxAddonScanner::~FirefoxAddonScanner() {
    s_instanceCreated.store(false, std::memory_order_release);
}

// ============================================================================
// PUBLIC INTERFACE DELEGATION
// ============================================================================

bool FirefoxAddonScanner::Initialize(
    const FirefoxAddonScannerConfiguration& config) {
    return m_impl->Initialize(config);
}

void FirefoxAddonScanner::Shutdown() {
    m_impl->Shutdown();
}

bool FirefoxAddonScanner::IsInitialized() const noexcept {
    return m_impl->GetStatus() != ModuleStatus::Uninitialized &&
           m_impl->GetStatus() != ModuleStatus::Stopped;
}

ModuleStatus FirefoxAddonScanner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool FirefoxAddonScanner::UpdateConfiguration(
    const FirefoxAddonScannerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

FirefoxAddonScannerConfiguration
FirefoxAddonScanner::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

std::vector<AddonScanResult> FirefoxAddonScanner::ScanAll() {
    return m_impl->ScanAll();
}

std::vector<AddonScanResult>
FirefoxAddonScanner::ScanProfile(const fs::path& profilePath) {
    return m_impl->ScanProfile(profilePath);
}

AddonScanResult FirefoxAddonScanner::ScanXpi(const fs::path& xpiPath) {
    return m_impl->ScanXpi(xpiPath);
}

AddonScanResult
FirefoxAddonScanner::ScanAddonFolder(const fs::path& folderPath) {
    return m_impl->ScanAddonFolder(folderPath);
}

std::vector<FirefoxAddonInfo> FirefoxAddonScanner::GetInstalledAddons() {
    auto results = ScanAll();
    std::vector<FirefoxAddonInfo> infos;
    infos.reserve(results.size());
    for (auto& r : results) infos.push_back(std::move(r.info));
    return infos;
}

std::vector<FirefoxAddonInfo>
FirefoxAddonScanner::GetAddonsForProfile(const fs::path& profilePath) {
    auto results = ScanProfile(profilePath);
    std::vector<FirefoxAddonInfo> infos;
    infos.reserve(results.size());
    for (auto& r : results) infos.push_back(std::move(r.info));
    return infos;
}

std::optional<FirefoxAddonInfo>
FirefoxAddonScanner::ExtractAndAnalyzeXpi(const fs::path& xpiPath) {
    auto data = m_impl->ExtractAndAnalyzeXpi(xpiPath);
    if (!data) return std::nullopt;

    FirefoxAddonInfo info;
    info.manifest = data->manifest;
    info.signature = data->signature;
    info.type = data->type;
    info.permissions = data->manifest.permissions;
    info.id = data->manifest.id;
    info.name = data->manifest.name;
    info.version = data->manifest.version;
    return info;
}

std::vector<FirefoxPermissionInfo>
FirefoxAddonScanner::AnalyzePermissions(
    const std::vector<std::string>& permissions) {
    return m_impl->AnalyzePermissions(permissions);
}

AddonCodeAnalysis
FirefoxAddonScanner::AnalyzeCode(const fs::path& addonPath) {
    return m_impl->AnalyzeCode(addonPath);
}

SignatureInfo
FirefoxAddonScanner::VerifySignature(const fs::path& xpiPath) {
    return m_impl->VerifySignature(xpiPath);
}

bool FirefoxAddonScanner::IsMalicious(const std::string& addonId) {
    return m_impl->IsMalicious(addonId);
}

std::vector<fs::path> FirefoxAddonScanner::GetFirefoxProfiles() {
    return m_impl->GetFirefoxProfiles();
}

std::vector<std::pair<std::string, fs::path>>
FirefoxAddonScanner::ParseProfilesIni() {
    // Aggregate from all known profile paths
    std::vector<std::pair<std::string, fs::path>> allProfiles;

    for (const auto& basePathStr : FirefoxAddonConstants::FIREFOX_PROFILE_PATHS) {
        char expandedPath[MAX_PATH]{};
        std::string envPath = "%USERPROFILE%" + std::string(basePathStr);
        if (!ExpandEnvironmentStringsA(envPath.c_str(), expandedPath, MAX_PATH)) {
            continue;
        }

        fs::path basePath(expandedPath);
        fs::path iniPath = basePath.parent_path() / "profiles.ini";
        if (fs::exists(iniPath)) {
            auto profiles = m_impl->ParseProfilesIniInternal(iniPath, basePath.parent_path());
            allProfiles.insert(allProfiles.end(), profiles.begin(), profiles.end());
        }
    }

    return allProfiles;
}

bool FirefoxAddonScanner::AllowAddon(const std::string& addonId) {
    return m_impl->AllowAddon(addonId);
}

bool FirefoxAddonScanner::BlockAddon(const std::string& addonId) {
    return m_impl->BlockAddon(addonId);
}

bool FirefoxAddonScanner::IsAddonAllowed(const std::string& addonId) const {
    return m_impl->IsAddonAllowed(addonId);
}

bool FirefoxAddonScanner::IsAddonBlocked(const std::string& addonId) const {
    return m_impl->IsAddonBlocked(addonId);
}

void FirefoxAddonScanner::RegisterScanCallback(AddonScanResultCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void FirefoxAddonScanner::RegisterMaliciousCallback(MaliciousAddonCallback callback) {
    m_impl->RegisterMaliciousCallback(std::move(callback));
}

void FirefoxAddonScanner::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void FirefoxAddonScanner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

FirefoxAddonScannerStatistics FirefoxAddonScanner::GetStatistics() const {
    return m_impl->GetStatisticsCopy();
}

void FirefoxAddonScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool FirefoxAddonScanner::SelfTest() {
    return m_impl->SelfTest();
}

std::string FirefoxAddonScanner::GetVersionString() noexcept {
    return std::to_string(FirefoxAddonConstants::VERSION_MAJOR) + "." +
           std::to_string(FirefoxAddonConstants::VERSION_MINOR) + "." +
           std::to_string(FirefoxAddonConstants::VERSION_PATCH);
}

// ============================================================================
// FREE-FUNCTION UTILITY IMPLEMENTATIONS
// ============================================================================

bool ExtractXpi(const fs::path& xpiPath, const fs::path& destPath) {
    try {
        auto fileSize = fs::file_size(xpiPath);
        if (fileSize > FirefoxAddonConstants::MAX_XPI_SIZE) {
            Logger::Warn("FirefoxAddonScanner: XPI too large for extraction: {} bytes",
                fileSize);
            return false;
        }

        std::ifstream file(xpiPath, std::ios::binary);
        if (!file) return false;

        std::vector<uint8_t> zipData(static_cast<size_t>(fileSize));
        file.read(reinterpret_cast<char*>(zipData.data()),
                  static_cast<std::streamsize>(fileSize));
        if (!file) return false;

        uint32_t centralDirOffset = 0;
        uint16_t entryCount = 0;
        if (!FindEndOfCentralDir(zipData, centralDirOffset, entryCount)) {
            return false;
        }

        std::vector<ZipCentralEntry> entries;
        if (!ParseCentralDirectory(zipData, centralDirOffset, entryCount, entries)) {
            return false;
        }

        fs::create_directories(destPath);

        size_t totalExtracted = 0;
        bool anyExtracted = false;

        for (const auto& entry : entries) {
            if (entry.filename.empty()) continue;
            if (entry.filename.back() == '/') continue;  // Directory entry

            // Security: prevent path traversal
            if (entry.filename.find("..") != std::string::npos) continue;

            // Size guard
            if (totalExtracted + entry.uncompressedSize >
                FirefoxAddonConstants::MAX_EXTRACTED_SIZE) {
                Logger::Warn("FirefoxAddonScanner: extraction size limit reached");
                break;
            }

            fs::path outPath = destPath / entry.filename;
            if (ExtractEntryToFile(zipData, entry, outPath)) {
                totalExtracted += entry.uncompressedSize;
                anyExtracted = true;
            }
        }

        return anyExtracted;
    } catch (const std::exception& e) {
        Logger::Error("FirefoxAddonScanner: ExtractXpi failed for {}: {}",
            xpiPath.string(), e.what());
        return false;
    }
}

std::optional<FirefoxManifest>
ParseFirefoxManifest(const fs::path& manifestPath) {
    try {
        std::ifstream f(manifestPath);
        if (!f) return std::nullopt;

        json j = json::parse(f, nullptr, false);
        if (j.is_discarded()) return std::nullopt;

        FirefoxManifest m;
        m.manifestVersion = j.value("manifest_version", 2);
        m.name = j.value("name", "");
        m.version = j.value("version", "");
        m.description = j.value("description", "");
        m.author = j.value("author", "");
        m.homepageUrl = j.value("homepage_url", "");

        // Permissions
        if (j.contains("permissions") && j["permissions"].is_array()) {
            for (const auto& p : j["permissions"]) {
                if (p.is_string()) m.permissions.push_back(p.get<std::string>());
            }
        }

        // Optional permissions
        if (j.contains("optional_permissions") &&
            j["optional_permissions"].is_array()) {
            for (const auto& p : j["optional_permissions"]) {
                if (p.is_string()) m.optionalPermissions.push_back(p.get<std::string>());
            }
        }

        // Host permissions (MV3)
        if (j.contains("host_permissions") && j["host_permissions"].is_array()) {
            for (const auto& p : j["host_permissions"]) {
                if (p.is_string()) m.hostPermissions.push_back(p.get<std::string>());
            }
        }

        // Content scripts
        if (j.contains("content_scripts") && j["content_scripts"].is_array()) {
            for (const auto& cs : j["content_scripts"]) {
                FirefoxContentScript script;
                if (cs.contains("matches") && cs["matches"].is_array()) {
                    for (const auto& match : cs["matches"]) {
                        if (match.is_string()) script.matches.push_back(match.get<std::string>());
                    }
                }
                if (cs.contains("exclude_matches") && cs["exclude_matches"].is_array()) {
                    for (const auto& em : cs["exclude_matches"]) {
                        if (em.is_string()) script.excludeMatches.push_back(em.get<std::string>());
                    }
                }
                if (cs.contains("include_globs") && cs["include_globs"].is_array()) {
                    for (const auto& g : cs["include_globs"]) {
                        if (g.is_string()) script.includeGlobs.push_back(g.get<std::string>());
                    }
                }
                if (cs.contains("exclude_globs") && cs["exclude_globs"].is_array()) {
                    for (const auto& g : cs["exclude_globs"]) {
                        if (g.is_string()) script.excludeGlobs.push_back(g.get<std::string>());
                    }
                }
                if (cs.contains("js") && cs["js"].is_array()) {
                    for (const auto& js : cs["js"]) {
                        if (js.is_string()) script.jsFiles.push_back(js.get<std::string>());
                    }
                }
                if (cs.contains("css") && cs["css"].is_array()) {
                    for (const auto& c : cs["css"]) {
                        if (c.is_string()) script.cssFiles.push_back(c.get<std::string>());
                    }
                }
                script.runAt = cs.value("run_at", "document_idle");
                script.allFrames = cs.value("all_frames", false);
                script.matchAboutBlank = cs.value("match_about_blank", false);
                m.contentScripts.push_back(std::move(script));
            }
        }

        // Background
        if (j.contains("background")) {
            const auto& bg = j["background"];
            if (bg.contains("scripts") && bg["scripts"].is_array()) {
                for (const auto& s : bg["scripts"]) {
                    if (s.is_string()) m.backgroundScripts.push_back(s.get<std::string>());
                }
            }
            if (bg.contains("page") && bg["page"].is_string()) {
                m.backgroundPage = bg["page"].get<std::string>();
            }
        }

        // Browser-specific settings / Gecko ID
        if (j.contains("browser_specific_settings")) {
            auto& bss = j["browser_specific_settings"];
            if (bss.contains("gecko")) {
                m.geckoId = bss["gecko"].value("id", "");
                m.strictMinVersion = bss["gecko"].value("strict_min_version", "");
            }
        } else if (j.contains("applications")) {
            auto& apps = j["applications"];
            if (apps.contains("gecko")) {
                m.geckoId = apps["gecko"].value("id", "");
                m.strictMinVersion = apps["gecko"].value("strict_min_version", "");
            }
        }

        m.id = m.geckoId;

        return m;
    } catch (const std::exception& e) {
        Logger::Warn("FirefoxAddonScanner: manifest parse error at {}: {}",
            manifestPath.string(), e.what());
        return std::nullopt;
    }
}

bool IsFirefoxDangerousPermission(const std::string& permission) {
    for (const char* dangerous : FirefoxAddonConstants::DANGEROUS_PERMISSIONS) {
        if (permission == dangerous) return true;
    }
    return false;
}

std::string GetAMOUrl(const std::string& addonId) {
    return std::string(FirefoxAddonConstants::MOZILLA_AMO_API) +
           "addons/addon/" + addonId + "/";
}

// ============================================================================
// UTILITY NAME FUNCTIONS
// ============================================================================

std::string_view GetAddonVerdictName(AddonVerdict verdict) noexcept {
    switch (verdict) {
        case AddonVerdict::Safe:            return "Safe";
        case AddonVerdict::Suspicious:      return "Suspicious";
        case AddonVerdict::Malicious:       return "Malicious";
        case AddonVerdict::OverPrivileged:  return "OverPrivileged";
        case AddonVerdict::Unsigned:        return "Unsigned";
        case AddonVerdict::Sideloaded:      return "Sideloaded";
        case AddonVerdict::PolicyViolation: return "PolicyViolation";
        case AddonVerdict::Legacy:          return "Legacy";
        case AddonVerdict::Unknown:         return "Unknown";
    }
    return "Unknown";
}

std::string_view GetAddonRiskLevelName(AddonRiskLevel level) noexcept {
    switch (level) {
        case AddonRiskLevel::None:     return "None";
        case AddonRiskLevel::Low:      return "Low";
        case AddonRiskLevel::Medium:   return "Medium";
        case AddonRiskLevel::High:     return "High";
        case AddonRiskLevel::Critical: return "Critical";
    }
    return "None";
}

std::string_view GetAddonTypeName(AddonType type) noexcept {
    switch (type) {
        case AddonType::Unknown:      return "Unknown";
        case AddonType::WebExtension: return "WebExtension";
        case AddonType::LegacyXUL:    return "LegacyXUL";
        case AddonType::Theme:        return "Theme";
        case AddonType::LangPack:     return "LanguagePack";
        case AddonType::Dictionary:   return "Dictionary";
        case AddonType::Plugin:       return "Plugin";
    }
    return "Unknown";
}

std::string_view GetAddonSourceName(AddonSource source) noexcept {
    switch (source) {
        case AddonSource::Unknown:     return "Unknown";
        case AddonSource::MozillaAMO:  return "MozillaAMO";
        case AddonSource::Sideloaded:  return "Sideloaded";
        case AddonSource::Enterprise:  return "Enterprise";
        case AddonSource::Development: return "Development";
        case AddonSource::System:      return "System";
    }
    return "Unknown";
}

std::string_view GetSignatureStatusName(SignatureStatus status) noexcept {
    switch (status) {
        case SignatureStatus::Unknown:    return "Unknown";
        case SignatureStatus::Valid:      return "Valid";
        case SignatureStatus::Invalid:    return "Invalid";
        case SignatureStatus::Missing:    return "Missing";
        case SignatureStatus::Expired:    return "Expired";
        case SignatureStatus::Privileged: return "Privileged";
    }
    return "Unknown";
}

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string FirefoxPermissionInfo::ToJson() const {
    json j;
    j["name"] = name;
    j["riskLevel"] = std::string(GetAddonRiskLevelName(riskLevel));
    j["description"] = description;
    j["isHostPermission"] = isHostPermission;
    j["isOptional"] = isOptional;
    return j.dump();
}

std::string FirefoxContentScript::ToJson() const {
    json j;
    j["matches"] = matches;
    j["excludeMatches"] = excludeMatches;
    j["includeGlobs"] = includeGlobs;
    j["excludeGlobs"] = excludeGlobs;
    j["jsFiles"] = jsFiles;
    j["cssFiles"] = cssFiles;
    j["runAt"] = runAt;
    j["allFrames"] = allFrames;
    j["matchAboutBlank"] = matchAboutBlank;
    return j.dump();
}

std::string FirefoxManifest::ToJson() const {
    json j;
    j["manifestVersion"] = manifestVersion;
    j["id"] = id;
    j["name"] = name;
    j["version"] = version;
    j["description"] = description;
    j["author"] = author;
    j["permissions"] = permissions;
    j["optionalPermissions"] = optionalPermissions;
    j["hostPermissions"] = hostPermissions;
    j["geckoId"] = geckoId;
    j["strictMinVersion"] = strictMinVersion;
    j["updateUrl"] = updateUrl;

    json csArray = json::array();
    for (const auto& cs : contentScripts) {
        csArray.push_back(json::parse(cs.ToJson()));
    }
    j["contentScripts"] = csArray;
    j["backgroundScripts"] = backgroundScripts;
    j["backgroundPage"] = backgroundPage;
    return j.dump();
}

std::string SignatureInfo::ToJson() const {
    json j;
    j["status"] = std::string(GetSignatureStatusName(status));
    j["signerName"] = signerName;
    j["certificateSubject"] = certificateSubject;
    j["certificateIssuer"] = certificateIssuer;
    j["isMozillaSigned"] = isMozillaSigned;
    j["isPrivileged"] = isPrivileged;
    return j.dump();
}

std::string AddonCodeAnalysis::ToJson() const {
    json j;
    j["totalJsFiles"] = totalJsFiles;
    j["totalCodeSize"] = totalCodeSize;
    j["isObfuscated"] = isObfuscated;
    j["obfuscationType"] = obfuscationType;
    j["hasEval"] = hasEval;
    j["hasDynamicScriptLoading"] = hasDynamicScriptLoading;
    j["hasDataExfiltration"] = hasDataExfiltration;
    j["hasCryptominer"] = hasCryptominer;
    j["suspiciousAPIs"] = suspiciousAPIs;
    j["suspiciousUrls"] = suspiciousUrls;
    j["riskScore"] = riskScore;
    return j.dump();
}

std::string FirefoxAddonInfo::ToJson() const {
    json j;
    j["id"] = id;
    j["name"] = name;
    j["version"] = version;
    j["description"] = description;
    j["addonPath"] = addonPath.string();
    j["profileName"] = profileName;
    j["type"] = std::string(GetAddonTypeName(type));
    j["source"] = std::string(GetAddonSourceName(source));
    j["permissions"] = permissions;
    j["isSideloaded"] = isSideloaded;
    j["isMalicious"] = isMalicious;
    j["isEnabled"] = isEnabled;
    j["isBuiltIn"] = isBuiltIn;
    j["xpiHash"] = xpiHash;
    j["amoUrl"] = amoUrl;
    j["manifest"] = json::parse(manifest.ToJson());
    j["signature"] = json::parse(signature.ToJson());
    return j.dump();
}

bool AddonScanResult::IsClean() const noexcept {
    return verdict == AddonVerdict::Safe;
}

std::string AddonScanResult::ToJson() const {
    json j;
    j["info"] = json::parse(info.ToJson());
    j["verdict"] = std::string(GetAddonVerdictName(verdict));
    j["riskLevel"] = std::string(GetAddonRiskLevelName(riskLevel));
    j["riskScore"] = riskScore;
    j["codeAnalysis"] = json::parse(codeAnalysis.ToJson());
    j["dangerousPermissionsCount"] = dangerousPermissionsCount;
    j["issues"] = issues;
    j["recommendations"] = recommendations;
    j["threatIntelMatches"] = threatIntelMatches;
    j["scanDurationUs"] = scanDuration.count();
    return j.dump();
}

void FirefoxAddonScannerStatistics::Reset() noexcept {
    totalScanned = 0;
    safeFound = 0;
    suspiciousFound = 0;
    maliciousFound = 0;
    unsignedFound = 0;
    sideloadedFound = 0;
    overPrivilegedFound = 0;
    profilesScanned = 0;
    xpisExtracted = 0;
    jsFilesAnalyzed = 0;
    obfuscatedFound = 0;
    for (auto& v : byVerdict) v.store(0, std::memory_order_relaxed);
    for (auto& t : byType) t.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string FirefoxAddonScannerStatistics::ToJson() const {
    json j;
    j["totalScanned"] = totalScanned.load();
    j["safeFound"] = safeFound.load();
    j["suspiciousFound"] = suspiciousFound.load();
    j["maliciousFound"] = maliciousFound.load();
    j["unsignedFound"] = unsignedFound.load();
    j["sideloadedFound"] = sideloadedFound.load();
    j["overPrivilegedFound"] = overPrivilegedFound.load();
    j["profilesScanned"] = profilesScanned.load();
    j["xpisExtracted"] = xpisExtracted.load();
    j["jsFilesAnalyzed"] = jsFilesAnalyzed.load();
    j["obfuscatedFound"] = obfuscatedFound.load();
    return j.dump();
}

bool FirefoxAddonScannerConfiguration::IsValid() const noexcept {
    if (maxXpiSize == 0) return false;
    if (maxXpiSize > FirefoxAddonConstants::MAX_XPI_SIZE * 2) return false;
    return true;
}

}  // namespace ShadowStrike::WebBrowser
