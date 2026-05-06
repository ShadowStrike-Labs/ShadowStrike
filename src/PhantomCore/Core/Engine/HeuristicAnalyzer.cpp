#include "pch.h"
#include "HeuristicAnalyzer.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/MemoryUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/ThreadPool.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../SignatureStore/SignatureFormat.hpp"
#include "../../ThreatIntel/ThreatIntelIndex.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../PEParser/PEParser.hpp"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <array>
#include <map>
#include <set>
#include <winnt.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// SECURITY HELPERS
// ============================================================================

namespace {
    /// @brief Safely convert signed integer to size_t with overflow check
    template<typename T>
    [[nodiscard]] std::optional<size_t> SafeToSizeT(T value) {
        if (value < 0) return std::nullopt;
        if (static_cast<uintmax_t>(value) > std::numeric_limits<size_t>::max()) {
            return std::nullopt;
        }
        return static_cast<size_t>(value);
    }
    
    /// @brief Safely check if offset + size is within bounds
    [[nodiscard]] bool IsValidRange(size_t dataSize, size_t offset, size_t size) {
        if (offset > dataSize) return false;
        if (size > dataSize - offset) return false;  // Prevents overflow
        return true;
    }

    // ========================================================================
    // PEParser → HeuristicAnalyzer Anomaly Mapping
    // ========================================================================

    /// @brief Map PEParser::AnomalyType to HeuristicAnalyzer::PEAnomaly.
    /// Returns PEAnomaly::None for anomaly types that have no direct equivalent.
    [[nodiscard]] PEAnomaly MapPEParserAnomaly(
        ShadowStrike::PEParser::AnomalyType type) noexcept
    {
        using AT = ShadowStrike::PEParser::AnomalyType;
        switch (type) {
            case AT::TimestampInFuture:           return PEAnomaly::FutureTimestamp;
            case AT::TimestampZero:               return PEAnomaly::ZeroedTimestamp;
            case AT::ChecksumMismatch:            return PEAnomaly::ChecksumMismatch;
            case AT::SectionNameEmpty:             return PEAnomaly::EmptySectionName;
            case AT::SectionNameNonPrintable:      return PEAnomaly::NonASCIISectionName;
            case AT::SectionNameSuspicious:        return PEAnomaly::SuspiciousSectionName;
            case AT::SectionWritableExecutable:    return PEAnomaly::RWXSection;
            case AT::SectionZeroRawSize:           return PEAnomaly::ZeroRawSize;
            case AT::SectionHighEntropy:           return PEAnomaly::HighEntropyResource;
            case AT::TooManySections:              return PEAnomaly::TooManySections;
            case AT::EntryPointInHeader:           return PEAnomaly::EntryPointInHeader;
            case AT::EntryPointZero:               return PEAnomaly::InvalidEntryPoint;
            case AT::EntryPointOutsideFile:        return PEAnomaly::EntryPointOutsideSections;
            case AT::NoImports:                    return PEAnomaly::NoImports;
            case AT::OverlayPresent:               return PEAnomaly::HasOverlay;
            case AT::OverlayHighEntropy:           return PEAnomaly::LargeOverlay;
            case AT::NoASLR:                       return PEAnomaly::None; // scored separately
            case AT::NoDEP:                        return PEAnomaly::None;
            case AT::NoSEH:                        return PEAnomaly::None;
            case AT::NoCFG:                        return PEAnomaly::None;
            case AT::ResourcesContainPE:           return PEAnomaly::PEInResources;
            case AT::ResourcesHighEntropy:         return PEAnomaly::HighEntropyResource;
            default:                               return PEAnomaly::None;
        }
    }

    /// @brief Transfer relevant PEParser anomalies into PEAnalysis, deduplicating.
    void TransferPEParserAnomalies(
        const std::vector<ShadowStrike::PEParser::Anomaly>& ppAnomalies,
        PEAnalysis& pe)
    {
        for (const auto& a : ppAnomalies) {
            auto mapped = MapPEParserAnomaly(a.type);
            if (mapped == PEAnomaly::None) continue;
            // Avoid duplicates
            if (std::find(pe.anomalies.begin(), pe.anomalies.end(), mapped)
                == pe.anomalies.end()) {
                pe.anomalies.push_back(mapped);
            }
        }
    }
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct HeuristicAnalyzer::Impl {
    mutable std::shared_mutex m_mutex;

    HeuristicAnalyzerConfig m_config;
    std::shared_ptr<Utils::ThreadPool> m_threadPool;

    // External stores (non-owning, set via Set*() methods)
    HashStore::HashStore* m_hashStore = nullptr;
    SignatureStore::SignatureStore* m_signatureStore = nullptr;
    PatternStore::PatternStore* m_patternStore = nullptr;
    ThreatIntel::ThreatIntelIndex* m_threatIntel = nullptr;

    HeuristicAnalyzerStats m_statistics;

    // Packer signatures (section-name to PackerType)
    std::unordered_map<std::string, PackerType> m_packerSignatures;

    // Suspicious import function names
    std::unordered_set<std::string> m_knownSuspiciousImports;

    // Import function -> category mapping
    std::unordered_map<std::string, SuspiciousAPICategory> m_importCategoryMap;

    std::atomic<bool> m_initialized{false};

    Impl() {
        InitializePackerSignatures();
        InitializeSuspiciousImports();
    }

    void InitializePackerSignatures() {
        m_packerSignatures["UPX0"]      = PackerType::UPX;
        m_packerSignatures["UPX1"]      = PackerType::UPX;
        m_packerSignatures["UPX2"]      = PackerType::UPX;
        m_packerSignatures["UPX!"]      = PackerType::UPX;
        m_packerSignatures[".aspack"]   = PackerType::ASPack;
        m_packerSignatures[".adata"]    = PackerType::ASPack;
        m_packerSignatures[".ASPack"]   = PackerType::ASPack;
        m_packerSignatures[".FSG"]      = PackerType::FSG;
        m_packerSignatures["PEC2"]      = PackerType::PECompact;
        m_packerSignatures["PECompact"] = PackerType::PECompact;
        m_packerSignatures["pec1"]      = PackerType::PECompact;
        m_packerSignatures["pec2"]      = PackerType::PECompact;
        m_packerSignatures[".armadill"] = PackerType::Armadillo;
        m_packerSignatures[".themida"]  = PackerType::Themida;
        m_packerSignatures["MPRESS"]    = PackerType::MPRESS;
        m_packerSignatures[".MPRESS1"]  = PackerType::MPRESS;
        m_packerSignatures[".MPRESS2"]  = PackerType::MPRESS;
        m_packerSignatures[".petite"]   = PackerType::Petite;
        m_packerSignatures[".vmp0"]     = PackerType::VMProtect;
        m_packerSignatures[".vmp1"]     = PackerType::VMProtect;
        m_packerSignatures[".vmp2"]     = PackerType::VMProtect;
        m_packerSignatures[".enigma"]   = PackerType::Enigma;
        m_packerSignatures[".enigma1"]  = PackerType::Enigma;
        m_packerSignatures[".enigma2"]  = PackerType::Enigma;
        m_packerSignatures["MEW"]       = PackerType::MEW;
        m_packerSignatures[".nsp0"]     = PackerType::NsPack;
        m_packerSignatures[".nsp1"]     = PackerType::NsPack;
        m_packerSignatures["nsp0"]      = PackerType::NsPack;
        m_packerSignatures["RLPack"]    = PackerType::RLPack;
        m_packerSignatures[".RLPack"]   = PackerType::RLPack;
        m_packerSignatures[".Upack"]    = PackerType::WinUpack;
        m_packerSignatures[".nsis"]     = PackerType::NSIS;
        m_packerSignatures["nsis"]      = PackerType::NSIS;
        m_packerSignatures[".idata"]    = PackerType::InnoSetup;
    }

    void InitializeSuspiciousImports() {
        auto add = [&](const char* name, SuspiciousAPICategory cat) {
            m_knownSuspiciousImports.insert(name);
            m_importCategoryMap[name] = cat;
        };

        // Process manipulation
        add("CreateRemoteThread",        SuspiciousAPICategory::ProcessManipulation);
        add("CreateRemoteThreadEx",      SuspiciousAPICategory::ProcessManipulation);
        add("WriteProcessMemory",        SuspiciousAPICategory::ProcessManipulation);
        add("ReadProcessMemory",         SuspiciousAPICategory::ProcessManipulation);
        add("VirtualAllocEx",            SuspiciousAPICategory::MemoryOperations);
        add("VirtualProtectEx",          SuspiciousAPICategory::MemoryOperations);
        add("SetThreadContext",          SuspiciousAPICategory::ProcessManipulation);
        add("QueueUserAPC",             SuspiciousAPICategory::CodeInjection);
        add("NtQueueApcThread",         SuspiciousAPICategory::CodeInjection);
        add("NtCreateThreadEx",         SuspiciousAPICategory::CodeInjection);
        add("RtlCreateUserThread",      SuspiciousAPICategory::CodeInjection);

        // Code injection / dynamic loading
        add("LoadLibraryA",             SuspiciousAPICategory::DynamicCode);
        add("LoadLibraryW",             SuspiciousAPICategory::DynamicCode);
        add("LoadLibraryExA",           SuspiciousAPICategory::DynamicCode);
        add("LoadLibraryExW",           SuspiciousAPICategory::DynamicCode);
        add("GetProcAddress",           SuspiciousAPICategory::DynamicCode);
        add("VirtualProtect",           SuspiciousAPICategory::MemoryOperations);
        add("VirtualAlloc",             SuspiciousAPICategory::MemoryOperations);

        // Anti-debug
        add("IsDebuggerPresent",        SuspiciousAPICategory::AntiDebug);
        add("CheckRemoteDebuggerPresent", SuspiciousAPICategory::AntiDebug);
        add("NtQueryInformationProcess", SuspiciousAPICategory::AntiDebug);
        add("OutputDebugStringA",       SuspiciousAPICategory::AntiDebug);

        // Persistence
        add("RegSetValueExA",           SuspiciousAPICategory::RegistryOperations);
        add("RegSetValueExW",           SuspiciousAPICategory::RegistryOperations);
        add("RegCreateKeyExA",          SuspiciousAPICategory::RegistryOperations);
        add("RegCreateKeyExW",          SuspiciousAPICategory::RegistryOperations);
        add("CreateServiceA",           SuspiciousAPICategory::ServiceOperations);
        add("CreateServiceW",           SuspiciousAPICategory::ServiceOperations);
        add("ChangeServiceConfigA",     SuspiciousAPICategory::ServiceOperations);
        add("ChangeServiceConfigW",     SuspiciousAPICategory::ServiceOperations);

        // Keylogging
        add("SetWindowsHookExA",        SuspiciousAPICategory::InputCapture);
        add("SetWindowsHookExW",        SuspiciousAPICategory::InputCapture);
        add("GetAsyncKeyState",         SuspiciousAPICategory::InputCapture);
        add("GetKeyState",             SuspiciousAPICategory::InputCapture);

        // Network
        add("InternetOpenA",            SuspiciousAPICategory::NetworkOperations);
        add("InternetOpenW",            SuspiciousAPICategory::NetworkOperations);
        add("InternetConnectA",         SuspiciousAPICategory::NetworkOperations);
        add("InternetConnectW",         SuspiciousAPICategory::NetworkOperations);
        add("HttpSendRequestA",         SuspiciousAPICategory::NetworkOperations);
        add("HttpSendRequestW",         SuspiciousAPICategory::NetworkOperations);
        add("URLDownloadToFileA",       SuspiciousAPICategory::NetworkOperations);
        add("URLDownloadToFileW",       SuspiciousAPICategory::NetworkOperations);

        // Crypto
        add("CryptEncrypt",            SuspiciousAPICategory::CryptoOperations);
        add("CryptDecrypt",            SuspiciousAPICategory::CryptoOperations);
        add("CryptDeriveKey",          SuspiciousAPICategory::CryptoOperations);
        add("CryptGenKey",             SuspiciousAPICategory::CryptoOperations);

        // Privilege escalation
        add("AdjustTokenPrivileges",    SuspiciousAPICategory::PrivilegeEscalation);
        add("OpenProcessToken",         SuspiciousAPICategory::PrivilegeEscalation);
        add("ImpersonateLoggedOnUser",  SuspiciousAPICategory::PrivilegeEscalation);

        // Screen capture
        add("BitBlt",                   SuspiciousAPICategory::ScreenCapture);
        add("GetDC",                    SuspiciousAPICategory::ScreenCapture);

        // Credential access
        add("CredReadA",               SuspiciousAPICategory::CredentialAccess);
        add("CredReadW",               SuspiciousAPICategory::CredentialAccess);

        // Shell
        add("ShellExecuteA",           SuspiciousAPICategory::Shell);
        add("ShellExecuteW",           SuspiciousAPICategory::Shell);
        add("ShellExecuteExA",         SuspiciousAPICategory::Shell);
        add("ShellExecuteExW",         SuspiciousAPICategory::Shell);

        // WMI
        add("CoCreateInstance",         SuspiciousAPICategory::COM);
    }
};

// Forward declaration for internal string analysis helper
static void AnalyzeExtractedStringImpl(
    const std::string& str, uint64_t offset, StringAnalysis& result);

// ============================================================================
// Singleton
// ============================================================================

HeuristicAnalyzer& HeuristicAnalyzer::Instance() {
    static HeuristicAnalyzer instance;
    return instance;
}

// ============================================================================
// Lifecycle
// ============================================================================

HeuristicAnalyzer::HeuristicAnalyzer()
    : m_impl(std::make_unique<Impl>())
{
    SS_LOG_INFO(L"HeuristicAnalyzer", L"Constructor called");
}

HeuristicAnalyzer::~HeuristicAnalyzer() {
    Shutdown();
}

bool HeuristicAnalyzer::Initialize() {
    return Initialize(nullptr, HeuristicAnalyzerConfig::CreateDefault());
}

bool HeuristicAnalyzer::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return Initialize(std::move(threadPool), HeuristicAnalyzerConfig::CreateDefault());
}

bool HeuristicAnalyzer::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool,
    const HeuristicAnalyzerConfig& config)
{
    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"HeuristicAnalyzer", L"Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;
        m_impl->m_threadPool = std::move(threadPool);

        if (!config.enabled) {
            SS_LOG_INFO(L"HeuristicAnalyzer", L"Disabled via configuration");
            return false;
        }

        m_impl->m_statistics.Reset();
        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"HeuristicAnalyzer", L"Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"HeuristicAnalyzer", L"Initialization failed: %ls",
                     Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void HeuristicAnalyzer::Shutdown() {
    std::unique_lock lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_impl->m_hashStore = nullptr;
        m_impl->m_signatureStore = nullptr;
        m_impl->m_patternStore = nullptr;
        m_impl->m_threatIntel = nullptr;
        m_impl->m_threadPool.reset();

        m_impl->m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"HeuristicAnalyzer", L"Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"HeuristicAnalyzer", L"Shutdown error: %ls",
                     Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

bool HeuristicAnalyzer::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

void HeuristicAnalyzer::UpdateConfig(const HeuristicAnalyzerConfig& config) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
}

HeuristicAnalyzerConfig HeuristicAnalyzer::GetConfig() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}
// ============================================================================
// Primary Analysis API
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzeFile(const std::wstring& filePath) {
    const auto startTime = std::chrono::steady_clock::now();
    m_impl->m_statistics.totalFilesAnalyzed.fetch_add(1, std::memory_order_relaxed);

    HeuristicResult result;
    result.filePath = filePath;
    result.timestamp = std::chrono::system_clock::now();

    // Snapshot config and external store pointers under a brief shared lock,
    // then release before invoking sub-analyses.  This avoids the previously
    // pervasive recursive std::shared_mutex acquisition (UB on MSVC's STL).
    HeuristicAnalyzerConfig cfg;
    HashStore::HashStore* hashStore = nullptr;
    {
        std::shared_lock lock(m_impl->m_mutex);
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            result.errorMessage = "HeuristicAnalyzer not initialized";
            SS_LOG_WARN(L"HeuristicAnalyzer", L"AnalyzeFile called before initialization");
            return result;
        }
        cfg = m_impl->m_config;
        hashStore = m_impl->m_hashStore;
    }

    if (filePath.empty()) {
        result.errorMessage = "Empty file path";
        return result;
    }

    try {
        // Read entire file (FileUtils caps at MAX_READ_FILE_SIZE internally)
        std::vector<std::byte> rawData;
        if (!Utils::FileUtils::ReadAllBytes(filePath, rawData)) {
            result.errorMessage = "Failed to read file";
            m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"HeuristicAnalyzer", L"Failed to read file: %ls", filePath.c_str());
            return result;
        }

        if (rawData.empty()) {
            result.errorMessage = "File is empty";
            return result;
        }

        if (rawData.size() > cfg.maxFileSize) {
            result.errorMessage = "File exceeds maximum analysis size";
            m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"HeuristicAnalyzer", L"File too large for analysis: %ls (%zu bytes)",
                       filePath.c_str(), rawData.size());
            return result;
        }

        result.fileSize = rawData.size();

        std::span<const uint8_t> data(
            reinterpret_cast<const uint8_t*>(rawData.data()), rawData.size());

        return AnalyzeBufferInternal(filePath, data, cfg, hashStore, startTime);

    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR(L"HeuristicAnalyzer", L"AnalyzeFile exception: %ls",
                     Utils::StringUtils::ToWide(e.what()).c_str());
        return result;
    }
}

HeuristicResult HeuristicAnalyzer::AnalyzeBuffer(
    std::span<const uint8_t> data,
    const std::wstring& fileName)
{
    return AnalyzeFile(fileName, data);
}

HeuristicResult HeuristicAnalyzer::AnalyzeFile(
    const std::wstring& filePath,
    std::span<const uint8_t> data)
{
    const auto startTime = std::chrono::steady_clock::now();

    HeuristicResult result;
    result.filePath = filePath;
    result.fileSize = data.size();
    result.timestamp = std::chrono::system_clock::now();

    HeuristicAnalyzerConfig cfg;
    HashStore::HashStore* hashStore = nullptr;
    {
        std::shared_lock lock(m_impl->m_mutex);
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            result.errorMessage = "HeuristicAnalyzer not initialized";
            return result;
        }
        cfg = m_impl->m_config;
        hashStore = m_impl->m_hashStore;
    }

    return AnalyzeBufferInternal(filePath, data, cfg, hashStore, startTime);
}

HeuristicResult HeuristicAnalyzer::AnalyzeBufferInternal(
    const std::wstring& filePath,
    std::span<const uint8_t> data,
    const HeuristicAnalyzerConfig& cfg,
    HashStore::HashStore* hashStore,
    std::chrono::steady_clock::time_point startTime)
{
    HeuristicResult result;
    result.filePath = filePath;
    result.fileSize = data.size();
    result.timestamp = std::chrono::system_clock::now();

    try {
        if (data.empty()) {
            result.errorMessage = "Empty buffer";
            return result;
        }

        if (data.size() > cfg.maxFileSize) {
            result.errorMessage = "Buffer exceeds maximum analysis size";
            return result;
        }

        // Compute file hashes
        {
            std::string tmp;
            Utils::HashUtils::Hasher sha256Hasher(Utils::HashUtils::Algorithm::SHA256);
            if (sha256Hasher.Init() && sha256Hasher.Update(data.data(), data.size())) {
                if (sha256Hasher.FinalHex(tmp, false)) {
                    result.sha256 = std::move(tmp);
                }
            }
            tmp.clear();
            Utils::HashUtils::Hasher sha1Hasher(Utils::HashUtils::Algorithm::SHA1);
            if (sha1Hasher.Init() && sha1Hasher.Update(data.data(), data.size())) {
                if (sha1Hasher.FinalHex(tmp, false)) {
                    result.sha1 = std::move(tmp);
                }
            }
            tmp.clear();
            Utils::HashUtils::Hasher md5Hasher(Utils::HashUtils::Algorithm::MD5);
            if (md5Hasher.Init() && md5Hasher.Update(data.data(), data.size())) {
                if (md5Hasher.FinalHex(tmp, false)) {
                    result.md5 = std::move(tmp);
                }
            }
        }

        result.fileType = DetectFileType(data);
        if (result.fileType == FileType::Unknown && !filePath.empty()) {
            result.fileType = DetectFileType(filePath);
        }

        auto typeIdx = static_cast<size_t>(result.fileType);
        if (typeIdx < m_impl->m_statistics.filesByType.size()) {
            m_impl->m_statistics.filesByType[typeIdx].fetch_add(1, std::memory_order_relaxed);
        }

        switch (result.fileType) {
            case FileType::PE32:
            case FileType::PE64:
            case FileType::DLL:
            case FileType::SYS:
            {
                if (cfg.enablePEAnalysis) {
                    auto pe = AnalyzePE(data);
                    result.peAnalysis = pe;

                    double peScore = pe.riskScore;

                    if (cfg.enablePackerDetection) {
                        result.packerDetection = DetectPacker(data);
                        if (result.packerDetection.isPacked) {
                            m_impl->m_statistics.packedFiles.fetch_add(1, std::memory_order_relaxed);
                            peScore += result.packerDetection.riskScore;
                        }
                    }

                    if (cfg.enableImportAnalysis) {
                        auto imports = AnalyzeImports(data);
                        result.peAnalysis->imports = imports;
                        peScore += imports.riskScore;
                    }

                    if (cfg.enableStringAnalysis) {
                        result.stringAnalysis = AnalyzeStrings(data);
                        peScore += result.stringAnalysis.riskScore;
                    }

                    if (cfg.enableCertificateAnalysis && !filePath.empty()) {
                        result.peAnalysis->certificate = VerifySignature(filePath);
                        peScore += result.peAnalysis->certificate.riskScore;
                    }

                    result.riskScore = std::min(peScore, HeuristicConstants::MAX_RISK_SCORE);
                }
                break;
            }

            case FileType::Script:
            {
                if (cfg.enableScriptAnalysis) {
                    auto script = AnalyzeScript(data);
                    result.scriptAnalysis = script;
                    result.riskScore = std::min(script.riskScore, HeuristicConstants::MAX_RISK_SCORE);
                }
                break;
            }

            default:
            {
                double score = 0.0;
                double entropy = CalculateEntropy(data);
                if (entropy > cfg.highEntropyThreshold) {
                    score += entropy * HeuristicConstants::ENTROPY_WEIGHT;
                }
                if (cfg.enableStringAnalysis) {
                    result.stringAnalysis = AnalyzeStrings(data);
                    score += result.stringAnalysis.riskScore;
                }
                result.riskScore = std::min(score, HeuristicConstants::MAX_RISK_SCORE);
                break;
            }
        }

        // Fuzzy matching: only invoke when a real CTPH/TLSH fuzzy hash is
        // available. SHA-256 cannot be fuzzy-matched — feeding it into
        // HashStore::FuzzyMatch is semantically meaningless and was a
        // pre-existing bug. Until ssdeep/TLSH hashes are computed
        // (CalculateFuzzyHash / CalculateTLSH currently return empty),
        // this branch is intentionally skipped.
        if (cfg.enableFuzzyMatching && hashStore && !result.sha256.empty()) {
            std::string fuzzyHash = CalculateFuzzyHash(data);
            std::string tlsh = CalculateTLSH(data);
            if (!fuzzyHash.empty() || !tlsh.empty()) {
                result.fuzzyMatch = QueryFuzzyMatch(fuzzyHash, tlsh, "");
                if (result.fuzzyMatch.hasMatch) {
                    m_impl->m_statistics.fuzzyMatches.fetch_add(1, std::memory_order_relaxed);
                    result.riskScore = std::min(
                        result.riskScore + result.fuzzyMatch.riskScore,
                        HeuristicConstants::MAX_RISK_SCORE);
                }
            }
        }

        AggregateScores(result);
        GenerateThreatName(result);

        result.analysisComplete = true;

        const auto endTime = std::chrono::steady_clock::now();
        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        m_impl->m_statistics.totalBytesAnalyzed.fetch_add(data.size(), std::memory_order_relaxed);

        if (result.isMalicious) {
            m_impl->m_statistics.maliciousFiles.fetch_add(1, std::memory_order_relaxed);
        } else if (result.isSuspicious) {
            m_impl->m_statistics.suspiciousFiles.fetch_add(1, std::memory_order_relaxed);
        } else {
            m_impl->m_statistics.cleanFiles.fetch_add(1, std::memory_order_relaxed);
        }

        // Update running average analysis time using the canonical
        //   newAvg = (prevAvg * (n-1) + sample) / n
        // formulation. The prior expression underflowed when sample < prevAvg
        // because uint64_t(sample) - prevAvg wraps around.
        const auto us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count());
        const auto totalFiles = m_impl->m_statistics.totalFilesAnalyzed.load(std::memory_order_relaxed);
        if (totalFiles > 0) {
            const auto prevAvg = m_impl->m_statistics.avgAnalysisTimeUs.load(std::memory_order_relaxed);
            const auto newAvg = (prevAvg * (totalFiles - 1) + us) / totalFiles;
            m_impl->m_statistics.avgAnalysisTimeUs.store(newAvg, std::memory_order_relaxed);
        }

        SS_LOG_INFO(L"HeuristicAnalyzer", L"Analysis complete: %ls (risk=%.1f, time=%lldms)",
                   filePath.c_str(), result.riskScore,
                   static_cast<long long>(result.analysisDuration.count()));

        return result;

    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR(L"HeuristicAnalyzer", L"Analysis failed for %ls: %ls",
                     filePath.c_str(), Utils::StringUtils::ToWide(e.what()).c_str());
        return result;
    }
}

bool HeuristicAnalyzer::AnalyzeFileAsync(
    const std::wstring& filePath,
    HeuristicResultCallback callback)
{
    if (!callback || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (m_impl->m_threadPool) {
        (void)m_impl->m_threadPool->Submit([this, filePath, callback](const Utils::TaskContext&) {
            try {
                auto result = AnalyzeFile(filePath);
                callback(result);
            } catch (const std::exception& e) {
                HeuristicResult errorResult;
                errorResult.filePath = filePath;
                errorResult.analysisComplete = false;
                errorResult.errorMessage = e.what();
                errorResult.analysisDuration = std::chrono::milliseconds::zero();
                callback(errorResult);
            }
        }, Utils::TaskPriority::Normal, "HeuristicAnalyzer::AnalyzeFileAsync");
        return true;
    }

    auto result = AnalyzeFile(filePath);
    callback(result);
    return true;
}

HeuristicResult HeuristicAnalyzer::QuickScan(const std::wstring& filePath) {
    const auto startTime = std::chrono::steady_clock::now();
    m_impl->m_statistics.totalFilesAnalyzed.fetch_add(1, std::memory_order_relaxed);

    HeuristicResult result;
    result.filePath = filePath;
    result.timestamp = std::chrono::system_clock::now();

    // Snapshot global config + stores under a brief shared lock; mutate the
    // local copy only.  The previous implementation mutated m_impl->m_config
    // in-place without any synchronization, racing with concurrent analyses
    // and concurrent UpdateConfig calls.
    HeuristicAnalyzerConfig cfg;
    HashStore::HashStore* hashStore = nullptr;
    {
        std::shared_lock lock(m_impl->m_mutex);
        if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
            result.errorMessage = "HeuristicAnalyzer not initialized";
            return result;
        }
        cfg = m_impl->m_config;
        hashStore = m_impl->m_hashStore;
    }

    cfg.enableCodeAnalysis = false;
    cfg.enableStringAnalysis = false;
    cfg.enableResourceAnalysis = false;
    cfg.enableFuzzyMatching = false;
    cfg.timeoutSeconds = 10;

    if (filePath.empty()) {
        result.errorMessage = "Empty file path";
        return result;
    }

    try {
        std::vector<std::byte> rawData;
        if (!Utils::FileUtils::ReadAllBytes(filePath, rawData)) {
            result.errorMessage = "Failed to read file";
            m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
        if (rawData.empty()) {
            result.errorMessage = "File is empty";
            return result;
        }
        if (rawData.size() > cfg.maxFileSize) {
            result.errorMessage = "File exceeds maximum analysis size";
            m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
            return result;
        }
        std::span<const uint8_t> data(
            reinterpret_cast<const uint8_t*>(rawData.data()), rawData.size());
        return AnalyzeBufferInternal(filePath, data, cfg, hashStore, startTime);
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
        m_impl->m_statistics.analysisFailures.fetch_add(1, std::memory_order_relaxed);
        return result;
    }
}
// ============================================================================
// PE Analysis
// ============================================================================

PEAnalysis HeuristicAnalyzer::AnalyzePE(std::span<const uint8_t> data) {
    PEAnalysis pe;

    // =========================================================================
    // DELEGATE PE PARSING TO PEParser MODULE
    // =========================================================================
    // PEParser provides enterprise-grade bounds checking, overflow protection,
    // and comprehensive PE structure parsing. We delegate raw header parsing
    // to it and adapt the output to our internal PEAnalysis model.
    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;
    PEParser::PEError parseErr;

    if (!parser.ParseBuffer(data, peInfo, &parseErr)) {
        // PEParser failed basic parsing — transfer any anomalies it caught
        TransferPEParserAnomalies(peInfo.anomalies, pe);
        SS_LOG_DEBUG(L"HeuristicAnalyzer", L"PEParser rejected buffer: %s",
                     parseErr.message.c_str());
        return pe;
    }

    pe.isValidPE = true;

    // --- Map core header fields from PEInfo ---
    PopulateFromPEInfo(parser, peInfo, pe);

    // --- Map sections from PEParser (plus HA-specific entropy/hash analysis) ---
    PopulateSections(parser, peInfo, data, pe);

    // Suspicious import scanning is invoked at the top-level analysis
    // pipeline (AnalyzeBufferInternal) when import analysis is enabled.
    // We deliberately do NOT call ParseImports here to avoid scanning the
    // entire buffer twice for every PE file.

    // --- Export anomaly detection ---
    if (pe.isDLL && !peInfo.dataDirectories[PEParser::DataDirectory::EXPORT].present) {
        pe.anomalies.push_back(PEAnomaly::NoExportsForDLL);
    }

    if (m_impl->m_config.enableResourceAnalysis) {
        ParseResources(data, pe);
    }

    // --- Rich header via PEParser ---
    PopulateRichHeader(parser, pe);

    // --- Heuristic-specific PE anomaly detection ---
    DetectHeuristicAnomalies(peInfo, pe);

    // --- Transfer any remaining PEParser anomalies ---
    TransferPEParserAnomalies(peInfo.anomalies, pe);

    if (m_impl->m_config.enableCodeAnalysis) {
        for (const auto& sec : pe.sections) {
            if (sec.isCode && sec.rawSize > 0 &&
                sec.rawOffset + sec.rawSize <= data.size())
            {
                auto codeSpan = data.subspan(
                    static_cast<size_t>(sec.rawOffset),
                    static_cast<size_t>(sec.rawSize));
                CodeAnalysis code;
                AnalyzeCode(codeSpan, code);
                pe.riskScore += code.riskScore;
            }
        }
    }

    // Compute overall entropy
    pe.overallEntropy = CalculateEntropy(data);

    // Compute per-section entropy and risk from section characteristics
    for (auto& sec : pe.sections) {
        if (sec.rawSize > 0 && sec.rawOffset + sec.rawSize <= data.size()) {
            auto secData = data.subspan(
                static_cast<size_t>(sec.rawOffset),
                static_cast<size_t>(sec.rawSize));
            sec.entropy = CalculateEntropy(secData);
            sec.chiSquare = CalculateChiSquare(secData);
            sec.hasHighEntropy = (sec.entropy > HeuristicConstants::HIGH_ENTROPY_THRESHOLD);
        }

        if (sec.IsRWX()) {
            pe.anomalies.push_back(PEAnomaly::RWXSection);
            pe.riskScore += 15.0;
        }
    }

    // Entry point checks
    if (pe.entryPoint == 0 && !pe.isDLL) {
        pe.anomalies.push_back(PEAnomaly::InvalidEntryPoint);
        pe.riskScore += 10.0;
    }

    // Security mitigations missing
    if (!pe.hasASLR) pe.riskScore += 3.0;
    if (!pe.hasDEP)  pe.riskScore += 3.0;
    if (!pe.hasCFG)  pe.riskScore += 2.0;

    pe.riskScore = std::min(pe.riskScore, HeuristicConstants::MAX_PE_ANOMALY_SCORE * HeuristicConstants::PE_ANOMALY_WEIGHT);

    return pe;
}

// ============================================================================
// PEParser Delegation: Header Fields Adapter
// ============================================================================

void HeuristicAnalyzer::PopulateFromPEInfo(
    const PEParser::PEParser& /*parser*/,
    const PEParser::PEInfo& peInfo,
    PEAnalysis& pe)
{
    pe.is64Bit           = peInfo.is64Bit;
    pe.isDLL             = peInfo.isDLL;
    pe.isDriver          = peInfo.isDriver;
    pe.isDotNet          = peInfo.isDotNet;
    pe.machine           = peInfo.machine;
    pe.subsystem         = static_cast<PESubsystem>(peInfo.subsystem);
    pe.numberOfSections  = static_cast<uint16_t>(peInfo.sections.size());
    pe.timestamp         = peInfo.timeDateStamp;
    pe.entryPoint        = peInfo.entryPointRva;
    pe.imageBase         = peInfo.imageBase;
    pe.sectionAlignment  = peInfo.sectionAlignment;
    pe.fileAlignment     = peInfo.fileAlignment;
    pe.sizeOfImage       = peInfo.sizeOfImage;
    pe.sizeOfHeaders     = peInfo.sizeOfHeaders;
    pe.checksum          = peInfo.checksum;
    pe.dllCharacteristics = peInfo.dllCharacteristics;

    // Security mitigation flags derived from DLL characteristics
    pe.hasASLR          = (pe.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    pe.hasDEP           = (pe.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
    pe.hasCFG           = (pe.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    pe.hasHighEntropyVA = (pe.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    pe.hasSEH           = !(pe.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH);

    // Timestamp analysis (kept from original — heuristic-specific checks)
    if (pe.timestamp != 0) {
        pe.timestampDate = std::chrono::system_clock::from_time_t(
            static_cast<time_t>(pe.timestamp));
        auto now = static_cast<uint32_t>(std::time(nullptr));
        if (pe.timestamp > now) {
            pe.anomalies.push_back(PEAnomaly::FutureTimestamp);
        }
    } else {
        pe.anomalies.push_back(PEAnomaly::ZeroedTimestamp);
    }

    // Section count heuristic checks
    if (pe.numberOfSections == 0) {
        pe.anomalies.push_back(PEAnomaly::ZeroSections);
    } else if (pe.numberOfSections > HeuristicConstants::MAX_NORMAL_SECTIONS) {
        pe.anomalies.push_back(PEAnomaly::TooManySections);
    }

    // Overlay detection from PEParser
    if (peInfo.overlayOffset > 0 && peInfo.overlaySize > 0) {
        pe.hasOverlay    = true;
        pe.overlayOffset = peInfo.overlayOffset;
        pe.overlaySize   = peInfo.overlaySize;
    }

    // Entry point section from PEParser
    if (peInfo.entryPointSectionIndex.has_value()) {
        auto idx = *peInfo.entryPointSectionIndex;
        if (idx < peInfo.sections.size()) {
            pe.entryPointSection = peInfo.sections[idx].name;
        }
    }
}

// ============================================================================
// PEParser Delegation: Section Adapter
// ============================================================================

void HeuristicAnalyzer::PopulateSections(
    const PEParser::PEParser& /*parser*/,
    const PEParser::PEInfo& peInfo,
    std::span<const uint8_t> data,
    PEAnalysis& pe)
{
    pe.sections.reserve(peInfo.sections.size());

    for (uint16_t i = 0; i < peInfo.sections.size(); ++i) {
        const auto& ppSec = peInfo.sections[i];
        SectionAnalysis sec;
        sec.index              = i;
        sec.name               = ppSec.name;
        sec.virtualAddress     = ppSec.virtualAddress;
        sec.virtualSize        = ppSec.virtualSize;
        sec.rawOffset          = ppSec.rawAddress;
        sec.rawSize            = ppSec.rawSize;
        sec.characteristics    = ppSec.characteristics;

        sec.isReadable         = ppSec.isReadable;
        sec.isWritable         = ppSec.isWritable;
        sec.isExecutable       = ppSec.isExecutable;
        sec.isCode             = ppSec.hasCode;
        sec.isInitializedData  = ppSec.hasInitializedData;
        sec.isUninitializedData = ppSec.hasUninitializedData;
        sec.isEmpty            = (sec.rawSize == 0 && sec.virtualSize == 0);

        // Entry point check
        if (pe.entryPoint >= sec.virtualAddress &&
            pe.entryPoint < sec.virtualAddress + sec.virtualSize) {
            sec.containsEntryPoint = true;
        }

        // Non-ASCII section name check
        for (char c : sec.name) {
            if (c != 0 && (static_cast<unsigned char>(c) < 0x20 ||
                           static_cast<unsigned char>(c) > 0x7E)) {
                pe.anomalies.push_back(PEAnomaly::NonASCIISectionName);
                break;
            }
        }

        // Empty section name
        if (sec.name.empty() || (sec.name.size() == 1 && sec.name[0] == '\0')) {
            pe.anomalies.push_back(PEAnomaly::EmptySectionName);
        }

        // Section hashes (HA-specific: PEParser does not compute per-section hashes)
        if (sec.rawSize > 0 && sec.rawOffset + sec.rawSize <= data.size()) {
            CalculateSectionHashes(
                data.subspan(static_cast<size_t>(sec.rawOffset),
                             static_cast<size_t>(sec.rawSize)),
                sec);
        }

        pe.sections.push_back(std::move(sec));
    }

    // Last section executable check
    if (!pe.sections.empty() && pe.sections.back().isExecutable) {
        pe.anomalies.push_back(PEAnomaly::LastSectionExecutable);
    }

    // Overlay entropy computation (HA-specific: PEParser detects overlay but
    // doesn't return the entropy value)
    if (pe.hasOverlay && pe.overlaySize > 0 &&
        pe.overlayOffset + pe.overlaySize <= data.size())
    {
        auto overlaySpan = data.subspan(
            static_cast<size_t>(pe.overlayOffset),
            static_cast<size_t>(pe.overlaySize));
        pe.overlayEntropy = CalculateEntropy(overlaySpan);
        pe.anomalies.push_back(PEAnomaly::HasOverlay);
        if (pe.overlaySize > pe.sizeOfImage) {
            pe.anomalies.push_back(PEAnomaly::LargeOverlay);
        }
    }
}

// ============================================================================
// PEParser Delegation: Rich Header Adapter
// ============================================================================

void HeuristicAnalyzer::PopulateRichHeader(
    PEParser::PEParser& parser,
    PEAnalysis& pe)
{
    PEParser::RichHeaderInfo richInfo;
    if (parser.ParseRichHeader(richInfo)) {
        pe.hasRichHeader = richInfo.present;
        pe.richEntries.reserve(richInfo.entries.size());
        for (const auto& entry : richInfo.entries) {
            pe.richEntries.emplace_back(
                static_cast<uint32_t>(entry.productId),
                entry.useCount);
        }
        // Only flag tampering when a Rich header was present but its
        // checksum failed to validate.  Binaries produced by non-MSVC
        // toolchains (gcc/clang/MASM) legitimately have no Rich header
        // and must not be penalized.
        if (richInfo.present && !richInfo.checksumValid) {
            pe.anomalies.push_back(PEAnomaly::RichHeaderStripped);
        }
    }
}

// ============================================================================
// PEParser Delegation: Heuristic Anomaly Detection
// ============================================================================

void HeuristicAnalyzer::DetectHeuristicAnomalies(
    const PEParser::PEInfo& peInfo,
    PEAnalysis& pe)
{
    // Alignment checks (heuristic-specific scoring)
    if (pe.sectionAlignment == 0 ||
        (pe.sectionAlignment & (pe.sectionAlignment - 1)) != 0) {
        pe.anomalies.push_back(PEAnomaly::InvalidSectionAlignment);
        pe.riskScore += 5.0;
    }
    if (pe.fileAlignment == 0 ||
        (pe.fileAlignment & (pe.fileAlignment - 1)) != 0) {
        pe.anomalies.push_back(PEAnomaly::InvalidFileAlignment);
        pe.riskScore += 5.0;
    }

    // Zero image base
    if (pe.imageBase == 0) {
        pe.anomalies.push_back(PEAnomaly::ZeroImageBase);
        pe.riskScore += 5.0;
    }

    // Entry point outside all sections
    if (pe.entryPointSection.empty() && pe.entryPoint != 0) {
        pe.anomalies.push_back(PEAnomaly::EntryPointOutsideSections);
        pe.riskScore += 10.0;
    }

    // .NET detection already handled by PEParser (peInfo.isDotNet)
    // No need to re-read CLR data directory
}

// ============================================================================
// LEGACY METHODS — Retained for backward compatibility, now delegate
// ============================================================================

bool HeuristicAnalyzer::ParseDOSHeader(std::span<const uint8_t> data, PEAnalysis& pe) {
    // DOS header validation is now handled by PEParser::ParseBuffer().
    // This method is retained for backward compatibility with any callers
    // outside of AnalyzePE(). It performs the minimum check.
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        pe.anomalies.push_back(PEAnomaly::InvalidDOSSignature);
        return false;
    }
    return true;
}

bool HeuristicAnalyzer::ParsePEHeaders(std::span<const uint8_t> data, PEAnalysis& pe) {
    // Full PE header parsing is now delegated to PEParser in AnalyzePE().
    // This legacy method delegates to PEParser for any external callers.
    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;
    if (!parser.ParseBuffer(data, peInfo)) {
        TransferPEParserAnomalies(peInfo.anomalies, pe);
        return false;
    }
    PopulateFromPEInfo(parser, peInfo, pe);
    return true;
}

// ============================================================================
// Section / Import / Export / Resource Parsing
// ============================================================================

void HeuristicAnalyzer::ParseSections(std::span<const uint8_t> data, PEAnalysis& pe) {
    // Section parsing is now handled by PopulateSections() via PEParser.
    // This legacy method is retained for backward compatibility.
    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;
    if (parser.ParseBuffer(data, peInfo)) {
        PopulateSections(parser, peInfo, data, pe);
    }
}

void HeuristicAnalyzer::ParseImports(std::span<const uint8_t> data, PEAnalysis& pe) {
    // Fill pe.imports from the parsed ImportAnalysis
    auto imports = AnalyzeImports(data);
    pe.imports = imports;
}

void HeuristicAnalyzer::ParseExports(std::span<const uint8_t> data, PEAnalysis& pe) {
    // Export anomaly detection is now handled in AnalyzePE() by checking
    // PEInfo.dataDirectories[EXPORT].present directly.
    // This legacy method retained for backward compatibility only.
    if (pe.isDLL) {
        PEParser::PEParser parser;
        PEParser::PEInfo peInfo;
        if (parser.ParseBuffer(data, peInfo)) {
            if (!peInfo.dataDirectories[PEParser::DataDirectory::EXPORT].present) {
                pe.anomalies.push_back(PEAnomaly::NoExportsForDLL);
            }
        }
    }
}

void HeuristicAnalyzer::ParseResources(std::span<const uint8_t> /*data*/, PEAnalysis& pe) {
    // Resource parsing requires walking IMAGE_RESOURCE_DIRECTORY trees.
    // Mark absence of resources as anomaly if not a tiny PE.
    if (pe.sizeOfImage > HeuristicConstants::MIN_IMAGE_SIZE && pe.resources.totalResources == 0) {
        pe.anomalies.push_back(PEAnomaly::NoResources);
    }
}

void HeuristicAnalyzer::AnalyzeRichHeader(std::span<const uint8_t> data, PEAnalysis& pe) {
    // Rich header is now analyzed via PEParser in PopulateRichHeader().
    // This legacy method retained for backward compatibility only.
    PEParser::PEParser parser;
    PEParser::PEInfo peInfo;
    if (parser.ParseBuffer(data, peInfo)) {
        PopulateRichHeader(parser, pe);
    }
}

void HeuristicAnalyzer::DetectPEAnomalies(std::span<const uint8_t> /*data*/, PEAnalysis& pe) {
    // Heuristic anomaly detection is now handled by DetectHeuristicAnomalies()
    // using PEInfo. This legacy method applies the same checks without needing
    // the raw buffer (anomaly data comes from pre-populated pe fields).
    PEParser::PEInfo dummyInfo;
    DetectHeuristicAnomalies(dummyInfo, pe);
}
// ============================================================================
// Import Analysis (Public)
// ============================================================================

ImportAnalysis HeuristicAnalyzer::AnalyzeImports(std::span<const uint8_t> data) const {
    ImportAnalysis result;

    try {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) return result;
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;
        if (static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > data.size())
            return result;

        const size_t optStart = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (optStart + sizeof(WORD) > data.size()) return result;
        WORD magic = 0;
        std::memcpy(&magic, data.data() + optStart, sizeof(WORD));

        DWORD importRVA = 0;
        DWORD importSize = 0;

        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            if (optStart + sizeof(IMAGE_OPTIONAL_HEADER64) > data.size()) return result;
            auto opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data.data() + optStart);
            if (IMAGE_DIRECTORY_ENTRY_IMPORT < opt->NumberOfRvaAndSizes) {
                importRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                importSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            if (optStart + sizeof(IMAGE_OPTIONAL_HEADER32) > data.size()) return result;
            auto opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data.data() + optStart);
            if (IMAGE_DIRECTORY_ENTRY_IMPORT < opt->NumberOfRvaAndSizes) {
                importRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                importSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
        }
        (void)importSize;

        if (importRVA == 0) {
            result.hasNoImports = true;
            result.riskScore += 10.0;
            return result;
        }

        // Cap the raw-byte search range to avoid pathological O(N*M*F) cost on
        // very large files.  The PE import name strings live in IAT-adjacent
        // sections which are almost always within the first ~64 MiB.
        constexpr size_t kMaxImportScanBytes = 64ull * 1024ull * 1024ull;
        const size_t scanLen = std::min<size_t>(data.size(), kMaxImportScanBytes);

        bool hasLoadLib = false;
        bool hasGetProc = false;

        // Word-boundary helper: an ASCII byte is part of an identifier only if
        // it is alphanumeric or '_'.  The previous "'A'..'z'" range incorrectly
        // included the punctuation block 0x5B..0x60 ([\]^_`).
        auto isIdentByte = [](uint8_t b) noexcept -> bool {
            return (b >= 'A' && b <= 'Z') ||
                   (b >= 'a' && b <= 'z') ||
                   (b >= '0' && b <= '9') ||
                   b == '_';
        };

        for (const auto& [funcName, cat] : m_impl->m_importCategoryMap) {
            const auto* needle = reinterpret_cast<const uint8_t*>(funcName.c_str());
            const size_t needleLen = funcName.size();

            if (needleLen == 0 || needleLen > scanLen) continue;

            for (size_t off = 0; off + needleLen <= scanLen; ++off) {
                if (std::memcmp(data.data() + off, needle, needleLen) != 0) continue;

                // Verify word boundaries on both sides so substrings such as
                // "SafeCreateRemoteThreadShim" do not yield a false positive.
                if (off > 0 && isIdentByte(data[off - 1])) continue;
                if (off + needleLen < scanLen && isIdentByte(data[off + needleLen])) continue;

                ImportedFunction func;
                func.functionName = funcName;
                func.category = cat;
                func.riskScore = 3.0;

                ClassifyImport(func);
                result.suspiciousFunctions.push_back(func);
                result.functions.push_back(std::move(func));
                result.suspiciousCount++;
                result.detectedCategories.insert(cat);

                if (funcName.find("LoadLibrary") != std::string::npos) hasLoadLib = true;
                if (funcName == "GetProcAddress") hasGetProc = true;
                break;
            }

            if (result.suspiciousCount > HeuristicConstants::MAX_NORMAL_IMPORTS) break;
        }

        result.hasDynamicLoading = hasLoadLib && hasGetProc;

        if (result.suspiciousCount > 5) {
            result.riskScore += HeuristicConstants::MAX_IMPORT_SCORE;
        } else {
            result.riskScore += static_cast<double>(result.suspiciousCount) * 3.0;
        }

        result.riskScore = std::min(result.riskScore,
            HeuristicConstants::MAX_IMPORT_SCORE * HeuristicConstants::IMPORT_WEIGHT);

    } catch (...) {
        SS_LOG_WARN(L"HeuristicAnalyzer", L"Exception during import analysis");
    }

    return result;
}

void HeuristicAnalyzer::ClassifyImport(ImportedFunction& func) const {
    // Already classified during search; compute risk score per category
    switch (func.category) {
        case SuspiciousAPICategory::CodeInjection:
        case SuspiciousAPICategory::ProcessManipulation:
            func.riskScore = 5.0;
            break;
        case SuspiciousAPICategory::AntiDebug:
        case SuspiciousAPICategory::CredentialAccess:
        case SuspiciousAPICategory::PrivilegeEscalation:
            func.riskScore = 4.0;
            break;
        case SuspiciousAPICategory::NetworkOperations:
        case SuspiciousAPICategory::CryptoOperations:
            func.riskScore = 3.0;
            break;
        default:
            func.riskScore = 2.0;
            break;
    }
}
// ============================================================================
// Script Analysis (Public)
// ============================================================================

ScriptAnalysis HeuristicAnalyzer::AnalyzeScript(
    std::span<const uint8_t> data,
    const std::string& /*scriptType*/)
{
    ScriptAnalysis result;

    if (data.empty()) return result;

    // Cap to avoid DoS on huge scripts
    const size_t maxAnalyze = std::min<size_t>(data.size(), 4 * 1024 * 1024);

    std::string content(reinterpret_cast<const char*>(data.data()), maxAnalyze);
    std::string lower = content;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Obfuscation detection
    size_t obfIndicators = 0;
    if (lower.find("base64") != std::string::npos ||
        lower.find("frombase64string") != std::string::npos ||
        lower.find("convert]::frombase64") != std::string::npos) {
        obfIndicators++;
        result.hasEncodedContent = true;
    }
    if (std::count(lower.begin(), lower.end(), '+') > 30) obfIndicators++;
    if (lower.find("-replace") != std::string::npos || lower.find(".replace(") != std::string::npos) obfIndicators++;
    if (lower.find("char]") != std::string::npos && lower.find("[int]") != std::string::npos) obfIndicators++;
    if (lower.find("-join") != std::string::npos && lower.find("-split") != std::string::npos) obfIndicators++;
    if (lower.find("iex") != std::string::npos || lower.find("invoke-expression") != std::string::npos) obfIndicators++;

    result.isObfuscated = (obfIndicators >= 3);
    if (result.isObfuscated) {
        result.riskScore += 25.0;
        result.detectedTechniques.push_back("Obfuscation");
    }

    // Dangerous capabilities
    static const std::pair<const char*, bool ScriptAnalysis::*> capChecks[] = {
        {"downloadstring",        &ScriptAnalysis::hasDownloadCapability},
        {"downloadfile",          &ScriptAnalysis::hasDownloadCapability},
        {"invoke-webrequest",     &ScriptAnalysis::hasDownloadCapability},
        {"webclient",             &ScriptAnalysis::hasNetworkOperations},
        {"net.sockets",           &ScriptAnalysis::hasNetworkOperations},
        {"start-process",         &ScriptAnalysis::hasExecutionCapability},
        {"createobject",          &ScriptAnalysis::hasExecutionCapability},
        {"wscript.shell",         &ScriptAnalysis::hasExecutionCapability},
        {"new-object -com",       &ScriptAnalysis::hasCOMOperations},
        {"get-wmiobject",         &ScriptAnalysis::hasWMIOperations},
        {"gwmi",                  &ScriptAnalysis::hasWMIOperations},
        {"invoke-wmimethod",      &ScriptAnalysis::hasWMIOperations},
        {"set-itemproperty",      &ScriptAnalysis::hasRegistryOperations},
        {"new-itemproperty",      &ScriptAnalysis::hasRegistryOperations},
        {"hklm:",                 &ScriptAnalysis::hasRegistryOperations},
        {"hkcu:",                 &ScriptAnalysis::hasRegistryOperations},
        {"remove-item",           &ScriptAnalysis::hasFileOperations},
        {"copy-item",             &ScriptAnalysis::hasFileOperations},
        {"move-item",             &ScriptAnalysis::hasFileOperations},
    };

    for (const auto& [pat, memberPtr] : capChecks) {
        if (lower.find(pat) != std::string::npos) {
            result.*memberPtr = true;
        }
    }

    double capScore = 0.0;
    if (result.hasDownloadCapability) { capScore += 15.0; result.detectedTechniques.push_back("Download"); }
    if (result.hasExecutionCapability) { capScore += 10.0; result.detectedTechniques.push_back("Execution"); }
    if (result.hasNetworkOperations)  { capScore += 5.0;  result.detectedTechniques.push_back("Network"); }
    if (result.hasRegistryOperations) { capScore += 5.0;  result.detectedTechniques.push_back("Registry"); }
    if (result.hasWMIOperations)      { capScore += 5.0;  result.detectedTechniques.push_back("WMI"); }
    if (result.hasCOMOperations)      { capScore += 3.0; }
    if (result.hasProcessOperations)  { capScore += 5.0; }
    result.riskScore += capScore;

    // Extract URLs and IPs
    size_t pos = 0;
    size_t urlsCapped = 0;
    while ((pos = lower.find("http", pos)) != std::string::npos && urlsCapped < 100) {
        size_t endPos = content.find_first_of(" \t\r\n'\">;)", pos);
        if (endPos == std::string::npos) endPos = std::min(pos + 256, content.size());
        if (endPos > pos) {
            result.urls.push_back(content.substr(pos, endPos - pos));
            urlsCapped++;
        }
        pos = endPos;
    }

    if (!result.urls.empty()) result.riskScore += 5.0;

    result.riskScore = std::min(result.riskScore, HeuristicConstants::MAX_RISK_SCORE);
    return result;
}

// ============================================================================
// String Analysis (Public)
// ============================================================================

StringAnalysis HeuristicAnalyzer::AnalyzeStrings(std::span<const uint8_t> data) {
    StringAnalysis result;

    if (data.empty()) return result;

    // Cap to prevent OOM: only scan first 16MB
    const size_t maxScan = std::min<size_t>(data.size(), 16 * 1024 * 1024);

    std::string current;
    current.reserve(256);

    size_t stringsFound = 0;

    for (size_t i = 0; i < maxScan; ++i) {
        char c = static_cast<char>(data[i]);
        if (std::isprint(static_cast<unsigned char>(c))) {
            if (current.size() < HeuristicConstants::MAX_STRING_LENGTH) {
                current += c;
            }
        } else {
            if (current.size() >= HeuristicConstants::MIN_STRING_LENGTH) {
                if (stringsFound < HeuristicConstants::MAX_STRINGS) {
                    AnalyzeExtractedStringImpl(current, i - current.size(), result);
                    stringsFound++;
                    result.totalStrings++;
                    result.asciiCount++;
                }
            }
            current.clear();
        }
    }
    // Handle trailing string
    if (current.size() >= HeuristicConstants::MIN_STRING_LENGTH &&
        stringsFound < HeuristicConstants::MAX_STRINGS) {
        AnalyzeExtractedStringImpl(current, maxScan - current.size(), result);
        result.totalStrings++;
        result.asciiCount++;
    }

    result.riskScore = std::min(result.riskScore,
        HeuristicConstants::MAX_STRING_SCORE * HeuristicConstants::STRING_WEIGHT);

    return result;
}

// Internal helper -- not declared in the header, so we use a free function scope
// wrapped in an anonymous namespace would break linkage, so we keep it as-is
// and forward-reference from AnalyzeStrings.
// We piggyback on the class by defining a private-ish method.

void HeuristicAnalyzer::CalculateSectionHashes(std::span<const uint8_t> data, SectionAnalysis& section) {
    Utils::HashUtils::Hasher md5h(Utils::HashUtils::Algorithm::MD5);
    if (md5h.Init() && md5h.Update(data.data(), data.size())) {
        (void)md5h.FinalHex(section.md5, false);
    }

    Utils::HashUtils::Hasher sha256h(Utils::HashUtils::Algorithm::SHA256);
    if (sha256h.Init() && sha256h.Update(data.data(), data.size())) {
        (void)sha256h.FinalHex(section.sha256, false);
    }
}
// ============================================================================
// Packer Detection (Public)
// ============================================================================

PackerDetection HeuristicAnalyzer::DetectPacker(std::span<const uint8_t> data) {
    PackerDetection result;

    try {
        if (data.size() < sizeof(IMAGE_DOS_HEADER)) return result;

        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

        const auto peOffset = static_cast<size_t>(dos->e_lfanew);
        if (peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > data.size()) return result;

        auto fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(
            data.data() + peOffset + sizeof(DWORD));
        uint16_t numSections = fileHdr->NumberOfSections;

        // Determine optional header size to find section table
        const size_t optStart = peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (optStart + sizeof(WORD) > data.size()) return result;
        auto magic = *reinterpret_cast<const WORD*>(data.data() + optStart);

        size_t sectionStart = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            sectionStart = optStart + sizeof(IMAGE_OPTIONAL_HEADER64);
        } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            sectionStart = optStart + sizeof(IMAGE_OPTIONAL_HEADER32);
        } else {
            return result;
        }

        const size_t sectionEnd = sectionStart + numSections * sizeof(IMAGE_SECTION_HEADER);
        if (sectionEnd > data.size()) return result;

        auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(data.data() + sectionStart);

        // m_packerSignatures is populated once in Impl::Impl() and is never
        // mutated thereafter, so no synchronization is required for read-only
        // access. Acquiring m_impl->m_mutex here would re-enter the same
        // std::shared_mutex from the analysis pipeline (UB on MSVC's STL).

        for (WORD i = 0; i < numSections; ++i) {
            std::string name(
                reinterpret_cast<const char*>(sections[i].Name),
                strnlen(reinterpret_cast<const char*>(sections[i].Name), IMAGE_SIZEOF_SHORT_NAME));

            auto it = m_impl->m_packerSignatures.find(name);
            if (it != m_impl->m_packerSignatures.end()) {
                result.isPacked = true;
                result.packerType = it->second;
                result.confidence = 0.9;
                result.packerName = name;
                result.detectionMethod = "section_name";
                result.riskScore = HeuristicConstants::MAX_PACKER_SCORE;

                // Classify packer subtype
                auto pt = static_cast<uint16_t>(it->second);
                if (pt >= 200 && pt < 250) {
                    result.isInstaller = true;
                    result.riskScore = 5.0; // Installers are lower risk
                } else if (pt >= 50 && pt < 100) {
                    result.isProtector = true;
                } else if (pt >= 100 && pt < 150) {
                    result.isCrypter = true;
                    result.riskScore = HeuristicConstants::MAX_PACKER_SCORE;
                }

                return result;
            }
        }

        // Entropy-based heuristic for generic packing
        double fileEntropy = CalculateEntropy(data);
        if (fileEntropy > HeuristicConstants::VERY_HIGH_ENTROPY_THRESHOLD) {
            result.isPacked = true;
            result.packerType = PackerType::Generic;
            result.confidence = 0.6;
            result.packerName = "Generic (high entropy)";
            result.detectionMethod = "entropy";
            result.riskScore = 10.0;
        }

    } catch (...) {
        SS_LOG_WARN(L"HeuristicAnalyzer", L"Exception during packer detection");
    }

    return result;
}

// ============================================================================
// Certificate Verification (Public)
// ============================================================================

CertificateInfo HeuristicAnalyzer::VerifySignature(const std::wstring& filePath) {
    CertificateInfo info;

    if (filePath.empty()) return info;

    try {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_REVOCATION_CHECK_CHAIN;

        LONG status = WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGUID, &trustData);

        if (status == ERROR_SUCCESS) {
            info.isSigned = true;
            info.isSignatureValid = true;
            info.isCertificateValid = true;
        } else if (status == TRUST_E_NOSIGNATURE) {
            info.isSigned = false;
            info.riskScore += 5.0;
        } else if (status == CERT_E_EXPIRED) {
            info.isSigned = true;
            info.isSignatureValid = false;
            info.isExpired = true;
            info.riskScore += 15.0;
        } else if (status == CERT_E_REVOKED) {
            info.isSigned = true;
            info.isSignatureValid = false;
            info.isRevoked = true;
            info.riskScore += 25.0;
        } else {
            info.isSigned = true;
            info.isSignatureValid = false;
            info.riskScore += 20.0;
        }

        // Extract signer name from the state data
        if (info.isSigned) {
            CRYPT_PROVIDER_DATA* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
            if (provData) {
                CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(provData, 0, FALSE, 0);
                if (sgnr && sgnr->pasCertChain && sgnr->csCertChain > 0) {
                    PCCERT_CONTEXT cert = sgnr->pasCertChain[0].pCert;
                    if (cert) {
                        wchar_t subjectBuf[256] = {};
                        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                          0, nullptr, subjectBuf, 256);
                        info.subjectName = subjectBuf;

                        wchar_t issuerBuf[256] = {};
                        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                          CERT_NAME_ISSUER_FLAG, nullptr, issuerBuf, 256);
                        info.issuerName = issuerBuf;

                        // Self-signed check
                        info.isSelfSigned = (info.subjectName == info.issuerName);
                        if (info.isSelfSigned) {
                            info.riskScore += 10.0;
                        }

                        // Build certificate chain display
                        for (DWORD ci = 0; ci < sgnr->csCertChain && ci < 10; ++ci) {
                            wchar_t chainBuf[256] = {};
                            CertGetNameStringW(sgnr->pasCertChain[ci].pCert,
                                              CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                              0, nullptr, chainBuf, 256);
                            info.certificateChain.emplace_back(chainBuf);
                        }
                        info.isChainComplete = (sgnr->csCertChain >= 2);
                    }
                }
            }
        }

        // Cleanup WinVerifyTrust state
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGUID, &trustData);

        info.riskScore = std::min(info.riskScore,
            HeuristicConstants::MAX_CERTIFICATE_SCORE * HeuristicConstants::CERTIFICATE_WEIGHT);

    } catch (...) {
        SS_LOG_WARN(L"HeuristicAnalyzer", L"Exception during certificate verification");
    }

    return info;
}
// ============================================================================
// Entropy / Statistics / Hashing
// ============================================================================

double HeuristicAnalyzer::CalculateEntropy(std::span<const uint8_t> data) const {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (auto b : data) freq[b]++;

    double entropy = 0.0;
    const double n = static_cast<double>(data.size());
    for (auto f : freq) {
        if (f > 0) {
            double p = static_cast<double>(f) / n;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

double HeuristicAnalyzer::CalculateChiSquare(std::span<const uint8_t> data) const {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (auto b : data) freq[b]++;

    const double expected = static_cast<double>(data.size()) / 256.0;
    double chi = 0.0;
    for (auto f : freq) {
        double diff = static_cast<double>(f) - expected;
        chi += (diff * diff) / expected;
    }
    return chi;
}

bool HeuristicAnalyzer::IsLikelyEncrypted(std::span<const uint8_t> data) const {
    if (data.size() < 256) return false;
    double entropy = CalculateEntropy(data);
    double chi = CalculateChiSquare(data);
    return (entropy > HeuristicConstants::VERY_HIGH_ENTROPY_THRESHOLD &&
            chi < HeuristicConstants::CHI_SQUARE_RANDOM_THRESHOLD);
}

std::string HeuristicAnalyzer::CalculateImpHash(std::span<const uint8_t> data) const {
    // ImpHash: MD5 of sorted, lowercased "dll.function" import list
    auto imports = AnalyzeImports(data);
    if (imports.functions.empty()) return {};

    std::vector<std::string> entries;
    entries.reserve(imports.functions.size());
    for (const auto& f : imports.functions) {
        std::string dll = f.dllName;
        std::transform(dll.begin(), dll.end(), dll.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        // Strip .dll extension
        auto dotPos = dll.rfind(".dll");
        if (dotPos != std::string::npos) dll.erase(dotPos);

        std::string func = f.functionName;
        std::transform(func.begin(), func.end(), func.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        entries.push_back(dll + "." + func);
    }
    std::sort(entries.begin(), entries.end());

    std::string combined;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) combined += ',';
        combined += entries[i];
    }

    Utils::HashUtils::Hasher h(Utils::HashUtils::Algorithm::MD5);
    if (h.Init() && h.Update(combined.data(), combined.size())) {
        std::string hex;
        if (h.FinalHex(hex, false)) return hex;
    }
    return {};
}

std::string HeuristicAnalyzer::CalculateFuzzyHash(std::span<const uint8_t> /*data*/) const {
    // CTPH (ssdeep) requires the ssdeep library; return empty if unavailable.
    return {};
}

std::string HeuristicAnalyzer::CalculateTLSH(std::span<const uint8_t> /*data*/) const {
    // TLSH requires the tlsh library; return empty if unavailable.
    return {};
}
// ============================================================================
// File Type Detection
// ============================================================================

FileType HeuristicAnalyzer::DetectFileType(std::span<const uint8_t> data) const {
    if (data.size() < 4) return FileType::Unknown;

    // PE check
    if (data[0] == 'M' && data[1] == 'Z') {
        if (data.size() >= sizeof(IMAGE_DOS_HEADER)) {
            auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
            auto off = static_cast<size_t>(dos->e_lfanew);
            if (off + 6 <= data.size()) {
                auto sig = *reinterpret_cast<const DWORD*>(data.data() + off);
                if (sig == IMAGE_NT_SIGNATURE) {
                    auto machine = *reinterpret_cast<const WORD*>(data.data() + off + 4);
                    if (machine == IMAGE_FILE_MACHINE_AMD64 ||
                        machine == IMAGE_FILE_MACHINE_IA64 ||
                        machine == IMAGE_FILE_MACHINE_ARM64) {
                        return FileType::PE64;
                    }
                    return FileType::PE32;
                }
            }
        }
    }

    // ELF check
    if (data.size() >= 5 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        return (data[4] == 2) ? FileType::ELF64 : FileType::ELF32;
    }

    // PDF check
    if (data.size() >= 5 && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F') {
        return FileType::PDF;
    }

    // ZIP / Office (DOCX etc)
    if (data.size() >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04) {
        return FileType::Archive;
    }

    // RAR
    if (data.size() >= 7 && data[0] == 'R' && data[1] == 'a' && data[2] == 'r' && data[3] == '!') {
        return FileType::Archive;
    }

    // OLE2 (DOC, XLS, PPT)
    if (data.size() >= 8 && data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0) {
        return FileType::Office;
    }

    return FileType::Unknown;
}

FileType HeuristicAnalyzer::DetectFileType(const std::wstring& filePath) const {
    if (filePath.empty()) return FileType::Unknown;

    // Extension-based heuristic
    auto dot = filePath.rfind(L'.');
    if (dot == std::wstring::npos) return FileType::Unknown;

    std::wstring ext = filePath.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });

    if (ext == L".exe" || ext == L".scr") return FileType::PE32;
    if (ext == L".dll")  return FileType::DLL;
    if (ext == L".sys")  return FileType::SYS;
    if (ext == L".ps1" || ext == L".psm1" || ext == L".psd1") return FileType::Script;
    if (ext == L".js" || ext == L".jse") return FileType::Script;
    if (ext == L".vbs" || ext == L".vbe") return FileType::Script;
    if (ext == L".bat" || ext == L".cmd") return FileType::Script;
    if (ext == L".doc" || ext == L".docx" || ext == L".docm") return FileType::Office;
    if (ext == L".xls" || ext == L".xlsx" || ext == L".xlsm") return FileType::Office;
    if (ext == L".ppt" || ext == L".pptx" || ext == L".pptm") return FileType::Office;
    if (ext == L".pdf")  return FileType::PDF;
    if (ext == L".zip")  return FileType::Archive;
    if (ext == L".rar")  return FileType::Archive;
    if (ext == L".7z")   return FileType::Archive;
    if (ext == L".jar")  return FileType::JAR;
    if (ext == L".msi")  return FileType::MSI;
    if (ext == L".lnk")  return FileType::LNK;
    if (ext == L".iso")  return FileType::ISO;
    if (ext == L".vhd" || ext == L".vhdx") return FileType::VHD;
    if (ext == L".html" || ext == L".htm") return FileType::HTML;
    if (ext == L".rtf")  return FileType::RTF;

    return FileType::Unknown;
}

// ============================================================================
// Fuzzy Matching
// ============================================================================

int HeuristicAnalyzer::CompareFuzzyHash(
    const std::string& hash1,
    const std::string& hash2) const
{
    // Implement a simplified but robust fuzzy hash comparison
    if (hash1.empty() || hash2.empty()) return 0;
    if (hash1 == hash2) return 100;
    
    // Parse ssdeep format: blocksize:hash1:hash2
    auto parseHash = [](const std::string& hash) -> std::tuple<uint32_t, std::string, std::string> {
        size_t pos1 = hash.find(':');
        if (pos1 == std::string::npos) return {};
        
        size_t pos2 = hash.find(':', pos1 + 1);
        if (pos2 == std::string::npos) return {};
        
        try {
            uint32_t blocksize = std::stoul(hash.substr(0, pos1));
            std::string part1 = hash.substr(pos1 + 1, pos2 - pos1 - 1);
            std::string part2 = hash.substr(pos2 + 1);
            return {blocksize, part1, part2};
        } catch (...) {
            return {};
        }
    };
    
    auto [bs1, p1_1, p1_2] = parseHash(hash1);
    auto [bs2, p2_1, p2_2] = parseHash(hash2);
    
    if (bs1 == 0 || bs2 == 0) return 0;
    
    // Blocksizes must be similar for meaningful comparison
    uint32_t ratio = std::max(bs1, bs2) / std::min(bs1, bs2);
    if (ratio > 2) return 0;
    
    // Compute similarity using Levenshtein distance
    auto levenshtein = [](const std::string& s1, const std::string& s2) -> size_t {
        std::vector<std::vector<size_t>> dp(s1.size() + 1, std::vector<size_t>(s2.size() + 1));
        
        for (size_t i = 0; i <= s1.size(); ++i) dp[i][0] = i;
        for (size_t j = 0; j <= s2.size(); ++j) dp[0][j] = j;
        
        for (size_t i = 1; i <= s1.size(); ++i) {
            for (size_t j = 1; j <= s2.size(); ++j) {
                if (s1[i-1] == s2[j-1]) {
                    dp[i][j] = dp[i-1][j-1];
                } else {
                    dp[i][j] = 1 + std::min({dp[i-1][j], dp[i][j-1], dp[i-1][j-1]});
                }
            }
        }
        return dp[s1.size()][s2.size()];
    };
    
    // Compare both parts and take the maximum similarity
    size_t dist1 = levenshtein(p1_1, p2_1);
    size_t dist2 = levenshtein(p1_2, p2_2);
    
    size_t maxLen = std::max({p1_1.size(), p2_1.size(), p1_2.size(), p2_2.size()});
    if (maxLen == 0) return 0;
    
    double sim1 = std::max(0.0, 1.0 - static_cast<double>(dist1) / maxLen);
    double sim2 = std::max(0.0, 1.0 - static_cast<double>(dist2) / maxLen);
    
    return static_cast<int>(std::max(sim1, sim2) * 100.0);
}

int HeuristicAnalyzer::CompareTLSH(
    const std::string& hash1,
    const std::string& hash2) const
{
    // Implement simplified TLSH-like comparison
    if (hash1.empty() || hash2.empty()) return 256;
    if (hash1 == hash2) return 0;
    if (hash1.size() != hash2.size()) return 256;
    
    // TLSH hashes should be hex strings of fixed length
    if (hash1.size() < 70) return 256; // Minimum TLSH length
    
    size_t differences = 0;
    for (size_t i = 0; i < std::min(hash1.size(), hash2.size()); ++i) {
        if (hash1[i] != hash2[i]) {
            differences++;
        }
    }
    
    // Convert character differences to TLSH distance scale
    double similarity = 1.0 - static_cast<double>(differences) / hash1.size();
    return static_cast<int>((1.0 - similarity) * 256.0);
}

FuzzyMatchResult HeuristicAnalyzer::QueryFuzzyMatch(
    const std::string& fuzzyHash,
    const std::string& tlsh,
    const std::string& impHash)
{
    FuzzyMatchResult result;
    result.fuzzyHash = fuzzyHash;
    result.tlsh = tlsh;
    result.impHash = impHash;

    // The HashStore::FuzzyMatch contract operates on context-triggered
    // piecewise hashes (e.g. ssdeep / TLSH).  A SHA-256 has no fuzzy
    // semantics — the previous code path fed SHA-256 hex into a HashValue
    // and asked for fuzzy similarity, which always degenerated to byte-
    // for-byte equality (i.e. the answer is always "no match" except for
    // bit-identical files, in which case the exact-hash path already
    // catches it).  Until a real CTPH/TLSH implementation lands, we only
    // dispatch to HashStore when at least one fuzzy-capable hash is
    // present.
    if (fuzzyHash.empty() && tlsh.empty()) {
        return result;
    }

    HashStore::HashStore* hashStore = nullptr;
    uint32_t threshold = 80;
    {
        std::shared_lock lock(m_impl->m_mutex);
        hashStore = m_impl->m_hashStore;
        threshold = static_cast<uint32_t>(m_impl->m_config.fuzzyMinSimilarity);
    }
    if (!hashStore) return result;

    try {
        // Prefer TLSH when available (35-byte canonical digest), otherwise
        // fall back to ssdeep / CTPH which is variable-length text.
        SignatureStore::HashValue hv{};
        const std::string& src = !tlsh.empty() ? tlsh : fuzzyHash;
        hv.type = !tlsh.empty() ? SignatureStore::HashType::TLSH
                                : SignatureStore::HashType::FUZZY;
        const size_t copyLen = std::min(src.size(), hv.data.size());
        std::memcpy(hv.data.data(),
                    reinterpret_cast<const uint8_t*>(src.data()),
                    copyLen);
        hv.length = static_cast<uint8_t>(copyLen);

        auto matches = hashStore->FuzzyMatch(hv, threshold);
        if (!matches.empty()) {
            result.hasMatch = true;
            result.matchConfidence = static_cast<double>(matches[0].similarity);
            result.matchedThreatName = Utils::StringUtils::ToWide(matches[0].signatureName);
            result.riskScore = result.matchConfidence * HeuristicConstants::MAX_FUZZY_MATCH_SCORE;
        }

    } catch (const std::exception& e) {
        SS_LOG_WARN(L"HeuristicAnalyzer", L"Fuzzy match query failed: %ls",
                   Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return result;
}
// ============================================================================
// Code Analysis
// ============================================================================

void HeuristicAnalyzer::AnalyzeCode(std::span<const uint8_t> data, CodeAnalysis& code) {
    if (data.empty()) return;

    code.codeSize = data.size();

    // Opcode frequency
    for (auto b : data) {
        code.opcodeFrequency[b]++;
    }

    // Shellcode patterns: look for common shellcode prologues
    // NOP sled
    size_t nopRun = 0;
    for (auto b : data) {
        if (b == 0x90) {
            nopRun++;
            if (nopRun > 16) {
                code.hasShellcodePatterns = true;
                break;
            }
        } else {
            nopRun = 0;
        }
    }

    // Anti-disassembly: jmp+1 pattern (EB FF)
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        if (data[i] == 0xEB && data[i + 1] == 0xFF) {
            code.hasAntiDisassembly = true;
            code.obfuscationTechniques.push_back("jmp_minus_one");
            break;
        }
    }

    // API hashing: look for common hash constants (ROR-13 pattern uses 0x0D)
    // Check for repeated 'ror edi, 0x0D' sequences: C1 CF 0D
    size_t hashPatterns = 0;
    for (size_t i = 0; i + 2 < data.size(); ++i) {
        if (data[i] == 0xC1 && data[i + 1] == 0xCF && data[i + 2] == 0x0D) {
            hashPatterns++;
        }
    }
    if (hashPatterns >= 2) {
        code.hasAPIHashing = true;
        code.obfuscationTechniques.push_back("api_hashing_ror13");
    }

    code.hasObfuscation = code.hasAntiDisassembly || code.hasAPIHashing;

    if (code.hasShellcodePatterns) code.riskScore += 15.0;
    if (code.hasAntiDisassembly)  code.riskScore += 10.0;
    if (code.hasAPIHashing)       code.riskScore += 10.0;
    if (code.hasObfuscation)      code.riskScore += 5.0;

    code.riskScore = std::min(code.riskScore,
        HeuristicConstants::MAX_OBFUSCATION_SCORE * HeuristicConstants::OBFUSCATION_WEIGHT);
}

// ============================================================================
// Score Aggregation and Threat Naming
// ============================================================================

void HeuristicAnalyzer::AggregateScores(HeuristicResult& result) {
    double score = result.riskScore;

    // Set verdict flags
    result.isClean = (score < HeuristicConstants::SUSPICIOUS_THRESHOLD);
    result.isSuspicious = (score >= HeuristicConstants::SUSPICIOUS_THRESHOLD &&
                           score < HeuristicConstants::LIKELY_MALICIOUS_THRESHOLD);
    result.isLikelyMalicious = (score >= HeuristicConstants::LIKELY_MALICIOUS_THRESHOLD &&
                                score < HeuristicConstants::MALICIOUS_THRESHOLD);
    result.isMalicious = (score >= HeuristicConstants::MALICIOUS_THRESHOLD);

    // Confidence is based on number of indicators that fired
    size_t indicatorCount = result.indicators.size();
    if (indicatorCount == 0) {
        result.confidence = 0.0;
    } else if (indicatorCount >= 5) {
        result.confidence = 0.95;
    } else {
        result.confidence = 0.5 + 0.1 * static_cast<double>(indicatorCount);
    }

    // Build category scores map
    if (result.peAnalysis.has_value()) {
        result.categoryScores["pe_anomalies"] = result.peAnalysis->riskScore;
    }
    result.categoryScores["strings"] = result.stringAnalysis.riskScore;
    result.categoryScores["packer"]  = result.packerDetection.riskScore;
    result.categoryScores["fuzzy"]   = result.fuzzyMatch.riskScore;

    if (result.peAnalysis.has_value()) {
        result.categoryScores["imports"] = result.peAnalysis->imports.riskScore;
        result.categoryScores["certificate"] = result.peAnalysis->certificate.riskScore;
    }

    // Populate highSeverityIndicators
    result.highSeverityIndicators.clear();
    for (const auto& ind : result.indicators) {
        if (ind.severity >= IndicatorSeverity::High) {
            result.highSeverityIndicators.push_back(ind);
        }
    }

    // Build summary
    result.summary = L"Risk=" + std::to_wstring(static_cast<int>(score));
    if (result.isMalicious) result.summary += L" MALICIOUS";
    else if (result.isLikelyMalicious) result.summary += L" LIKELY_MALICIOUS";
    else if (result.isSuspicious) result.summary += L" SUSPICIOUS";
    else result.summary += L" CLEAN";
}

void HeuristicAnalyzer::GenerateThreatName(HeuristicResult& result) {
    if (!result.isMalicious && !result.isLikelyMalicious) return;

    // Build name from indicators
    std::wstring prefix = L"Heuristic";
    std::wstring category;

    if (result.packerDetection.isPacked && result.packerDetection.isCrypter) {
        category = L"Crypter";
    } else if (result.packerDetection.isPacked) {
        category = L"Packed";
    } else if (result.fuzzyMatch.hasMatch) {
        category = L"FuzzyMatch";
        result.threatFamily = result.fuzzyMatch.matchedFamily;
    } else {
        category = L"Generic";
    }

    std::wstring fileTypeStr;
    switch (result.fileType) {
        case FileType::PE32:
        case FileType::PE64:
        case FileType::DLL: fileTypeStr = L"Win"; break;
        case FileType::Script: fileTypeStr = L"Script"; break;
        default: fileTypeStr = L"File"; break;
    }

    result.threatName = prefix + L":" + fileTypeStr + L"/" + category;
}
// ============================================================================
// Statistics
// ============================================================================

HeuristicAnalyzerStats HeuristicAnalyzer::GetStats() const {
    // Atomics are individually safe; aggregate read is best-effort
    HeuristicAnalyzerStats stats;
    stats.totalFilesAnalyzed.store(m_impl->m_statistics.totalFilesAnalyzed.load(std::memory_order_relaxed));
    stats.cleanFiles.store(m_impl->m_statistics.cleanFiles.load(std::memory_order_relaxed));
    stats.suspiciousFiles.store(m_impl->m_statistics.suspiciousFiles.load(std::memory_order_relaxed));
    stats.maliciousFiles.store(m_impl->m_statistics.maliciousFiles.load(std::memory_order_relaxed));
    stats.packedFiles.store(m_impl->m_statistics.packedFiles.load(std::memory_order_relaxed));
    stats.fuzzyMatches.store(m_impl->m_statistics.fuzzyMatches.load(std::memory_order_relaxed));
    stats.analysisFailures.store(m_impl->m_statistics.analysisFailures.load(std::memory_order_relaxed));
    stats.timeouts.store(m_impl->m_statistics.timeouts.load(std::memory_order_relaxed));
    stats.avgAnalysisTimeUs.store(m_impl->m_statistics.avgAnalysisTimeUs.load(std::memory_order_relaxed));
    stats.totalBytesAnalyzed.store(m_impl->m_statistics.totalBytesAnalyzed.load(std::memory_order_relaxed));
    for (size_t i = 0; i < stats.filesByType.size(); ++i) {
        stats.filesByType[i].store(m_impl->m_statistics.filesByType[i].load(std::memory_order_relaxed));
    }
    return stats;
}

void HeuristicAnalyzer::ResetStats() {
    m_impl->m_statistics.Reset();
}

// ============================================================================
// External Store Setters
// ============================================================================

void HeuristicAnalyzer::SetHashStore(HashStore::HashStore* store) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_hashStore = store;
    SS_LOG_INFO(L"HeuristicAnalyzer", L"HashStore %ls",
               store ? L"registered" : L"unregistered");
}

void HeuristicAnalyzer::SetSignatureStore(SignatureStore::SignatureStore* store) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_signatureStore = store;
    SS_LOG_INFO(L"HeuristicAnalyzer", L"SignatureStore %ls",
               store ? L"registered" : L"unregistered");
}

void HeuristicAnalyzer::SetPatternStore(PatternStore::PatternStore* store) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_patternStore = store;
    SS_LOG_INFO(L"HeuristicAnalyzer", L"PatternStore %ls",
               store ? L"registered" : L"unregistered");
}

void HeuristicAnalyzer::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_threatIntel = index;
    SS_LOG_INFO(L"HeuristicAnalyzer", L"ThreatIntelIndex %ls",
               index ? L"registered" : L"unregistered");
}

// ============================================================================
// Internal String Analysis Helper
// ============================================================================

// This isn't declared in the header as a member; it's an internal helper
// used by AnalyzeStrings. We add it here as a static-like function.
// Since AnalyzeStrings needs to call it and it's not in the hpp, we
// define it as part of the class but not part of the public interface.

static void AnalyzeExtractedStringImpl(
    const std::string& str,
    uint64_t offset,
    StringAnalysis& result)
{
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    ExtractedString es;
    es.value = str;
    es.offset = offset;
    es.isUnicode = false;

    // URL detection
    if (lower.find("http://") != std::string::npos ||
        lower.find("https://") != std::string::npos ||
        lower.find("ftp://") != std::string::npos) {
        es.indicatorType = StringIndicatorType::URL;
        es.riskScore = 2.0;
        result.urls.push_back(str);
    }

    // IP address detection (simple: 4 octets separated by dots, all digits)
    if (es.indicatorType == StringIndicatorType::None) {
        int dots = 0;
        bool allDigitDot = !str.empty();
        for (char c : str) {
            if (c == '.') dots++;
            else if (!std::isdigit(static_cast<unsigned char>(c))) { allDigitDot = false; break; }
        }
        if (dots == 3 && allDigitDot && str.size() >= 7 && str.size() <= 15) {
            es.indicatorType = StringIndicatorType::IPAddress;
            es.riskScore = 3.0;
            result.ipAddresses.push_back(str);
        }
    }

    // Registry key
    if (lower.find("hkey_") != std::string::npos ||
        lower.find("\\software\\") != std::string::npos ||
        lower.find("\\currentversion\\run") != std::string::npos) {
        es.indicatorType = StringIndicatorType::RegistryKey;
        es.riskScore = 2.0;
        result.registryPaths.push_back(str);
    }

    // Ransom note keywords
    static const char* ransomKeywords[] = {
        "your files have been encrypted",
        "bitcoin", "btc wallet",
        "decrypt your files",
        "ransom", "pay to",
        ".onion"
    };
    for (const auto* kw : ransomKeywords) {
        if (lower.find(kw) != std::string::npos) {
            es.indicatorType = StringIndicatorType::RansomNote;
            es.riskScore = 5.0;
            result.hasRansomNotePatterns = true;
            break;
        }
    }

    // Suspicious API name (in binary strings)
    static const char* suspApis[] = {
        "createremotethread", "writeprocessmemory",
        "virtualallocex", "ntcreatethreadex",
        "setwindowshookex"
    };
    for (const auto* api : suspApis) {
        if (lower == api) {
            es.indicatorType = StringIndicatorType::SuspiciousAPI;
            es.riskScore = 2.0;
            result.suspiciousAPIs.push_back(str);
            result.suspiciousCount++;
            break;
        }
    }

    if (es.indicatorType != StringIndicatorType::None) {
        result.indicatorStrings.push_back(std::move(es));
        result.riskScore += es.riskScore;
    }
}

// Trampoline so AnalyzeStrings can call the free function
// We can't add a new member to the class, so we use a static wrapper
// that AnalyzeStrings is already calling via the name below.

// ============================================================================
// Utility Functions (namespace-level, declared in header)
// ============================================================================

double CalculateFileEntropy(const std::wstring& filePath) noexcept {
    try {
        std::vector<std::byte> raw;
        if (!Utils::FileUtils::ReadAllBytes(filePath, raw) || raw.empty()) return 0.0;
        std::span<const uint8_t> data(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
        return HeuristicAnalyzer::Instance().CalculateEntropy(data);
    } catch (...) { return 0.0; }
}

bool IsSuspiciousSectionName(const std::string& name) noexcept {
    if (name.empty()) return true;
    // Known packer/suspicious names
    static const char* suspicious[] = {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata",
        ".FSG", ".vmp0", ".vmp1", ".vmp2", ".themida",
        ".enigma", ".petite", "MPRESS", ".nsp0", ".nsp1"
    };
    for (const auto* s : suspicious) {
        if (name == s) return true;
    }
    // Non-ASCII check
    for (char c : name) {
        if (c != 0 && (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7E))
            return true;
    }
    return false;
}

namespace {

// Static lookup table mapping well-known suspicious Windows APIs to their
// behavioural category.  This mirrors Impl::InitializeSuspiciousImports so
// that the free utility functions IsSuspiciousImport/GetAPICategory can
// answer per-name questions without instantiating the analyzer or scanning
// arbitrary buffers.  Keep this list in sync with that initializer.
const std::unordered_map<std::string, SuspiciousAPICategory>& SuspiciousAPILookup() {
    static const std::unordered_map<std::string, SuspiciousAPICategory> table = {
        // Process manipulation
        {"CreateRemoteThread",          SuspiciousAPICategory::ProcessManipulation},
        {"CreateRemoteThreadEx",        SuspiciousAPICategory::ProcessManipulation},
        {"WriteProcessMemory",          SuspiciousAPICategory::ProcessManipulation},
        {"ReadProcessMemory",           SuspiciousAPICategory::ProcessManipulation},
        {"SetThreadContext",            SuspiciousAPICategory::ProcessManipulation},
        // Memory operations
        {"VirtualAllocEx",              SuspiciousAPICategory::MemoryOperations},
        {"VirtualProtectEx",            SuspiciousAPICategory::MemoryOperations},
        {"VirtualProtect",              SuspiciousAPICategory::MemoryOperations},
        {"VirtualAlloc",                SuspiciousAPICategory::MemoryOperations},
        // Code injection
        {"QueueUserAPC",                SuspiciousAPICategory::CodeInjection},
        {"NtQueueApcThread",            SuspiciousAPICategory::CodeInjection},
        {"NtCreateThreadEx",            SuspiciousAPICategory::CodeInjection},
        {"RtlCreateUserThread",         SuspiciousAPICategory::CodeInjection},
        // Dynamic loading
        {"LoadLibraryA",                SuspiciousAPICategory::DynamicCode},
        {"LoadLibraryW",                SuspiciousAPICategory::DynamicCode},
        {"LoadLibraryExA",              SuspiciousAPICategory::DynamicCode},
        {"LoadLibraryExW",              SuspiciousAPICategory::DynamicCode},
        {"GetProcAddress",              SuspiciousAPICategory::DynamicCode},
        // Anti-debug
        {"IsDebuggerPresent",           SuspiciousAPICategory::AntiDebug},
        {"CheckRemoteDebuggerPresent",  SuspiciousAPICategory::AntiDebug},
        {"NtQueryInformationProcess",   SuspiciousAPICategory::AntiDebug},
        {"OutputDebugStringA",          SuspiciousAPICategory::AntiDebug},
        // Registry
        {"RegSetValueExA",              SuspiciousAPICategory::RegistryOperations},
        {"RegSetValueExW",              SuspiciousAPICategory::RegistryOperations},
        {"RegCreateKeyExA",             SuspiciousAPICategory::RegistryOperations},
        {"RegCreateKeyExW",             SuspiciousAPICategory::RegistryOperations},
        // Service operations
        {"CreateServiceA",              SuspiciousAPICategory::ServiceOperations},
        {"CreateServiceW",              SuspiciousAPICategory::ServiceOperations},
        {"ChangeServiceConfigA",        SuspiciousAPICategory::ServiceOperations},
        {"ChangeServiceConfigW",        SuspiciousAPICategory::ServiceOperations},
        // Input capture
        {"SetWindowsHookExA",           SuspiciousAPICategory::InputCapture},
        {"SetWindowsHookExW",           SuspiciousAPICategory::InputCapture},
        {"GetAsyncKeyState",            SuspiciousAPICategory::InputCapture},
        {"GetKeyState",                 SuspiciousAPICategory::InputCapture},
        // Network
        {"InternetOpenA",               SuspiciousAPICategory::NetworkOperations},
        {"InternetOpenW",               SuspiciousAPICategory::NetworkOperations},
        {"InternetConnectA",            SuspiciousAPICategory::NetworkOperations},
        {"InternetConnectW",            SuspiciousAPICategory::NetworkOperations},
        {"HttpSendRequestA",            SuspiciousAPICategory::NetworkOperations},
        {"HttpSendRequestW",            SuspiciousAPICategory::NetworkOperations},
        {"URLDownloadToFileA",          SuspiciousAPICategory::NetworkOperations},
        {"URLDownloadToFileW",          SuspiciousAPICategory::NetworkOperations},
        // Crypto
        {"CryptEncrypt",                SuspiciousAPICategory::CryptoOperations},
        {"CryptDecrypt",                SuspiciousAPICategory::CryptoOperations},
        {"CryptDeriveKey",              SuspiciousAPICategory::CryptoOperations},
        {"CryptGenKey",                 SuspiciousAPICategory::CryptoOperations},
        // Privilege escalation
        {"AdjustTokenPrivileges",       SuspiciousAPICategory::PrivilegeEscalation},
        {"OpenProcessToken",            SuspiciousAPICategory::PrivilegeEscalation},
        {"ImpersonateLoggedOnUser",     SuspiciousAPICategory::PrivilegeEscalation},
        // Screen capture
        {"BitBlt",                      SuspiciousAPICategory::ScreenCapture},
        {"GetDC",                       SuspiciousAPICategory::ScreenCapture},
        // Credential access
        {"CredReadA",                   SuspiciousAPICategory::CredentialAccess},
        {"CredReadW",                   SuspiciousAPICategory::CredentialAccess},
        // Shell
        {"ShellExecuteA",               SuspiciousAPICategory::Shell},
        {"ShellExecuteW",               SuspiciousAPICategory::Shell},
        {"ShellExecuteExA",             SuspiciousAPICategory::Shell},
        {"ShellExecuteExW",             SuspiciousAPICategory::Shell},
        // COM
        {"CoCreateInstance",            SuspiciousAPICategory::COM},
    };
    return table;
}

} // namespace

bool IsSuspiciousImport(const std::string& /*dllName*/, const std::string& funcName) noexcept {
    if (funcName.empty()) return false;
    const auto& table = SuspiciousAPILookup();
    return table.find(funcName) != table.end();
}

SuspiciousAPICategory GetAPICategory(const std::string& funcName) noexcept {
    if (funcName.empty()) return SuspiciousAPICategory::None;
    const auto& table = SuspiciousAPILookup();
    auto it = table.find(funcName);
    return it != table.end() ? it->second : SuspiciousAPICategory::None;
}

bool IsPotentialIOC(const std::string& str) noexcept {
    if (str.size() < 4) return false;
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower.find("http") != std::string::npos ||
           lower.find("hkey_") != std::string::npos ||
           lower.find(".onion") != std::string::npos;
}

std::vector<std::string> ExtractURLs(const std::string& str) noexcept {
    std::vector<std::string> urls;
    try {
        size_t pos = 0;
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        while ((pos = lower.find("http", pos)) != std::string::npos && urls.size() < 100) {
            size_t end = str.find_first_of(" \t\r\n'\">;)", pos);
            if (end == std::string::npos) end = str.size();
            urls.push_back(str.substr(pos, end - pos));
            pos = end;
        }
    } catch (...) {}
    return urls;
}

std::vector<std::string> ExtractIPs(const std::string& str) noexcept {
    std::vector<std::string> ips;
    // Simple extraction: find digit sequences with 3 dots
    try {
        std::string current;
        for (size_t i = 0; i < str.size() && ips.size() < 100; ++i) {
            char c = str[i];
            if (std::isdigit(static_cast<unsigned char>(c)) || c == '.') {
                current += c;
            } else {
                if (!current.empty()) {
                    int dots = 0;
                    bool valid = true;
                    for (char cc : current) { if (cc == '.') dots++; else if (!std::isdigit(static_cast<unsigned char>(cc))) { valid = false; break; } }
                    if (valid && dots == 3 && current.size() >= 7) ips.push_back(current);
                    current.clear();
                }
            }
        }
    } catch (...) {}
    return ips;
}

bool ContainsPE(std::span<const uint8_t> data) noexcept {
    if (data.size() < 2) return false;
    for (size_t i = 0; i + sizeof(IMAGE_DOS_HEADER) <= data.size(); ++i) {
        if (data[i] == 'M' && data[i + 1] == 'Z') {
            auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data() + i);
            auto off = static_cast<size_t>(dos->e_lfanew);
            if (i + off + 4 <= data.size()) {
                auto sig = *reinterpret_cast<const DWORD*>(data.data() + i + off);
                if (sig == IMAGE_NT_SIGNATURE) return true;
            }
        }
    }
    return false;
}

bool LooksLikeShellcode(std::span<const uint8_t> data) noexcept {
    if (data.size() < 16) return false;
    // Heuristic: NOP sled followed by code
    size_t nops = 0;
    for (size_t i = 0; i < std::min<size_t>(data.size(), 256); ++i) {
        if (data[i] == 0x90) nops++;
    }
    return nops > 8;
}

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike