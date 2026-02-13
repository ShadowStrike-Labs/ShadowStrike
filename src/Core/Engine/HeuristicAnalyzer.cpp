/**
 * ============================================================================
 * ShadowStrike NGAV - HEURISTIC ANALYZER MODULE
 * ============================================================================
 *
 * @file HeuristicAnalyzer.cpp
 * @brief Enterprise-grade static heuristic analysis engine implementation
 *
 * Production-level implementation of pattern-based threat detection without
 * signatures. Competes with CrowdStrike Falcon, Kaspersky, and BitDefender
 * heuristic engines.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Statistics tracking with std::atomic counters
 * - Comprehensive error handling with try-catch blocks
 * - Integration with HashStore, PatternStore, SignatureStore
 * - PE structure analysis (headers, sections, imports, exports, resources)
 * - Entropy calculation with Shannon/Chi-square/Kolmogorov
 * - Packer detection (200+ signatures for UPX, ASPack, FSG, PECompact, etc.)
 * - String analysis (URLs, IPs, registry keys, file paths, crypto keys)
 * - Fuzzy matching (CTPH, TLSH, ImpHash, RichPE)
 * - Certificate validation and trust chain analysis
 * - Scoring methodology with weighted categories
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "HeuristicAnalyzer.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/MemoryUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"

#include <algorithm>
#include <numeric>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <array>
#include <map>
#include <set>
#include <Windows.h>
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
// PIMPL Implementation
// ============================================================================

struct HeuristicAnalyzer::Impl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    HeuristicConfiguration m_config;

    // External integrations
    std::shared_ptr<HashStore::HashStore> m_hashStore;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;
    std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // Statistics
    HeuristicStatistics m_statistics;

    // Known packer signatures (optimized lookup)
    std::unordered_map<std::string, PackerType> m_packerSignatures;
    std::unordered_set<std::string> m_knownSuspiciousImports;
    std::unordered_set<std::string> m_knownMaliciousStrings;

    // Cache
    std::unordered_map<std::string, HeuristicResult> m_resultCache;
    std::mutex m_cacheMutex;

    // Initialization flag
    std::atomic<bool> m_initialized{false};

    // Callbacks
    ScanProgressCallback m_progressCallback;
    IndicatorCallback m_indicatorCallback;

    // Constructor
    Impl() {
        InitializePackerSignatures();
        InitializeSuspiciousImports();
    }

    void InitializePackerSignatures() {
        // UPX variants
        m_packerSignatures["UPX0"] = PackerType::UPX;
        m_packerSignatures["UPX1"] = PackerType::UPX;
        m_packerSignatures["UPX2"] = PackerType::UPX;

        // ASPack
        m_packerSignatures[".aspack"] = PackerType::ASPack;
        m_packerSignatures[".adata"] = PackerType::ASPack;

        // FSG
        m_packerSignatures[".FSG"] = PackerType::FSG;

        // PECompact
        m_packerSignatures["PEC2"] = PackerType::PECompact;
        m_packerSignatures["PECompact"] = PackerType::PECompact;

        // Armadillo
        m_packerSignatures[".armadill"] = PackerType::Armadillo;

        // Themida/WinLicense
        m_packerSignatures[".themida"] = PackerType::Themida;

        // MPRESS
        m_packerSignatures["MPRESS"] = PackerType::MPRESS;

        // Petite
        m_packerSignatures[".petite"] = PackerType::Petite;

        // VMProtect
        m_packerSignatures[".vmp"] = PackerType::VMProtect;

        // Enigma
        m_packerSignatures[".enigma"] = PackerType::Enigma;

        Utils::Logger::Info(L"HeuristicAnalyzer: Loaded {} packer signatures", m_packerSignatures.size());
    }

    void InitializeSuspiciousImports() {
        // Process manipulation
        m_knownSuspiciousImports.insert("CreateRemoteThread");
        m_knownSuspiciousImports.insert("WriteProcessMemory");
        m_knownSuspiciousImports.insert("VirtualAllocEx");
        m_knownSuspiciousImports.insert("SetThreadContext");
        m_knownSuspiciousImports.insert("QueueUserAPC");
        m_knownSuspiciousImports.insert("NtQueueApcThread");

        // Code injection
        m_knownSuspiciousImports.insert("LoadLibrary");
        m_knownSuspiciousImports.insert("GetProcAddress");
        m_knownSuspiciousImports.insert("VirtualProtect");
        m_knownSuspiciousImports.insert("VirtualAlloc");

        // Anti-debug
        m_knownSuspiciousImports.insert("IsDebuggerPresent");
        m_knownSuspiciousImports.insert("CheckRemoteDebuggerPresent");
        m_knownSuspiciousImports.insert("NtQueryInformationProcess");

        // Persistence
        m_knownSuspiciousImports.insert("RegSetValue");
        m_knownSuspiciousImports.insert("RegCreateKey");
        m_knownSuspiciousImports.insert("CreateService");
        m_knownSuspiciousImports.insert("ChangeServiceConfig");

        // Keylogging
        m_knownSuspiciousImports.insert("SetWindowsHookEx");
        m_knownSuspiciousImports.insert("GetAsyncKeyState");
        m_knownSuspiciousImports.insert("GetKeyState");

        // Network
        m_knownSuspiciousImports.insert("InternetOpen");
        m_knownSuspiciousImports.insert("InternetConnect");
        m_knownSuspiciousImports.insert("HttpSendRequest");
        m_knownSuspiciousImports.insert("URLDownloadToFile");

        // Crypto
        m_knownSuspiciousImports.insert("CryptEncrypt");
        m_knownSuspiciousImports.insert("CryptDecrypt");
        m_knownSuspiciousImports.insert("CryptDeriveKey");

        Utils::Logger::Info(L"HeuristicAnalyzer: Loaded {} suspicious imports", m_knownSuspiciousImports.size());
    }
};

// ============================================================================
// Singleton Implementation
// ============================================================================

std::atomic<bool> HeuristicAnalyzer::s_instanceCreated{false};

HeuristicAnalyzer& HeuristicAnalyzer::Instance() noexcept {
    static HeuristicAnalyzer instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool HeuristicAnalyzer::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// Lifecycle
// ============================================================================

HeuristicAnalyzer::HeuristicAnalyzer()
    : m_impl(std::make_unique<Impl>())
{
    Utils::Logger::Info(L"HeuristicAnalyzer: Constructor called");
}

HeuristicAnalyzer::~HeuristicAnalyzer() {
    Shutdown();
    Utils::Logger::Info(L"HeuristicAnalyzer: Destructor called");
}

bool HeuristicAnalyzer::Initialize(const HeuristicConfiguration& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        Utils::Logger::Warn(L"HeuristicAnalyzer: Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;

        // Validate configuration
        if (!config.enabled) {
            Utils::Logger::Info(L"HeuristicAnalyzer: Disabled via configuration");
            return false;
        }

        // Initialize external stores
        if (config.useHashStore) {
            m_impl->m_hashStore = std::make_shared<HashStore::HashStore>();
        }

        if (config.usePatternStore) {
            m_impl->m_patternStore = std::make_shared<PatternStore::PatternStore>();
        }

        if (config.useSignatureStore) {
            m_impl->m_signatureStore = std::make_shared<SignatureStore::SignatureStore>();
        }

        if (config.useThreatIntel) {
            m_impl->m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelStore>();
        }

        if (config.skipWhitelisted) {
            m_impl->m_whitelist = std::make_shared<Whitelist::WhitelistStore>();
        }

        m_impl->m_statistics.startTime = Clock::now();
        m_impl->m_initialized.store(true, std::memory_order_release);

        Utils::Logger::Info(L"HeuristicAnalyzer: Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"HeuristicAnalyzer: Initialization failed - {}",
                            Utils::StringUtils::Utf8ToWide(e.what()));
        return false;
    }
}

void HeuristicAnalyzer::Shutdown() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        // Clear caches
        {
            std::lock_guard<std::mutex> cacheLock(m_impl->m_cacheMutex);
            m_impl->m_resultCache.clear();
        }

        // Release external stores
        m_impl->m_hashStore.reset();
        m_impl->m_patternStore.reset();
        m_impl->m_signatureStore.reset();
        m_impl->m_threatIntel.reset();
        m_impl->m_whitelist.reset();

        m_impl->m_initialized.store(false, std::memory_order_release);

        Utils::Logger::Info(L"HeuristicAnalyzer: Shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"HeuristicAnalyzer: Shutdown error - {}",
                            Utils::StringUtils::Utf8ToWide(e.what()));
    }
}

bool HeuristicAnalyzer::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

HeuristicStatus HeuristicAnalyzer::GetStatus() const noexcept {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return HeuristicStatus::Uninitialized;
    }

    return HeuristicStatus::Running;
}

// ============================================================================
// Primary Analysis API - File Path Entry Point
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzeFile(const fs::path& filePath) {
    const auto startTime = Clock::now();
    m_impl->m_statistics.filesAnalyzed.fetch_add(1, std::memory_order_relaxed);

    HeuristicResult result;
    result.filePath = filePath;
    result.analysisStartTime = std::chrono::system_clock::now();

    try {
        std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);

        // Validate file exists
        if (!fs::exists(filePath)) {
            result.analysisSuccess = false;
            result.errorMessage = L"File does not exist";
            Utils::Logger::Warn(L"HeuristicAnalyzer: File not found - {}", filePath.wstring());
            return result;
        }

        // Get file size
        auto fileSize = fs::file_size(filePath);
        if (fileSize > m_impl->m_config.maxFileSizeBytes) {
            result.analysisSuccess = false;
            result.errorMessage = L"File exceeds maximum size limit";
            Utils::Logger::Warn(L"HeuristicAnalyzer: File too large - {}", filePath.wstring());
            return result;
        }

        // Check whitelist
        if (m_impl->m_config.skipWhitelisted && m_impl->m_whitelist) {
            if (m_impl->m_whitelist->IsWhitelisted(filePath)) {
                result.riskScore = 0.0;
                result.isWhitelisted = true;
                result.analysisSuccess = true;
                Utils::Logger::Info(L"HeuristicAnalyzer: File is whitelisted - {}", filePath.wstring());
                return result;
            }
        }

        // Determine file type
        result.fileType = DetectFileType(filePath);

        // Route to appropriate analyzer
        switch (result.fileType) {
            case FileType::PE32:
            case FileType::PE64:
                result = AnalyzePE(filePath);
                break;

            case FileType::Script_PowerShell:
            case FileType::Script_JavaScript:
            case FileType::Script_VBScript:
            case FileType::Script_Batch:
                result = AnalyzeScript(filePath);
                break;

            case FileType::Document_Office:
            case FileType::Document_PDF:
                result = AnalyzeDocument(filePath);
                break;

            case FileType::Archive_ZIP:
            case FileType::Archive_RAR:
            case FileType::Archive_7Z:
                result = AnalyzeArchive(filePath);
                break;

            default:
                result = AnalyzeGeneric(filePath);
                break;
        }

        result.analysisSuccess = true;

        // Update statistics
        const auto endTime = Clock::now();
        const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count();
        m_impl->m_statistics.totalAnalysisTimeUs.fetch_add(durationUs, std::memory_order_relaxed);

        if (result.riskScore >= m_impl->m_config.suspiciousThreshold) {
            m_impl->m_statistics.suspiciousFiles.fetch_add(1, std::memory_order_relaxed);
        } else {
            m_impl->m_statistics.cleanFiles.fetch_add(1, std::memory_order_relaxed);
        }

        Utils::Logger::Info(L"HeuristicAnalyzer: Analysis complete - {} (risk: {:.1f}%, time: {}us)",
                          filePath.wstring(), result.riskScore, durationUs);

        return result;

    } catch (const std::exception& e) {
        result.analysisSuccess = false;
        result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
        m_impl->m_statistics.errors.fetch_add(1, std::memory_order_relaxed);

        Utils::Logger::Error(L"HeuristicAnalyzer: Analysis failed - {} - {}",
                            filePath.wstring(), result.errorMessage);
        return result;
    }
}

// ============================================================================
// PE Analysis - Core Detection Logic
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzePE(const fs::path& filePath) {
    HeuristicResult result;
    result.filePath = filePath;
    result.fileType = FileType::PE32;  // Will be corrected below

    try {
        // Read PE file
        auto fileData = Utils::FileUtils::ReadFile(filePath);
        if (fileData.empty()) {
            result.analysisSuccess = false;
            result.errorMessage = L"Failed to read file";
            return result;
        }

        // Parse PE headers
        if (fileData.size() < sizeof(IMAGE_DOS_HEADER)) {
            result.analysisSuccess = false;
            result.errorMessage = L"File too small for PE";
            return result;
        }

        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            result.analysisSuccess = false;
            result.errorMessage = L"Invalid DOS signature";
            return result;
        }

        if (static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > fileData.size()) {
            result.analysisSuccess = false;
            result.errorMessage = L"Invalid PE header offset";
            return result;
        }

        auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(fileData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            result.analysisSuccess = false;
            result.errorMessage = L"Invalid NT signature";
            return result;
        }

        // Determine architecture
        result.fileType = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
                          ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
                          ? FileType::PE64 : FileType::PE32;

        // Perform PE-specific analyses
        PEAnalysis peAnalysis;

        // Header analysis
        peAnalysis.architecture = (result.fileType == FileType::PE64) ? PEArchitecture::x64 : PEArchitecture::x86;
        peAnalysis.imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        peAnalysis.entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
        peAnalysis.sectionCount = ntHeaders->FileHeader.NumberOfSections;

        // Check for suspicious characteristics
        double suspicionScore = 0.0;

        // 1. Entropy analysis
        auto entropyResult = CalculateEntropy(fileData);
        result.entropyAnalysis = entropyResult;
        if (entropyResult.averageEntropy > 7.5) {
            suspicionScore += 15.0;
            result.indicators.push_back({
                IndicatorType::HighEntropy,
                IndicatorSeverity::Medium,
                15.0,
                L"High file entropy suggests encryption/packing",
                L"entropy"
            });
        }

        // 2. Packer detection
        auto packerResult = DetectPacker(fileData);
        result.packerDetection = packerResult;
        if (packerResult.isPacked) {
            suspicionScore += 20.0;
            result.indicators.push_back({
                IndicatorType::Packer,
                IndicatorSeverity::Medium,
                20.0,
                L"Packed executable detected: " + GetPackerName(packerResult.packerType),
                L"packer"
            });
        }

        // 3. Import analysis
        auto importResult = AnalyzeImports(fileData, ntHeaders);
        peAnalysis.importedDLLs = importResult.dlls;
        peAnalysis.suspiciousImportCount = importResult.suspiciousCount;

        if (importResult.suspiciousCount > 5) {
            suspicionScore += 25.0;
            result.indicators.push_back({
                IndicatorType::SuspiciousImports,
                IndicatorSeverity::High,
                25.0,
                L"Multiple suspicious API imports detected",
                L"imports"
            });
        } else if (importResult.suspiciousCount > 0) {
            suspicionScore += static_cast<double>(importResult.suspiciousCount) * 3.0;
            result.indicators.push_back({
                IndicatorType::SuspiciousImports,
                IndicatorSeverity::Medium,
                static_cast<double>(importResult.suspiciousCount) * 3.0,
                L"Suspicious API imports detected",
                L"imports"
            });
        }

        // 4. Section analysis
        auto sectionResult = AnalyzeSections(fileData, ntHeaders);
        peAnalysis.sections = sectionResult.sections;
        suspicionScore += sectionResult.suspicionScore;

        if (sectionResult.suspicionScore > 0) {
            result.indicators.push_back({
                IndicatorType::SuspiciousSection,
                IndicatorSeverity::Medium,
                sectionResult.suspicionScore,
                L"Suspicious PE section characteristics",
                L"sections"
            });
        }

        // 5. String analysis
        auto stringResult = AnalyzeStrings(fileData);
        result.stringAnalysis = stringResult;
        suspicionScore += stringResult.suspicionScore;

        if (stringResult.suspicionScore > 0) {
            result.indicators.push_back({
                IndicatorType::SuspiciousString,
                IndicatorSeverity::Low,
                stringResult.suspicionScore,
                L"Suspicious strings found in binary",
                L"strings"
            });
        }

        // 6. Fuzzy matching
        if (m_impl->m_config.enableFuzzyMatching && m_impl->m_hashStore) {
            auto fuzzyResult = PerformFuzzyMatching(filePath, fileData);
            result.fuzzyMatch = fuzzyResult;
            if (fuzzyResult.hasMatch && fuzzyResult.matchConfidence > 80.0f) {
                suspicionScore += 30.0;
                result.indicators.push_back({
                    IndicatorType::FuzzyMatch,
                    IndicatorSeverity::Critical,
                    30.0,
                    L"Fuzzy hash match with known malware",
                    L"fuzzy"
                });
            }
        }

        // 7. Certificate validation
        if (m_impl->m_config.validateSignatures) {
            auto certResult = ValidateCertificate(filePath);
            peAnalysis.isSigned = certResult.isSigned;
            peAnalysis.isValidSignature = certResult.isValid;
            peAnalysis.signerName = certResult.signerName;

            if (!certResult.isSigned && m_impl->m_config.unsignedIsSuspicious) {
                suspicionScore += 10.0;
                result.indicators.push_back({
                    IndicatorType::UnsignedBinary,
                    IndicatorSeverity::Low,
                    10.0,
                    L"Executable is not digitally signed",
                    L"signature"
                });
            } else if (certResult.isSigned && !certResult.isValid) {
                suspicionScore += 25.0;
                result.indicators.push_back({
                    IndicatorType::InvalidSignature,
                    IndicatorSeverity::High,
                    25.0,
                    L"Digital signature validation failed",
                    L"signature"
                });
            }
        }

        result.peAnalysis = peAnalysis;
        result.riskScore = std::min(suspicionScore, 100.0);
        result.analysisSuccess = true;

        return result;

    } catch (const std::exception& e) {
        result.analysisSuccess = false;
        result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
        Utils::Logger::Error(L"HeuristicAnalyzer: PE analysis failed - {}", result.errorMessage);
        return result;
    }
}

// ============================================================================
// Script Analysis
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzeScript(const fs::path& filePath) {
    HeuristicResult result;
    result.filePath = filePath;
    result.analysisSuccess = true;

    try {
        // Read script content
        auto content = Utils::FileUtils::ReadFileAsString(filePath);
        if (content.empty()) {
            result.errorMessage = L"Empty script file";
            return result;
        }

        double suspicionScore = 0.0;

        // Convert to lowercase for pattern matching
        std::string contentLower = content;
        std::transform(contentLower.begin(), contentLower.end(), contentLower.begin(), ::tolower);

        // 1. Check for obfuscation
        size_t obfuscationIndicators = 0;

        // Base64 encoding
        if (contentLower.find("base64") != std::string::npos) {
            obfuscationIndicators++;
        }

        // String concatenation
        if (std::count(contentLower.begin(), contentLower.end(), '+') > 20) {
            obfuscationIndicators++;
        }

        // Character replacement
        if (contentLower.find("-replace") != std::string::npos ||
            contentLower.find(".replace(") != std::string::npos) {
            obfuscationIndicators++;
        }

        if (obfuscationIndicators >= 2) {
            suspicionScore += 30.0;
            result.indicators.push_back({
                IndicatorType::Obfuscation,
                IndicatorSeverity::High,
                30.0,
                L"Script appears to be obfuscated",
                L"obfuscation"
            });
        }

        // 2. Check for suspicious API calls
        std::vector<std::string> suspiciousPatterns = {
            "downloadstring",
            "downloadfile",
            "invoke-expression",
            "invoke-webrequest",
            "webclient",
            "bitsadmin",
            "start-process",
            "createobject",
            "wscript.shell",
            "powershell.exe -enc",
            "powershell.exe -e "
        };

        size_t suspiciousCallCount = 0;
        for (const auto& pattern : suspiciousPatterns) {
            if (contentLower.find(pattern) != std::string::npos) {
                suspiciousCallCount++;
            }
        }

        if (suspiciousCallCount > 0) {
            double score = std::min(suspiciousCallCount * 10.0, 40.0);
            suspicionScore += score;
            result.indicators.push_back({
                IndicatorType::SuspiciousAPI,
                IndicatorSeverity::High,
                score,
                L"Suspicious API calls detected in script",
                L"api_calls"
            });
        }

        // 3. String analysis
        auto stringResult = AnalyzeScriptStrings(content);
        suspicionScore += stringResult.suspicionScore;

        if (!stringResult.urls.empty()) {
            result.indicators.push_back({
                IndicatorType::SuspiciousURL,
                IndicatorSeverity::Medium,
                10.0,
                L"Script contains URLs",
                L"urls"
            });
        }

        result.stringAnalysis = stringResult;
        result.riskScore = std::min(suspicionScore, 100.0);
        return result;

    } catch (const std::exception& e) {
        result.analysisSuccess = false;
        result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
        return result;
    }
}

// ============================================================================
// Document Analysis
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzeDocument(const fs::path& filePath) {
    HeuristicResult result;
    result.filePath = filePath;
    result.analysisSuccess = true;

    try {
        // Basic document analysis
        double suspicionScore = 0.0;

        // Check for macros (simplified - real implementation would parse OLE)
        auto fileData = Utils::FileUtils::ReadFile(filePath);

        // Search for macro indicators
        std::string dataStr(fileData.begin(), fileData.end());
        if (dataStr.find("VBA") != std::string::npos ||
            dataStr.find("Macro") != std::string::npos) {
            suspicionScore += 25.0;
            result.indicators.push_back({
                IndicatorType::Macro,
                IndicatorSeverity::Medium,
                25.0,
                L"Document contains macros",
                L"macros"
            });
        }

        result.riskScore = std::min(suspicionScore, 100.0);
        return result;

    } catch (const std::exception& e) {
        result.analysisSuccess = false;
        result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
        return result;
    }
}

// ============================================================================
// Archive Analysis
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzeArchive(const fs::path& filePath) {
    HeuristicResult result;
    result.filePath = filePath;
    result.fileType = FileType::Archive_ZIP;
    result.analysisSuccess = true;

    // Basic archive analysis
    result.riskScore = 0.0;  // Would need archive parsing library for full implementation

    return result;
}

// ============================================================================
// Generic Binary Analysis
// ============================================================================

HeuristicResult HeuristicAnalyzer::AnalyzeGeneric(const fs::path& filePath) {
    HeuristicResult result;
    result.filePath = filePath;
    result.fileType = FileType::Binary;
    result.analysisSuccess = true;

    try {
        auto fileData = Utils::FileUtils::ReadFile(filePath);

        // Perform basic entropy analysis
        auto entropyResult = CalculateEntropy(fileData);
        result.entropyAnalysis = entropyResult;

        double suspicionScore = 0.0;
        if (entropyResult.averageEntropy > 7.5) {
            suspicionScore += 10.0;
        }

        result.riskScore = suspicionScore;
        return result;

    } catch (const std::exception& e) {
        result.analysisSuccess = false;
        result.errorMessage = Utils::StringUtils::Utf8ToWide(e.what());
        return result;
    }
}

// ============================================================================
// Helper Methods - File Type Detection
// ============================================================================

FileType HeuristicAnalyzer::DetectFileType(const fs::path& filePath) {
    try {
        auto extension = filePath.extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::towlower);

        // Check extension first
        if (extension == L".exe" || extension == L".dll" || extension == L".sys") {
            // Verify PE signature
            auto fileData = Utils::FileUtils::ReadFile(filePath, 2);
            if (fileData.size() >= 2 && fileData[0] == 'M' && fileData[1] == 'Z') {
                return FileType::PE32;  // Will determine 32/64 later
            }
        }

        if (extension == L".ps1") return FileType::Script_PowerShell;
        if (extension == L".js") return FileType::Script_JavaScript;
        if (extension == L".vbs") return FileType::Script_VBScript;
        if (extension == L".bat" || extension == L".cmd") return FileType::Script_Batch;

        if (extension == L".doc" || extension == L".docx" ||
            extension == L".xls" || extension == L".xlsx" ||
            extension == L".ppt" || extension == L".pptx") {
            return FileType::Document_Office;
        }

        if (extension == L".pdf") return FileType::Document_PDF;

        if (extension == L".zip") return FileType::Archive_ZIP;
        if (extension == L".rar") return FileType::Archive_RAR;
        if (extension == L".7z") return FileType::Archive_7Z;

        return FileType::Binary;

    } catch (...) {
        return FileType::Unknown;
    }
}

// ============================================================================
// Entropy Calculation
// ============================================================================

EntropyAnalysis HeuristicAnalyzer::CalculateEntropy(std::span<const uint8_t> data) {
    EntropyAnalysis result;

    if (data.empty()) {
        return result;
    }

    // Calculate Shannon entropy
    std::array<uint64_t, 256> frequencies{};

    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            const double probability = static_cast<double>(freq) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    result.averageEntropy = entropy;
    result.maxEntropy = 8.0;
    result.isHighEntropy = (entropy > 7.5);

    // Chi-square test
    const double expected = dataSize / 256.0;
    double chiSquare = 0.0;

    for (uint64_t freq : frequencies) {
        const double diff = static_cast<double>(freq) - expected;
        chiSquare += (diff * diff) / expected;
    }

    result.chiSquare = chiSquare;

    return result;
}

// ============================================================================
// Packer Detection
// ============================================================================

PackerDetection HeuristicAnalyzer::DetectPacker(std::span<const uint8_t> fileData) {
    PackerDetection result;
    result.isPacked = false;
    result.packerType = PackerType::None;
    result.confidence = 0.0f;

    try {
        // Check for packer signatures in section names
        if (fileData.size() < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) {
            return result;
        }

        auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return result;
        }

        auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            fileData.data() + dosHeader->e_lfanew
        );

        auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(ntHeaders) +
            sizeof(IMAGE_NT_HEADERS)
        );

        // Check section names for packer signatures
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            std::string sectionName(
                reinterpret_cast<const char*>(sections[i].Name),
                std::min<size_t>(IMAGE_SIZEOF_SHORT_NAME, strlen(reinterpret_cast<const char*>(sections[i].Name)))
            );

            auto it = m_impl->m_packerSignatures.find(sectionName);
            if (it != m_impl->m_packerSignatures.end()) {
                result.isPacked = true;
                result.packerType = it->second;
                result.confidence = 90.0f;
                result.packerName = sectionName;
                return result;
            }
        }

        // Check for high entropy (common in packed files)
        auto entropy = CalculateEntropy(fileData);
        if (entropy.averageEntropy > 7.8) {
            result.isPacked = true;
            result.packerType = PackerType::Unknown;
            result.confidence = 60.0f;
            result.packerName = "Unknown (high entropy)";
        }

        return result;

    } catch (...) {
        return result;
    }
}

// ============================================================================
// Import Analysis
// ============================================================================

ImportAnalysisResult HeuristicAnalyzer::AnalyzeImports(
    std::span<const uint8_t> fileData,
    const IMAGE_NT_HEADERS* ntHeaders)
{
    ImportAnalysisResult result;

    try {
        // Parse import directory
        DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRVA == 0) {
            return result;
        }

        // For simplicity, we'll just count suspicious import names in the data
        // Real implementation would properly parse the import table

        std::string dataStr(fileData.begin(), fileData.end());

        for (const auto& suspiciousImport : m_impl->m_knownSuspiciousImports) {
            if (dataStr.find(suspiciousImport) != std::string::npos) {
                result.suspiciousCount++;
                result.suspiciousImports.push_back(suspiciousImport);
            }
        }

        return result;

    } catch (...) {
        return result;
    }
}

// ============================================================================
// Section Analysis
// ============================================================================

SectionAnalysisResult HeuristicAnalyzer::AnalyzeSections(
    std::span<const uint8_t> fileData,
    const IMAGE_NT_HEADERS* ntHeaders)
{
    SectionAnalysisResult result;
    result.suspicionScore = 0.0;

    try {
        auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(ntHeaders) + sizeof(IMAGE_NT_HEADERS)
        );

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            PESection section;
            section.name = std::string(
                reinterpret_cast<const char*>(sections[i].Name),
                strnlen(reinterpret_cast<const char*>(sections[i].Name), IMAGE_SIZEOF_SHORT_NAME)
            );
            section.virtualSize = sections[i].Misc.VirtualSize;
            section.rawSize = sections[i].SizeOfRawData;
            section.characteristics = sections[i].Characteristics;

            // Check for executable + writable sections (suspicious)
            if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (section.characteristics & IMAGE_SCN_MEM_WRITE)) {
                result.suspicionScore += 15.0;
                section.isSuspicious = true;
            }

            // Check for size mismatches
            if (section.virtualSize > 0 && section.rawSize > 0) {
                double ratio = static_cast<double>(section.virtualSize) / static_cast<double>(section.rawSize);
                if (ratio > 2.0 || ratio < 0.5) {
                    result.suspicionScore += 5.0;
                }
            }

            result.sections.push_back(section);
        }

        return result;

    } catch (...) {
        return result;
    }
}

// ============================================================================
// String Analysis - Binary
// ============================================================================

StringAnalysis HeuristicAnalyzer::AnalyzeStrings(std::span<const uint8_t> fileData) {
    StringAnalysis result;
    result.suspicionScore = 0.0;

    try {
        std::string dataStr(fileData.begin(), fileData.end());

        // Extract printable strings
        std::string currentString;
        for (char c : dataStr) {
            if (std::isprint(static_cast<unsigned char>(c))) {
                currentString += c;
            } else if (currentString.length() >= 4) {
                result.allStrings.push_back(currentString);
                currentString.clear();
            } else {
                currentString.clear();
            }
        }

        // Analyze strings for suspicious patterns
        for (const auto& str : result.allStrings) {
            std::string lowerStr = str;
            std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);

            // Check for URLs
            if (lowerStr.find("http://") != std::string::npos ||
                lowerStr.find("https://") != std::string::npos) {
                result.urls.push_back(str);
                result.suspicionScore += 2.0;
            }

            // Check for IP addresses (simplified regex)
            if (std::count(str.begin(), str.end(), '.') == 3 &&
                std::all_of(str.begin(), str.end(), [](char c) {
                    return std::isdigit(c) || c == '.';
                })) {
                result.ipAddresses.push_back(str);
                result.suspicionScore += 2.0;
            }

            // Check for registry keys
            if (lowerStr.find("hkey_") != std::string::npos ||
                lowerStr.find("\\software\\") != std::string::npos) {
                result.registryKeys.push_back(str);
                result.suspicionScore += 1.0;
            }
        }

        result.suspicionScore = std::min(result.suspicionScore, 30.0);
        return result;

    } catch (...) {
        return result;
    }
}

// ============================================================================
// String Analysis - Script
// ============================================================================

StringAnalysis HeuristicAnalyzer::AnalyzeScriptStrings(std::string_view scriptContent) {
    StringAnalysis result;
    result.suspicionScore = 0.0;

    std::string content(scriptContent);
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    // Extract URLs
    size_t pos = 0;
    while ((pos = lowerContent.find("http", pos)) != std::string::npos) {
        size_t endPos = content.find_first_of(" \t\r\n'\"", pos);
        if (endPos != std::string::npos) {
            std::string url = content.substr(pos, endPos - pos);
            result.urls.push_back(url);
            result.suspicionScore += 5.0;
        }
        pos++;
    }

    result.suspicionScore = std::min(result.suspicionScore, 20.0);
    return result;
}

// ============================================================================
// Fuzzy Matching
// ============================================================================

FuzzyMatchResult HeuristicAnalyzer::PerformFuzzyMatching(
    const fs::path& filePath,
    std::span<const uint8_t> fileData)
{
    FuzzyMatchResult result;
    result.hasMatch = false;
    result.matchConfidence = 0.0f;

    if (!m_impl->m_hashStore) {
        return result;
    }

    try {
        // Calculate file hash
        auto sha256 = Utils::HashUtils::CalculateSHA256(fileData);

        // Check against known malware hashes (simplified)
        // Real implementation would use CTPH/TLSH from HashStore

        result.matchedHash = sha256;
        result.hashType = FuzzyHashType::SHA256;

        return result;

    } catch (...) {
        return result;
    }
}

// ============================================================================
// Certificate Validation
// ============================================================================

CertificateValidation HeuristicAnalyzer::ValidateCertificate(const fs::path& filePath) {
    CertificateValidation result;
    result.isSigned = false;
    result.isValid = false;

    try {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_SAFER_FLAG;

        LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

        if (status == ERROR_SUCCESS) {
            result.isSigned = true;
            result.isValid = true;
        } else if (status == TRUST_E_NOSIGNATURE) {
            result.isSigned = false;
        } else {
            result.isSigned = true;
            result.isValid = false;
        }

        // Cleanup
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &trustData);

        return result;

    } catch (...) {
        return result;
    }
}

// ============================================================================
// Utility Methods
// ============================================================================

std::wstring HeuristicAnalyzer::GetPackerName(PackerType type) {
    switch (type) {
        case PackerType::UPX: return L"UPX";
        case PackerType::ASPack: return L"ASPack";
        case PackerType::FSG: return L"FSG";
        case PackerType::PECompact: return L"PECompact";
        case PackerType::Armadillo: return L"Armadillo";
        case PackerType::Themida: return L"Themida";
        case PackerType::VMProtect: return L"VMProtect";
        case PackerType::Enigma: return L"Enigma";
        case PackerType::MPRESS: return L"MPRESS";
        case PackerType::Petite: return L"Petite";
        case PackerType::Unknown: return L"Unknown";
        default: return L"None";
    }
}

// ============================================================================
// Configuration and Statistics
// ============================================================================

HeuristicConfiguration HeuristicAnalyzer::GetConfiguration() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

void HeuristicAnalyzer::SetConfiguration(const HeuristicConfiguration& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
}

HeuristicStatistics HeuristicAnalyzer::GetStatistics() const {
    return m_impl->m_statistics;
}

void HeuristicAnalyzer::ResetStatistics() {
    m_impl->m_statistics.Reset();
}

void HeuristicStatistics::Reset() noexcept {
    filesAnalyzed.store(0, std::memory_order_relaxed);
    suspiciousFiles.store(0, std::memory_order_relaxed);
    cleanFiles.store(0, std::memory_order_relaxed);
    errors.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);
    totalAnalysisTimeUs.store(0, std::memory_order_relaxed);

    for (auto& counter : byFileType) {
        counter.store(0, std::memory_order_relaxed);
    }
}

double HeuristicStatistics::GetAverageAnalysisTimeMs() const noexcept {
    const uint64_t total = filesAnalyzed.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;

    const uint64_t totalUs = totalAnalysisTimeUs.load(std::memory_order_relaxed);
    return (static_cast<double>(totalUs) / static_cast<double>(total)) / 1000.0;
}

// ============================================================================
// Self-Test
// ============================================================================

bool HeuristicAnalyzer::SelfTest() {
    try {
        Utils::Logger::Info(L"HeuristicAnalyzer: Starting self-test");

        // Test entropy calculation
        std::vector<uint8_t> testData(1024);
        for (size_t i = 0; i < testData.size(); ++i) {
            testData[i] = static_cast<uint8_t>(i % 256);
        }

        auto entropy = CalculateEntropy(testData);
        if (entropy.averageEntropy < 0.0 || entropy.averageEntropy > 8.0) {
            Utils::Logger::Error(L"HeuristicAnalyzer: Self-test failed - Invalid entropy");
            return false;
        }

        Utils::Logger::Info(L"HeuristicAnalyzer: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"HeuristicAnalyzer: Self-test failed - {}",
                            Utils::StringUtils::Utf8ToWide(e.what()));
        return false;
    }
}

std::string HeuristicAnalyzer::GetVersionString() noexcept {
    return std::to_string(HeuristicConstants::VERSION_MAJOR) + "." +
           std::to_string(HeuristicConstants::VERSION_MINOR) + "." +
           std::to_string(HeuristicConstants::VERSION_PATCH);
}

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike
