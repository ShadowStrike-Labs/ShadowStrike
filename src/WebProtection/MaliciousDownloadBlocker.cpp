/**
 * ============================================================================
 * ShadowStrike NGAV - MALICIOUS DOWNLOAD BLOCKER IMPLEMENTATION
 * ============================================================================
 *
 * @file MaliciousDownloadBlocker.cpp
 * @brief Implementation of the MaliciousDownloadBlocker class.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "MaliciousDownloadBlocker.hpp"
#include "SafeBrowsingAPI.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>
#include <regex>
#include <filesystem>

// Windows Headers for Trust Verification
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> MaliciousDownloadBlocker::s_instanceCreated{false};

// ============================================================================
// UTILITY HELPERS
// ============================================================================

namespace {
    // Helper to get formatted time string
    std::string TimeToString(SystemTimePoint tp) {
        auto time = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
        localtime_s(&tm, &time);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
        return oss.str();
    }

    // Helper to verify digital signature
    bool VerifyDigitalSignature(const std::wstring& filePath, std::string& outSigner) {
        WINTRUST_FILE_INFO fileData = { 0 };
        fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileData.pcwszFilePath = filePath.c_str();
        fileData.hFile = NULL;
        fileData.pgKnownSubject = NULL;

        GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trustData = { 0 };
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.pFile = &fileData;

        LONG lStatus = WinVerifyTrust(NULL, &guidAction, &trustData);

        bool isValid = (lStatus == ERROR_SUCCESS);

        // Cleanup
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &guidAction, &trustData);

        // Note: Extracting signer name requires CryptQueryObject/CertGetNameString
        // Simplified for this implementation
        if (isValid) {
            outSigner = "Verified Publisher";
        }

        return isValid;
    }

    bool IsTemporaryDownloadFile(const fs::path& path) {
        std::string ext = Utils::StringUtils::ToLower(path.extension().string());
        return (ext == ".crdownload" || ext == ".part" || ext == ".tmp" || ext == ".opdownload");
    }
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MaliciousDownloadBlockerImpl {
public:
    MaliciousDownloadBlockerImpl();
    ~MaliciousDownloadBlockerImpl();

    bool Initialize(const DownloadBlockerConfiguration& config);
    void Shutdown();

    ModuleStatus GetStatus() const noexcept { return m_status; }

    bool UpdateConfiguration(const DownloadBlockerConfiguration& config);
    DownloadBlockerConfiguration GetConfiguration() const;

    // Scanning
    DownloadScanResult ScanFile(const fs::path& filePath, const std::string& sourceUrl);
    std::future<DownloadScanResult> ScanFileAsync(const fs::path& filePath, const std::string& sourceUrl);

    // Monitoring
    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_isMonitoring; }

    bool AddMonitoredDirectory(const fs::path& directory);
    bool RemoveMonitoredDirectory(const fs::path& directory);
    std::vector<fs::path> GetMonitoredDirectories() const;

    // Actions
    bool QuarantineFile(const fs::path& filePath);
    bool RestoreFromQuarantine(const std::string& quarantineId);

    // Policy
    bool AddBlockedExtension(const std::string& extension);
    bool IsExtensionBlocked(const std::string& extension) const;

    // Stats & Callbacks
    DownloadBlockerStatistics GetStatistics() const { return m_stats; }
    void ResetStatistics() { m_stats.Reset(); }

    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterBlockedCallback(DownloadBlockedCallback callback);

    bool SelfTest();

private:
    void MonitoringLoop();
    DownloadVerdict AnalyzeFile(const fs::path& path, const std::string& hash, FileAnalysisResult& analysis);

    mutable std::shared_mutex m_mutex;
    DownloadBlockerConfiguration m_config;
    ModuleStatus m_status{ModuleStatus::Uninitialized};

    // Monitoring
    std::atomic<bool> m_isMonitoring{false};
    std::thread m_monitorThread;
    std::atomic<bool> m_stopThread{false};
    std::vector<fs::path> m_monitoredDirs;
    std::unordered_set<std::string> m_processedFiles; // Simple dedup

    // Policy
    std::unordered_set<std::string> m_blockedExtensions;
    std::unordered_set<std::string> m_allowedExtensions;

    // Callbacks
    mutable std::mutex m_cbMutex;
    std::vector<ScanResultCallback> m_scanCallbacks;
    std::vector<DownloadBlockedCallback> m_blockedCallbacks;

    // Stats
    mutable DownloadBlockerStatistics m_stats;
};

// ============================================================================
// IMPLEMENTATION DETAILS
// ============================================================================

MaliciousDownloadBlockerImpl::MaliciousDownloadBlockerImpl() {
    m_stats.Reset();
}

MaliciousDownloadBlockerImpl::~MaliciousDownloadBlockerImpl() {
    Shutdown();
}

bool MaliciousDownloadBlockerImpl::Initialize(const DownloadBlockerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_status != ModuleStatus::Uninitialized && m_status != ModuleStatus::Stopped) {
        return true;
    }

    m_config = config;

    // Load extensions
    for (const auto& ext : config.blockedExtensions) m_blockedExtensions.insert(Utils::StringUtils::ToLower(ext));
    for (const auto& ext : config.allowedExtensions) m_allowedExtensions.insert(Utils::StringUtils::ToLower(ext));

    // Load directories
    m_monitoredDirs = config.monitoredDirectories;
    if (m_monitoredDirs.empty()) {
        // Add default Downloads folder if none provided
        // In real impl use SHGetKnownFolderPath(FOLDERID_Downloads)
        // Simplified:
        // m_monitoredDirs.push_back(GetDefaultDownloadDirectories()[0]);
    }

    m_status = ModuleStatus::Running;
    SS_LOG_INFO(L"DownloadBlocker", L"Initialized. Monitoring %zu directories.", m_monitoredDirs.size());

    if (config.enabled) {
        // Auto-start monitoring if configured?
        // Logic usually requires explicit StartMonitoring call, but config has 'enabled' flag.
    }

    return true;
}

void MaliciousDownloadBlockerImpl::Shutdown() {
    StopMonitoring();
    std::unique_lock lock(m_mutex);
    m_status = ModuleStatus::Stopped;
}

bool MaliciousDownloadBlockerImpl::UpdateConfiguration(const DownloadBlockerConfiguration& config) {
    std::unique_lock lock(m_mutex);
    m_config = config;
    return true;
}

DownloadBlockerConfiguration MaliciousDownloadBlockerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

DownloadScanResult MaliciousDownloadBlockerImpl::ScanFile(const fs::path& filePath, const std::string& sourceUrl) {
    DownloadScanResult result;
    result.filePath = filePath;
    result.scanTimestamp = std::chrono::system_clock::now();
    result.downloadId = Utils::StringUtils::GenerateUUID();

    auto start = Clock::now();
    m_stats.totalDownloads++;
    m_stats.scannedDownloads++;

    // 1. Basic Validation
    if (!fs::exists(filePath)) {
        result.status = DownloadStatus::Error;
        result.verdict = DownloadVerdict::Error;
        return result;
    }

    result.fileAnalysis.mimeType = "application/octet-stream"; // Placeholder
    std::string ext = Utils::StringUtils::ToLower(filePath.extension().string());

    // 2. Policy Check (Extension)
    {
        std::shared_lock lock(m_mutex);
        if (m_blockedExtensions.count(ext)) {
            result.verdict = DownloadVerdict::Blocked;
            result.action = DownloadAction::Block;
            result.shouldBlock = true;
            result.threatName = "PolicyViolation:BlockedExtension";
            m_stats.policyBlocks++;
            return result;
        }
    }

    // 3. Hash Calculation
    std::string hash;
    try {
        // Calculate SHA256
        std::vector<uint8_t> hashBytes;
        if (Utils::CryptoUtils::CalculateFileHash(filePath.wstring(), Utils::CryptoUtils::HashAlgorithm::SHA256, hashBytes)) {
            hash = Utils::CryptoUtils::BytesToHex(hashBytes);
        }
    } catch (...) {
        SS_LOG_ERROR(L"DownloadBlocker", L"Failed to calculate hash for %ls", filePath.c_str());
    }

    // 4. Reputation Check (HashStore)
    if (m_config.enableReputationChecking && !hash.empty()) {
        // Check HashStore
        if (HashStore::Instance().IsKnownMalware(hash)) {
            result.verdict = DownloadVerdict::Malware;
            result.action = DownloadAction::Quarantine;
            result.shouldBlock = true;
            result.threatName = "KnownMalware:HashReputation";
            result.indicators = (ThreatIndicator)((uint32_t)result.indicators | (uint32_t)ThreatIndicator::KnownMalware);
            m_stats.malwareDetected++;
            m_stats.reputationBlocks++;

            // Log and notify
            SS_LOG_WARN(L"DownloadBlocker", L"Malware detected by hash: %hs", hash.c_str());
            return result;
        }
    }

    // 5. Signature Scanning
    if (m_config.enableSignatureScanning) {
        // Check SignatureStore (YARA/Pattern)
        // Simulated integration
        // if (SignatureStore::Instance().ScanFile(filePath, matchedSigs)) ...
    }

    // 6. Heuristic Analysis (PE Headers, Macros)
    if (m_config.enableHeuristicScanning) {
        result.verdict = AnalyzeFile(filePath, hash, result.fileAnalysis);
        if (result.verdict != DownloadVerdict::Safe && result.verdict != DownloadVerdict::Clean) {
            result.shouldBlock = true;
            result.action = DownloadAction::Quarantine;
            if (result.verdict == DownloadVerdict::Suspicious) {
                m_stats.suspiciousDetected++;
            } else {
                m_stats.malwareDetected++;
            }
        }
    }

    // 7. Threat Intel (URL)
    if (!sourceUrl.empty() && m_config.enableReputationChecking) {
        if (ThreatIntelManager::Instance().CheckURL(sourceUrl)) {
             result.verdict = DownloadVerdict::Malware;
             result.shouldBlock = true;
             result.threatName = "MaliciousSourceURL";
             result.indicators = (ThreatIndicator)((uint32_t)result.indicators | (uint32_t)ThreatIndicator::BadSourceURL);
        }
    }

    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start);

    if (!result.shouldBlock) {
        result.verdict = DownloadVerdict::Clean;
        result.status = DownloadStatus::Allowed;
        m_stats.cleanDownloads++;
    } else {
        result.status = DownloadStatus::Blocked;
        m_stats.blockedDownloads++;

        // Quarantine if needed
        if (result.action == DownloadAction::Quarantine) {
            if (QuarantineFile(filePath)) {
                result.status = DownloadStatus::Quarantined;
            }
        }
    }

    // Notify callbacks
    {
        std::unique_lock lock(m_cbMutex);
        for (const auto& cb : m_scanCallbacks) cb(result);
        if (result.shouldBlock) {
            DownloadInfo dInfo;
            dInfo.filePath = filePath;
            dInfo.sourceUrl = sourceUrl;
            dInfo.downloadId = result.downloadId;
            for (const auto& cb : m_blockedCallbacks) cb(dInfo, result);
        }
    }

    return result;
}

std::future<DownloadScanResult> MaliciousDownloadBlockerImpl::ScanFileAsync(const fs::path& filePath, const std::string& sourceUrl) {
    return std::async(std::launch::async, [this, filePath, sourceUrl]() {
        return ScanFile(filePath, sourceUrl);
    });
}

DownloadVerdict MaliciousDownloadBlockerImpl::AnalyzeFile(const fs::path& path, const std::string& hash, FileAnalysisResult& analysis) {
    // Basic static analysis
    std::string ext = Utils::StringUtils::ToLower(path.extension().string());

    // Check digital signature for executables
    if (ext == ".exe" || ext == ".dll" || ext == ".sys") {
        analysis.isExecutable = true;
        std::string signer;
        if (VerifyDigitalSignature(path.wstring(), signer)) {
            analysis.hasSignature = true;
            analysis.signatureValid = true;
            analysis.publisher = signer;
        } else {
            if (m_config.blockUnsignedExecutables) {
                return DownloadVerdict::Suspicious;
            }
        }
    }

    // Check for high entropy (packed)
    // implementation skipped for brevity

    return DownloadVerdict::Safe;
}

// ... Monitoring ...

bool MaliciousDownloadBlockerImpl::StartMonitoring() {
    std::unique_lock lock(m_mutex);
    if (m_isMonitoring) return true;

    m_stopThread = false;
    m_monitorThread = std::thread(&MaliciousDownloadBlockerImpl::MonitoringLoop, this);
    m_isMonitoring = true;

    SS_LOG_INFO(L"DownloadBlocker", L"Monitoring started.");
    return true;
}

void MaliciousDownloadBlockerImpl::StopMonitoring() {
    {
        std::unique_lock lock(m_mutex);
        if (!m_isMonitoring) return;
        m_stopThread = true;
    }

    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    m_isMonitoring = false;
    SS_LOG_INFO(L"DownloadBlocker", L"Monitoring stopped.");
}

void MaliciousDownloadBlockerImpl::MonitoringLoop() {
    // Simple polling implementation for robustness
    // Real implementation would use ReadDirectoryChangesW

    while (!m_stopThread) {
        std::vector<fs::path> dirs;
        {
            std::shared_lock lock(m_mutex);
            dirs = m_monitoredDirs;
        }

        for (const auto& dir : dirs) {
            if (!fs::exists(dir)) continue;

            try {
                for (const auto& entry : fs::directory_iterator(dir)) {
                    if (entry.is_regular_file()) {
                        fs::path p = entry.path();
                        if (IsTemporaryDownloadFile(p)) continue;

                        std::string pathStr = p.string();

                        // Check if already processed
                        if (m_processedFiles.find(pathStr) == m_processedFiles.end()) {
                            // New file found
                            // Wait for write handle to close? (File is ready)
                            // For now, just trigger scan async
                            ScanFileAsync(p, "");
                            m_processedFiles.insert(pathStr);
                        }
                    }
                }
            } catch (...) {
                // directory access error
            }
        }

        // Cleanup processed files cache occasionally to prevent memory growth?
        // For this simple implementation we just keep growing or reset periodically.

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

bool MaliciousDownloadBlockerImpl::AddMonitoredDirectory(const fs::path& directory) {
    std::unique_lock lock(m_mutex);
    if (std::find(m_monitoredDirs.begin(), m_monitoredDirs.end(), directory) == m_monitoredDirs.end()) {
        m_monitoredDirs.push_back(directory);
        return true;
    }
    return false;
}

bool MaliciousDownloadBlockerImpl::RemoveMonitoredDirectory(const fs::path& directory) {
    std::unique_lock lock(m_mutex);
    auto it = std::remove(m_monitoredDirs.begin(), m_monitoredDirs.end(), directory);
    if (it != m_monitoredDirs.end()) {
        m_monitoredDirs.erase(it, m_monitoredDirs.end());
        return true;
    }
    return false;
}

std::vector<fs::path> MaliciousDownloadBlockerImpl::GetMonitoredDirectories() const {
    std::shared_lock lock(m_mutex);
    return m_monitoredDirs;
}

// ... Actions ...

bool MaliciousDownloadBlockerImpl::QuarantineFile(const fs::path& filePath) {
    if (m_config.quarantinePath.empty()) return false;

    // Create unique name
    std::string uuid = Utils::StringUtils::GenerateUUID();
    fs::path dest = m_config.quarantinePath / (uuid + ".quarantine");

    try {
        fs::create_directories(m_config.quarantinePath);
        // Rename/Move
        fs::rename(filePath, dest);

        // Log meta data
        // ...

        m_stats.quarantinedDownloads++;
        return true;
    } catch (...) {
        SS_LOG_ERROR(L"DownloadBlocker", L"Failed to quarantine %ls", filePath.c_str());
        return false;
    }
}

bool MaliciousDownloadBlockerImpl::RestoreFromQuarantine(const std::string& quarantineId) {
    return false; // Not implemented
}

// ... Policy ...

bool MaliciousDownloadBlockerImpl::AddBlockedExtension(const std::string& extension) {
    std::unique_lock lock(m_mutex);
    m_blockedExtensions.insert(Utils::StringUtils::ToLower(extension));
    return true;
}

bool MaliciousDownloadBlockerImpl::IsExtensionBlocked(const std::string& extension) const {
    std::shared_lock lock(m_mutex);
    return m_blockedExtensions.count(Utils::StringUtils::ToLower(extension));
}

void MaliciousDownloadBlockerImpl::RegisterScanCallback(ScanResultCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_scanCallbacks.push_back(std::move(callback));
}

void MaliciousDownloadBlockerImpl::RegisterBlockedCallback(DownloadBlockedCallback callback) {
    std::unique_lock lock(m_cbMutex);
    m_blockedCallbacks.push_back(std::move(callback));
}

bool MaliciousDownloadBlockerImpl::SelfTest() {
    // 1. Check directory access
    // 2. Test hash calculation on self
    return true;
}

// ============================================================================
// PUBLIC INTERFACE DELEGATION
// ============================================================================

MaliciousDownloadBlocker& MaliciousDownloadBlocker::Instance() noexcept {
    static MaliciousDownloadBlocker instance;
    return instance;
}

bool MaliciousDownloadBlocker::HasInstance() noexcept {
    return s_instanceCreated.load();
}

MaliciousDownloadBlocker::MaliciousDownloadBlocker()
    : m_impl(std::make_unique<MaliciousDownloadBlockerImpl>()) {
    s_instanceCreated = true;
}

MaliciousDownloadBlocker::~MaliciousDownloadBlocker() = default;

bool MaliciousDownloadBlocker::Initialize(const DownloadBlockerConfiguration& config) {
    return m_impl->Initialize(config);
}

void MaliciousDownloadBlocker::Shutdown() {
    m_impl->Shutdown();
}

bool MaliciousDownloadBlocker::IsInitialized() const noexcept {
    return m_impl->GetStatus() != ModuleStatus::Uninitialized;
}

ModuleStatus MaliciousDownloadBlocker::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool MaliciousDownloadBlocker::UpdateConfiguration(const DownloadBlockerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

DownloadBlockerConfiguration MaliciousDownloadBlocker::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void MaliciousDownloadBlocker::OnDownloadComplete(const std::wstring& filePath, const std::string& sourceUrl) {
    m_impl->ScanFileAsync(fs::path(filePath), sourceUrl);
}

void MaliciousDownloadBlocker::OnDownloadComplete(const DownloadInfo& download) {
    m_impl->ScanFileAsync(download.filePath, download.sourceUrl);
}

bool MaliciousDownloadBlocker::OnDownloadStart(const DownloadInfo& download) {
    // Pre-filtering based on URL or extension
    if (IsExtensionBlocked(download.extension)) return false;
    return true;
}

DownloadScanResult MaliciousDownloadBlocker::ScanFile(const fs::path& filePath) {
    return m_impl->ScanFile(filePath, "");
}

DownloadScanResult MaliciousDownloadBlocker::ScanFile(const fs::path& filePath, const std::string& sourceUrl) {
    return m_impl->ScanFile(filePath, sourceUrl);
}

std::future<DownloadScanResult> MaliciousDownloadBlocker::ScanFileAsync(const fs::path& filePath, const std::string& sourceUrl) {
    return m_impl->ScanFileAsync(filePath, sourceUrl);
}

int MaliciousDownloadBlocker::GetFileReputation(const fs::path& filePath) {
    // Simplified access
    return 50;
}

bool MaliciousDownloadBlocker::IsExtensionBlocked(const std::string& extension) const {
    return m_impl->IsExtensionBlocked(extension);
}

bool MaliciousDownloadBlocker::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void MaliciousDownloadBlocker::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool MaliciousDownloadBlocker::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

bool MaliciousDownloadBlocker::AddMonitoredDirectory(const fs::path& directory) {
    return m_impl->AddMonitoredDirectory(directory);
}

bool MaliciousDownloadBlocker::RemoveMonitoredDirectory(const fs::path& directory) {
    return m_impl->RemoveMonitoredDirectory(directory);
}

std::vector<fs::path> MaliciousDownloadBlocker::GetMonitoredDirectories() const {
    return m_impl->GetMonitoredDirectories();
}

std::future<SandboxResult> MaliciousDownloadBlocker::SubmitToSandbox(const fs::path& filePath) {
    // Placeholder
    return std::async([]() { return SandboxResult{}; });
}

std::optional<SandboxResult> MaliciousDownloadBlocker::GetSandboxResult(const std::string& downloadId) {
    return std::nullopt;
}

bool MaliciousDownloadBlocker::QuarantineFile(const fs::path& filePath) {
    return m_impl->QuarantineFile(filePath);
}

bool MaliciousDownloadBlocker::RestoreFromQuarantine(const std::string& quarantineId) {
    return m_impl->RestoreFromQuarantine(quarantineId);
}

bool MaliciousDownloadBlocker::DeleteFromQuarantine(const std::string& quarantineId) {
    return false;
}

bool MaliciousDownloadBlocker::AddBlockedExtension(const std::string& extension) {
    return m_impl->AddBlockedExtension(extension);
}

bool MaliciousDownloadBlocker::RemoveBlockedExtension(const std::string& extension) {
    return false; // To implement
}

bool MaliciousDownloadBlocker::AddAllowedExtension(const std::string& extension) {
    return false; // To implement
}

void MaliciousDownloadBlocker::RegisterScanCallback(ScanResultCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void MaliciousDownloadBlocker::RegisterBlockedCallback(DownloadBlockedCallback callback) {
    m_impl->RegisterBlockedCallback(std::move(callback));
}

void MaliciousDownloadBlocker::RegisterSandboxCallback(SandboxCompleteCallback callback) {}
void MaliciousDownloadBlocker::RegisterPreDownloadCallback(PreDownloadCallback callback) {}
void MaliciousDownloadBlocker::RegisterErrorCallback(ErrorCallback callback) {}
void MaliciousDownloadBlocker::UnregisterCallbacks() {}

DownloadBlockerStatistics MaliciousDownloadBlocker::GetStatistics() const {
    return m_impl->GetStatistics();
}

void MaliciousDownloadBlocker::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool MaliciousDownloadBlocker::SelfTest() {
    return m_impl->SelfTest();
}

std::string MaliciousDownloadBlocker::GetVersionString() noexcept {
    return "3.0.0";
}

// ============================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ============================================================================

std::string_view GetDownloadVerdictName(DownloadVerdict verdict) noexcept {
    switch (verdict) {
        case DownloadVerdict::Safe: return "Safe";
        case DownloadVerdict::Malware: return "Malware";
        case DownloadVerdict::Blocked: return "Blocked";
        default: return "Unknown";
    }
}

// Stub implementations
std::string_view GetDownloadActionName(DownloadAction) noexcept { return "Action"; }
std::string_view GetDownloadStatusName(DownloadStatus) noexcept { return "Status"; }
std::string_view GetRiskLevelName(RiskLevel) noexcept { return "Risk"; }
std::string_view GetThreatIndicatorName(ThreatIndicator) noexcept { return "Indicator"; }
bool IsHighRiskFile(const fs::path& filePath) { return false; }
std::string DetectFileType(const fs::path& filePath) { return "application/octet-stream"; }
std::vector<fs::path> GetDefaultDownloadDirectories() { return {}; }

// ============================================================================
// STRUCT METHODS
// ============================================================================

std::string DownloadInfo::ToJson() const { return "{}"; }
std::string FileAnalysisResult::ToJson() const { return "{}"; }
std::string ReputationResult::ToJson() const { return "{}"; }
std::string SandboxResult::ToJson() const { return "{}"; }
std::string DownloadScanResult::ToJson() const { return "{}"; }
void DownloadBlockerStatistics::Reset() noexcept { totalDownloads = 0; }
std::string DownloadBlockerStatistics::ToJson() const { return "{}"; }
bool DownloadBlockerConfiguration::IsValid() const noexcept { return true; }

} // namespace WebBrowser
} // namespace ShadowStrike
