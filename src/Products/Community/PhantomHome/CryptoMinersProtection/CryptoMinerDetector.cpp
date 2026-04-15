#include "pch.h"
#include "CryptoMinerDetector.hpp"

#include "BrowserMinerDetector.hpp"
#include "CPUUsageAnalyzer.hpp"
#include "GPUMiningDetector.hpp"
#include "PoolConnectionDetector.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"

#include <Psapi.h>
#include <TlHelp32.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#pragma comment(lib, "Psapi.lib")

namespace ShadowStrike {
namespace CryptoMiners {

using SystemClock = std::chrono::system_clock;

namespace {

constexpr size_t kMaxRecentDetections = 1000;
constexpr size_t kMaxSignatureScanBytes = 4 * 1024 * 1024;
constexpr auto kDetectionCooldown = std::chrono::minutes(5);
constexpr auto kMonitorWakeInterval = std::chrono::milliseconds(MinerConstants::RESOURCE_MONITOR_INTERVAL_MS);
constexpr auto kQuickScanInterval = std::chrono::milliseconds(MinerConstants::PROCESS_SCAN_INTERVAL_MS);

const std::array<std::string_view, 30> kCpuMinerNames = {
    "xmrig", "xmrig.exe", "xmr-stak", "xmr-stak.exe", "cgminer", "cgminer.exe",
    "bfgminer", "bfgminer.exe", "cpuminer", "cpuminer.exe", "minerd", "minerd.exe",
    "nheqminer", "nheqminer.exe", "ccminer", "ccminer.exe", "cryptonight", "cryptonight.exe",
    "minergate", "minergate.exe", "stratum", "stratum.exe", "miner", "miner.exe",
    "xmr", "xmr.exe", "monero", "monero.exe", "randomx", "randomx.exe"
};

const std::array<std::string_view, 29> kGpuMinerNames = {
    "phoenixminer", "phoenixminer.exe", "t-rex", "t-rex.exe", "lolminer", "lolminer.exe",
    "ethminer", "ethminer.exe", "claymore", "claymore.exe", "nbminer", "nbminer.exe",
    "teamredminer", "teamredminer.exe", "gminer", "gminer.exe", "nanominer", "nanominer.exe",
    "bminer", "bminer.exe", "trex", "excavator", "excavator.exe", "kawpowminer",
    "kawpowminer.exe", "rhminer", "rhminer.exe", "wildrig", "wildrig.exe"
};

const std::array<std::string_view, 16> kSuspiciousCommandPatterns = {
    "--donate-level", "--pool", "--url", "--wallet", "--user", "--pass", "--algo", "--coin",
    "stratum+tcp://", "stratum+ssl://", "mining.subscribe", "mining.authorize", "randomx",
    "cryptonight", "ethash", "kawpow"
};

const std::array<std::string_view, 32> kMiningPoolDomains = {
    "supportxmr.com", "nanopool.org", "minexmr.com", "monerohash.com", "xmrpool.eu",
    "monero.crypto-pool.fr", "ethermine.org", "2miners.com", "f2pool.com", "hiveon.net",
    "ezil.me", "flexpool.io", "nicehash.com", "pool.hashvault.pro", "mining-pool.eu",
    "zpool.ca", "prohashing.com", "miningpoolhub.com", "slushpool.com", "antpool.com",
    "btc.com", "viabtc.com", "poolin.com", "ravenminer.com", "minermore.com",
    "flypool.org", "moneroocean.stream", "c3pool.com", "hashvault.pro", "woolypooly.com",
    "herominers.com", "pool.supportxmr.com"
};

const std::array<std::string_view, 18> kSignatureMarkers = {
    "xmrig", "xmrig-proxy", "randomx", "cryptonight", "stratum+tcp", "stratum+ssl",
    "mining.subscribe", "mining.authorize", "mining.submit", "ethash", "etchash", "kawpow",
    "phoenixminer", "teamredminer", "nbminer", "lolminer", "coinhive", "cryptoloot"
};

struct UniqueHandle {
    HANDLE handle{nullptr};

    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE value) noexcept : handle(value) {}
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle(other.handle) {
        other.handle = nullptr;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            handle = other.handle;
            other.handle = nullptr;
        }
        return *this;
    }

    ~UniqueHandle() {
        Reset();
    }

    void Reset(HANDLE value = nullptr) noexcept {
        if (handle && handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(handle);
        }
        handle = value;
    }

    [[nodiscard]] HANDLE Get() const noexcept {
        return handle;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return handle && handle != INVALID_HANDLE_VALUE;
    }
};

[[nodiscard]] uint64_t ToUnixMillis(const SystemTimePoint& timePoint) {
    if (timePoint == SystemTimePoint{}) {
        return 0;
    }

    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        timePoint.time_since_epoch()).count());
}

[[nodiscard]] std::wstring ToLowerWide(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return value;
}

[[nodiscard]] std::string ToLowerUtf8(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

[[nodiscard]] std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = ::WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

[[nodiscard]] std::wstring Utf8ToWide(std::string_view value) {
    if (value.empty()) {
        return {};
    }

    const int size = ::MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        return {};
    }

    std::wstring result(static_cast<size_t>(size), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

[[nodiscard]] std::string TrimAndNormalizeHost(std::string host) {
    host = ToLowerUtf8(std::move(host));
    host.erase(std::remove_if(host.begin(), host.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }), host.end());
    while (!host.empty() && host.back() == '.') {
        host.pop_back();
    }
    return host;
}

[[nodiscard]] std::string HashToHex(const Hash256& hash) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : hash) {
        stream << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return stream.str();
}

[[nodiscard]] bool EndsWithPathComponent(std::wstring_view path, std::wstring_view component) {
    const auto normalizedPath = ToLowerWide(std::wstring(path));
    const auto normalizedComponent = ToLowerWide(std::wstring(component));
    if (normalizedPath.size() < normalizedComponent.size()) {
        return false;
    }
    return normalizedPath.rfind(normalizedComponent) != std::wstring::npos;
}

[[nodiscard]] bool IsSuspiciousExecutableName(const std::wstring& processName) {
    const auto lower = ToLowerUtf8(WideToUtf8(ToLowerWide(processName)));
    return std::any_of(kCpuMinerNames.begin(), kCpuMinerNames.end(), [&](std::string_view value) {
        return lower.find(value) != std::string::npos;
    }) || std::any_of(kGpuMinerNames.begin(), kGpuMinerNames.end(), [&](std::string_view value) {
        return lower.find(value) != std::string::npos;
    });
}

[[nodiscard]] bool IsLikelyMinerCommandLine(const std::wstring& commandLine) {
    const auto lower = ToLowerUtf8(WideToUtf8(ToLowerWide(commandLine)));
    size_t matches = 0;
    for (const auto marker : kSuspiciousCommandPatterns) {
        if (lower.find(marker) != std::string::npos) {
            ++matches;
            if (matches >= 2) {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] std::optional<std::wstring> QueryProcessImagePath(uint32_t pid) {
    UniqueHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!process) {
        return std::nullopt;
    }

    std::wstring buffer(MAX_PATH, L'\0');
    DWORD length = static_cast<DWORD>(buffer.size());
    while (!::QueryFullProcessImageNameW(process.Get(), 0, buffer.data(), &length)) {
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || buffer.size() >= 32768) {
            return std::nullopt;
        }
        buffer.resize(buffer.size() * 2, L'\0');
        length = static_cast<DWORD>(buffer.size());
    }

    buffer.resize(length);
    return buffer;
}

[[nodiscard]] std::optional<std::wstring> QueryProcessCommandLine(uint32_t pid) {
    if (const auto commandLine = Utils::ProcessUtils::GetProcessCommandLine(pid); commandLine.has_value()) {
        return commandLine;
    }
    return std::nullopt;
}

[[nodiscard]] bool QueryProcessMemoryStats(uint32_t pid, PROCESS_MEMORY_COUNTERS_EX& counters) {
    ZeroMemory(&counters, sizeof(counters));
    counters.cb = sizeof(counters);

    UniqueHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!process) {
        return false;
    }

    return ::GetProcessMemoryInfo(process.Get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)) != FALSE;
}

[[nodiscard]] bool QueryIs64BitProcess(uint32_t pid) {
    UniqueHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process) {
        return false;
    }

    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const auto isWow64Process2 = reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kernel32, "IsWow64Process2"));
    if (isWow64Process2 && isWow64Process2(process.Get(), &processMachine, &nativeMachine)) {
        return processMachine == IMAGE_FILE_MACHINE_UNKNOWN &&
            (nativeMachine == IMAGE_FILE_MACHINE_AMD64 || nativeMachine == IMAGE_FILE_MACHINE_ARM64);
    }

    BOOL wow64 = FALSE;
    if (::IsWow64Process(process.Get(), &wow64)) {
#if defined(_WIN64)
        return !wow64;
#else
        return false;
#endif
    }

    return false;
}

struct ProcessRecord {
    uint32_t pid{0};
    uint32_t parentPid{0};
    uint32_t threadCount{0};
    std::wstring processName;
};

[[nodiscard]] std::vector<ProcessRecord> EnumerateProcessesSnapshot() {
    std::vector<ProcessRecord> processes;
    UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        return processes;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot.Get(), &entry)) {
        return processes;
    }

    do {
        ProcessRecord record;
        record.pid = entry.th32ProcessID;
        record.parentPid = entry.th32ParentProcessID;
        record.threadCount = entry.cntThreads;
        record.processName = entry.szExeFile;
        processes.push_back(std::move(record));
        if (processes.size() >= MinerConstants::MAX_PROCESS_SCAN) {
            break;
        }
    } while (::Process32NextW(snapshot.Get(), &entry));

    return processes;
}

[[nodiscard]] std::optional<ProcessRecord> FindProcessRecord(uint32_t pid) {
    for (const auto& record : EnumerateProcessesSnapshot()) {
        if (record.pid == pid) {
            return record;
        }
    }
    return std::nullopt;
}

[[nodiscard]] MiningAlgorithm MapSuspectedAlgorithm(SuspectedAlgorithm algorithm) {
    switch (algorithm) {
        case SuspectedAlgorithm::RandomX: return MiningAlgorithm::RandomX;
        case SuspectedAlgorithm::CryptoNight:
        case SuspectedAlgorithm::CryptoNightR: return MiningAlgorithm::CryptoNightR;
        case SuspectedAlgorithm::Scrypt: return MiningAlgorithm::Scrypt;
        case SuspectedAlgorithm::SHA256: return MiningAlgorithm::SHA256;
        default: return MiningAlgorithm::Unknown;
    }
}

[[nodiscard]] MiningAlgorithm MapGpuAlgorithm(GPUMiningAlgorithm algorithm) {
    switch (algorithm) {
        case GPUMiningAlgorithm::Ethash: return MiningAlgorithm::Ethash;
        case GPUMiningAlgorithm::Etchash: return MiningAlgorithm::Etchash;
        case GPUMiningAlgorithm::Kawpow: return MiningAlgorithm::Kawpow;
        case GPUMiningAlgorithm::Autolykos: return MiningAlgorithm::Autolykos;
        case GPUMiningAlgorithm::Equihash: return MiningAlgorithm::Equihash;
        case GPUMiningAlgorithm::ProgPow: return MiningAlgorithm::ProgPow;
        case GPUMiningAlgorithm::CuckooCycle: return MiningAlgorithm::CuckooCycle;
        default: return MiningAlgorithm::Unknown;
    }
}

[[nodiscard]] Cryptocurrency MapPoolCurrency(MinedCryptocurrency currency) {
    switch (currency) {
        case MinedCryptocurrency::Bitcoin: return Cryptocurrency::Bitcoin;
        case MinedCryptocurrency::Ethereum: return Cryptocurrency::Ethereum;
        case MinedCryptocurrency::Monero: return Cryptocurrency::Monero;
        case MinedCryptocurrency::Litecoin: return Cryptocurrency::Litecoin;
        case MinedCryptocurrency::Ravencoin: return Cryptocurrency::Ravencoin;
        case MinedCryptocurrency::Zcash: return Cryptocurrency::Zcash;
        case MinedCryptocurrency::EthClassic: return Cryptocurrency::EthClassic;
        case MinedCryptocurrency::Ergo: return Cryptocurrency::Ergo;
        default: return Cryptocurrency::Unknown;
    }
}

[[nodiscard]] MiningProtocol MapPoolProtocol(PoolProtocolType protocol) {
    switch (protocol) {
        case PoolProtocolType::Stratum: return MiningProtocol::Stratum;
        case PoolProtocolType::StratumV2: return MiningProtocol::StratumV2;
        case PoolProtocolType::NiceHashStratum: return MiningProtocol::NiceHash;
        case PoolProtocolType::EthProxy:
        case PoolProtocolType::EthereumStratum: return MiningProtocol::EthProxy;
        case PoolProtocolType::GetWork: return MiningProtocol::GetWork;
        case PoolProtocolType::GetBlockTemplate: return MiningProtocol::GetBlockTemplate;
        case PoolProtocolType::CryptoNightStratum: return MiningProtocol::CryptoNight;
        default: return MiningProtocol::Unknown;
    }
}

[[nodiscard]] MinerFamily MapBrowserFamily(BrowserMinerFamily family) {
    switch (family) {
        case BrowserMinerFamily::Coinhive: return MinerFamily::Coinhive;
        case BrowserMinerFamily::CryptoLoot: return MinerFamily::CryptoLoot;
        case BrowserMinerFamily::CoinIMP: return MinerFamily::CoinIMP;
        case BrowserMinerFamily::JSECoin: return MinerFamily::JSECoin;
        case BrowserMinerFamily::WebMinePool: return MinerFamily::WebMinePool;
        default: return MinerFamily::Unknown;
    }
}

[[nodiscard]] bool IsSeverityGreater(ThreatSeverity lhs, ThreatSeverity rhs) {
    return static_cast<uint8_t>(lhs) > static_cast<uint8_t>(rhs);
}

[[nodiscard]] size_t DetectionSourceWeight(DetectionSource source) {
    switch (source) {
        case DetectionSource::SignatureBinary:
        case DetectionSource::SignatureMemory:
            return 100;
        case DetectionSource::NetworkStratum:
            return 95;
        case DetectionSource::NetworkPoolIP:
        case DetectionSource::NetworkPoolDomain:
            return 90;
        case DetectionSource::BrowserWASM:
            return 88;
        case DetectionSource::BrowserScript:
            return 85;
        case DetectionSource::GPUHeuristic:
            return 80;
        case DetectionSource::CPUHeuristic:
            return 75;
        case DetectionSource::ProcessBehavior:
            return 60;
        default:
            return 0;
    }
}

[[nodiscard]] std::string BuildDetectionKey(const MinerDetectionResult& result) {
    std::ostringstream stream;
    stream << result.processInfo.processId << ':' << static_cast<int>(result.minerType)
           << ':' << static_cast<int>(result.source) << ':' << static_cast<int>(result.minerFamily)
           << ':' << static_cast<int>(result.algorithm);

    if (result.browserInfo.has_value()) {
        stream << ':' << result.browserInfo->domain << ':' << result.browserInfo->url;
    }

    if (!result.poolAddresses.empty()) {
        stream << ':' << result.poolAddresses.front();
    }

    return stream.str();
}

[[nodiscard]] std::vector<std::string> ReadFileMarkers(const std::wstring& path) {
    std::vector<std::string> matches;
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return matches;
    }

    file.seekg(0, std::ios::end);
    const auto size = static_cast<size_t>(file.tellg());
    if (size == 0) {
        return matches;
    }

    const auto boundedSize = std::min(size, kMaxSignatureScanBytes);
    std::string buffer(boundedSize, '\0');
    file.seekg(0, std::ios::beg);
    file.read(buffer.data(), static_cast<std::streamsize>(boundedSize));
    buffer.resize(static_cast<size_t>(file.gcount()));
    const auto lower = ToLowerUtf8(std::move(buffer));

    for (const auto marker : kSignatureMarkers) {
        if (lower.find(marker) != std::string::npos) {
            matches.emplace_back(marker);
        }
    }

    return matches;
}

[[nodiscard]] std::string_view FirstSignatureMarker(const std::vector<std::string>& markers) {
    return markers.empty() ? std::string_view{} : std::string_view(markers.front());
}

[[nodiscard]] std::optional<size_t> FamilyIndex(MinerFamily family) {
    switch (family) {
        case MinerFamily::XMRig: return 0;
        case MinerFamily::XMRStak: return 1;
        case MinerFamily::CGMiner: return 2;
        case MinerFamily::BFGMiner: return 3;
        case MinerFamily::PhoenixMiner: return 4;
        case MinerFamily::TRexMiner: return 5;
        case MinerFamily::LolMiner: return 6;
        case MinerFamily::Ethminer: return 7;
        case MinerFamily::Claymore: return 8;
        case MinerFamily::NiceHash: return 9;
        case MinerFamily::NBMiner: return 10;
        case MinerFamily::TeamRedMiner: return 11;
        case MinerFamily::GMiner: return 12;
        case MinerFamily::Coinhive: return 13;
        case MinerFamily::CryptoLoot: return 14;
        case MinerFamily::CoinIMP: return 15;
        case MinerFamily::JSECoin: return 16;
        case MinerFamily::WebMinePool: return 17;
        case MinerFamily::Custom: return 18;
        default: return std::nullopt;
    }
}

[[nodiscard]] std::optional<size_t> AlgorithmIndex(MiningAlgorithm algorithm) {
    switch (algorithm) {
        case MiningAlgorithm::SHA256: return 0;
        case MiningAlgorithm::Scrypt: return 1;
        case MiningAlgorithm::Ethash: return 2;
        case MiningAlgorithm::Etchash: return 3;
        case MiningAlgorithm::CryptoNightR: return 4;
        case MiningAlgorithm::RandomX: return 5;
        case MiningAlgorithm::Kawpow: return 6;
        case MiningAlgorithm::Autolykos: return 7;
        case MiningAlgorithm::Equihash: return 8;
        case MiningAlgorithm::CuckooCycle: return 9;
        case MiningAlgorithm::ProgPow: return 10;
        default: return std::nullopt;
    }
}

[[nodiscard]] bool IsPathTransient(const std::wstring& path) {
    const auto lower = ToLowerWide(path);
    return lower.find(L"\\temp\\") != std::wstring::npos ||
        lower.find(L"\\tmp\\") != std::wstring::npos ||
        lower.find(L"\\appdata\\") != std::wstring::npos ||
        lower.find(L"\\programdata\\") != std::wstring::npos;
}

} // namespace

class CryptoMinerDetectorImpl {
public:
    [[nodiscard]] bool Initialize(const CryptoMinerDetectorConfiguration& config);
    void Shutdown();

    [[nodiscard]] bool Start();
    [[nodiscard]] bool Stop();
    void Pause();
    void Resume();
    [[nodiscard]] bool IsRunning() const noexcept;

    [[nodiscard]] MinerDetectionResult ScanProcessInternal(uint32_t processId);
    [[nodiscard]] std::vector<MinerDetectionResult> ScanAllProcessesInternal();
    [[nodiscard]] std::vector<MinerDetectionResult> QuickScanInternal();
    [[nodiscard]] std::vector<BrowserMinerInfo> ScanBrowsersInternal() const;

    [[nodiscard]] bool DetectCPUMining(uint32_t processId, MinerDetectionResult& result) const;
    [[nodiscard]] bool DetectGPUMining(uint32_t processId, MinerDetectionResult& result) const;
    [[nodiscard]] bool DetectNetworkMining(uint32_t processId, MinerDetectionResult& result) const;
    [[nodiscard]] bool DetectBrowserMining(uint32_t processId, MinerDetectionResult& result) const;
    [[nodiscard]] bool DetectSignatureMining(uint32_t processId, MinerDetectionResult& result) const;
    [[nodiscard]] bool DetectBehavioralMining(uint32_t processId, MinerDetectionResult& result) const;

    void AnalyzeSystemResourcesInternal();
    [[nodiscard]] ResourceUsageStats GetResourceUsageInternal() const;
    [[nodiscard]] ResourceUsageStats GetProcessResourceUsageInternal(uint32_t processId) const;

    [[nodiscard]] bool IsMiningPoolInternal(const std::string& host, uint16_t port) const;
    [[nodiscard]] std::optional<MiningPoolInfo> GetPoolInfoInternal(const std::string& host) const;
    [[nodiscard]] std::vector<MinerNetworkConnection> GetActiveMiningConnectionsInternal() const;
    [[nodiscard]] bool LoadPoolBlacklistInternal(const std::filesystem::path& path);
    void AddPoolToBlacklistInternal(const MiningPoolInfo& poolInfo);
    [[nodiscard]] bool BlockPoolConnectionInternal(const std::string& poolAddress);

    [[nodiscard]] bool TerminateMinerInternal(uint32_t processId) const;
    [[nodiscard]] bool QuarantineMinerInternal(uint32_t processId) const;
    [[nodiscard]] bool BlockMinerNetworkInternal(uint32_t processId) const;

    [[nodiscard]] bool IsWhitelistedInternal(uint32_t processId, std::string* reason = nullptr) const;
    void AddToWhitelistInternal(uint32_t processId, const std::string& reason);
    void AddPathToWhitelistInternal(const std::filesystem::path& path, const std::string& reason);
    void RemoveFromWhitelistInternal(uint32_t processId);

    void RegisterDetectionCallback(MinerDetectedCallback callback);
    void RegisterResourceAnomalyCallback(ResourceAnomalyCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    [[nodiscard]] MinerDetectionStatistics GetStatisticsSnapshot() const;
    void ResetStatistics();
    [[nodiscard]] std::vector<MinerDetectionResult> GetRecentDetections(size_t maxCount) const;
    [[nodiscard]] bool SelfTest() const;

    class ActiveOperation final {
    public:
        explicit ActiveOperation(CryptoMinerDetectorImpl& impl) noexcept
            : m_impl(impl), m_acquired(impl.TryBeginOperation()) {}

        ~ActiveOperation() {
            if (m_acquired) {
                m_impl.EndOperation();
            }
        }

        [[nodiscard]] bool Acquired() const noexcept {
            return m_acquired;
        }

    private:
        CryptoMinerDetectorImpl& m_impl;
        bool m_acquired{false};
    };

    [[nodiscard]] bool TryBeginOperation() noexcept;
    void EndOperation() noexcept;

    [[nodiscard]] bool PopulateProcessInfo(uint32_t processId, ProcessMinerInfo& info) const;
    [[nodiscard]] MinerFamily IdentifyMinerFamily(const std::wstring& processName, const std::wstring& commandLine) const;
    [[nodiscard]] MiningAlgorithm DetectAlgorithm(const std::wstring& commandLine) const;
    [[nodiscard]] Cryptocurrency DetectCryptocurrency(const std::wstring& commandLine) const;
    void AggregateResult(MinerDetectionResult& result) const;
    void PublishDetection(MinerDetectionResult& result, bool executeRemediation);
    void PublishResourceAnomaly(const ResourceUsageStats& stats) const;
    void InvokeErrorCallbacks(const std::string& message, int code) const;
    [[nodiscard]] bool ShouldPublishDetection(const MinerDetectionResult& result);
    [[nodiscard]] std::string GenerateDetectionId() const;
    void LoadBuiltinPools();
    void MonitorLoop();
    [[nodiscard]] std::vector<uint32_t> CollectQuickScanTargets() const;

    mutable std::shared_mutex m_stateMutex;
    mutable std::shared_mutex m_detectionsMutex;
    mutable std::shared_mutex m_poolMutex;
    mutable std::shared_mutex m_whitelistMutex;
    mutable std::mutex m_callbackMutex;
    mutable std::mutex m_monitorMutex;
    mutable std::mutex m_cooldownMutex;
    mutable std::mutex m_operationMutex;
    mutable std::condition_variable m_monitorCv;
    mutable std::condition_variable m_operationCv;

    CryptoMinerDetectorConfiguration m_config{};
    MinerDetectionStatistics m_statistics{};
    std::deque<MinerDetectionResult> m_recentDetections;
    std::unordered_map<std::string, MiningPoolInfo> m_poolDatabase;
    std::unordered_map<uint32_t, std::string> m_whitelistedPids;
    std::unordered_map<std::wstring, std::string> m_whitelistedPaths;
    std::unordered_set<std::wstring> m_whitelistedProcessNames;
    std::unordered_set<std::string> m_whitelistedPools;
    std::unordered_map<std::string, TimePoint> m_detectionCooldowns;

    std::vector<MinerDetectedCallback> m_detectionCallbacks;
    std::vector<ResourceAnomalyCallback> m_resourceCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    CPUUsageAnalyzer* m_cpuDetector{nullptr};
    GPUMiningDetector* m_gpuDetector{nullptr};
    BrowserMinerDetector* m_browserDetector{nullptr};
    PoolConnectionDetector* m_poolDetector{nullptr};

    bool m_initializedCpu{false};
    bool m_initializedGpu{false};
    bool m_initializedBrowser{false};
    bool m_initializedPool{false};
    bool m_startedCpu{false};
    bool m_startedGpu{false};
    bool m_startedPool{false};

    std::thread m_monitorThread;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    std::atomic<uint32_t> m_activeOperations{0};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    mutable std::atomic<uint64_t> m_detectionSequence{0};
};

bool CryptoMinerDetectorImpl::Initialize(const CryptoMinerDetectorConfiguration& config) {
    std::unique_lock lock(m_stateMutex);
    if (m_initialized.load(std::memory_order_acquire)) {
        return true;
    }

    if (!config.IsValid()) {
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        InvokeErrorCallbacks("invalid configuration", ERROR_INVALID_PARAMETER);
        return false;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);
    m_config = config;
    m_statistics.Reset();
    m_recentDetections.clear();
    m_poolDatabase.clear();
    m_whitelistedPids.clear();
    m_whitelistedPaths.clear();
    m_whitelistedProcessNames.clear();
    m_whitelistedPools.clear();
    m_detectionCooldowns.clear();

    for (const auto& name : config.whitelistedApplications) {
        m_whitelistedProcessNames.insert(ToLowerWide(name));
    }
    for (const auto& pool : config.whitelistedPools) {
        m_whitelistedPools.insert(TrimAndNormalizeHost(pool));
    }

    LoadBuiltinPools();

    if (!config.poolBlacklistPath.empty()) {
        LoadPoolBlacklistInternal(config.poolBlacklistPath);
    }

    if (config.enableCPUMonitoring) {
        m_cpuDetector = &CPUUsageAnalyzer::Instance();
        if (!m_cpuDetector->IsInitialized()) {
            CPUUsageAnalyzerConfiguration cpuConfig{};
            cpuConfig.highUsageThreshold = config.cpuUsageThreshold;
            cpuConfig.miningThreshold = std::max(0.0, std::min(config.cpuUsageThreshold, 100.0));
            cpuConfig.observationWindowSecs = config.sustainedUsageTriggerSecs;
            cpuConfig.verboseLogging = config.verboseLogging;
            if (!m_cpuDetector->Initialize(cpuConfig)) {
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                InvokeErrorCallbacks("failed to initialize CPUUsageAnalyzer", ERROR_GEN_FAILURE);
                return false;
            }
            m_initializedCpu = true;
        }
    }

    if (config.enableGPUMonitoring) {
        m_gpuDetector = &GPUMiningDetector::Instance();
        if (!m_gpuDetector->IsInitialized()) {
            GPUMiningDetectorConfiguration gpuConfig{};
            gpuConfig.gpuLoadThreshold = config.gpuUsageThreshold;
            gpuConfig.verboseLogging = config.verboseLogging;
            gpuConfig.whitelistedApplications = config.whitelistedApplications;
            if (!m_gpuDetector->Initialize(gpuConfig)) {
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                InvokeErrorCallbacks("failed to initialize GPUMiningDetector", ERROR_GEN_FAILURE);
                return false;
            }
            m_initializedGpu = true;
        }
    }

    if (config.enableBrowserScanning) {
        m_browserDetector = &BrowserMinerDetector::Instance();
        if (!m_browserDetector->IsInitialized()) {
            BrowserMinerDetectorConfiguration browserConfig{};
            browserConfig.blockKnownDomains = config.blockStratumProtocol;
            browserConfig.enableDomainBlocking = config.blockStratumProtocol;
            browserConfig.enableWorkerMonitoring = false;
            browserConfig.terminateMiningWorkers = false;
            browserConfig.verboseLogging = config.verboseLogging;
            if (!m_browserDetector->Initialize(browserConfig)) {
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                InvokeErrorCallbacks("failed to initialize BrowserMinerDetector", ERROR_GEN_FAILURE);
                return false;
            }
            m_initializedBrowser = true;
        }
    }

    if (config.enableNetworkMonitoring) {
        m_poolDetector = &PoolConnectionDetector::Instance();
        if (!m_poolDetector->IsInitialized()) {
            PoolConnectionDetectorConfiguration poolConfig{};
            poolConfig.blockStratumTraffic = config.blockStratumProtocol;
            poolConfig.blockMaliciousPools = config.blockStratumProtocol;
            poolConfig.poolBlacklistPath = config.poolBlacklistPath;
            poolConfig.whitelistedPools = config.whitelistedPools;
            poolConfig.verboseLogging = config.verboseLogging;
            if (!m_poolDetector->Initialize(poolConfig)) {
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                InvokeErrorCallbacks("failed to initialize PoolConnectionDetector", ERROR_GEN_FAILURE);
                return false;
            }
            m_initializedPool = true;
        }
    }

    m_initialized.store(true, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    return true;
}

void CryptoMinerDetectorImpl::Shutdown() {
    Stop();

    std::unique_lock lock(m_stateMutex);
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        m_status.store(ModuleStatus::Uninitialized, std::memory_order_release);
        return;
    }

    lock.unlock();

    {
        std::unique_lock operationsLock(m_operationMutex);
        m_operationCv.wait(operationsLock, [this]() {
            return m_activeOperations.load(std::memory_order_acquire) == 0;
        });
    }

    if (m_initializedPool && m_poolDetector) {
        m_poolDetector->Shutdown();
    }
    if (m_initializedBrowser && m_browserDetector) {
        m_browserDetector->Shutdown();
    }
    if (m_initializedGpu && m_gpuDetector) {
        m_gpuDetector->Shutdown();
    }
    if (m_initializedCpu && m_cpuDetector) {
        m_cpuDetector->Shutdown();
    }

    lock.lock();
    m_cpuDetector = nullptr;
    m_gpuDetector = nullptr;
    m_browserDetector = nullptr;
    m_poolDetector = nullptr;
    m_initializedCpu = false;
    m_initializedGpu = false;
    m_initializedBrowser = false;
    m_initializedPool = false;
    m_startedCpu = false;
    m_startedGpu = false;
    m_startedPool = false;
    m_recentDetections.clear();
    m_poolDatabase.clear();
    m_whitelistedPids.clear();
    m_whitelistedPaths.clear();
    m_whitelistedProcessNames.clear();
    m_whitelistedPools.clear();
    m_detectionCooldowns.clear();
    m_detectionCallbacks.clear();
    m_resourceCallbacks.clear();
    m_errorCallbacks.clear();
    m_status.store(ModuleStatus::Uninitialized, std::memory_order_release);
}

bool CryptoMinerDetectorImpl::Start() {
    std::unique_lock lock(m_stateMutex);
    if (!m_initialized.load(std::memory_order_acquire)) {
        InvokeErrorCallbacks("start requested before initialization", ERROR_INVALID_STATE);
        return false;
    }
    if (m_running.load(std::memory_order_acquire)) {
        return true;
    }

    if (m_cpuDetector && !m_cpuDetector->Start()) {
        InvokeErrorCallbacks("failed to start CPUUsageAnalyzer", ERROR_GEN_FAILURE);
        return false;
    }
    m_startedCpu = m_cpuDetector != nullptr;

    if (m_gpuDetector && !m_gpuDetector->Start()) {
        if (m_startedCpu) {
            m_cpuDetector->Stop();
            m_startedCpu = false;
        }
        InvokeErrorCallbacks("failed to start GPUMiningDetector", ERROR_GEN_FAILURE);
        return false;
    }
    m_startedGpu = m_gpuDetector != nullptr;

    if (m_poolDetector && !m_poolDetector->Start()) {
        if (m_startedGpu) {
            m_gpuDetector->Stop();
            m_startedGpu = false;
        }
        if (m_startedCpu) {
            m_cpuDetector->Stop();
            m_startedCpu = false;
        }
        InvokeErrorCallbacks("failed to start PoolConnectionDetector", ERROR_GEN_FAILURE);
        return false;
    }
    m_startedPool = m_poolDetector != nullptr;

    m_paused.store(false, std::memory_order_release);
    m_running.store(true, std::memory_order_release);
    m_status.store(ModuleStatus::Running, std::memory_order_release);
    m_monitorThread = std::thread(&CryptoMinerDetectorImpl::MonitorLoop, this);
    return true;
}

bool CryptoMinerDetectorImpl::Stop() {
    {
        std::unique_lock lock(m_stateMutex);
        if (!m_running.exchange(false, std::memory_order_acq_rel)) {
            if (m_initialized.load(std::memory_order_acquire)) {
                m_status.store(ModuleStatus::Stopped, std::memory_order_release);
            }
            return true;
        }
        m_paused.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);
    }

    m_monitorCv.notify_all();
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    if (m_startedPool && m_poolDetector) {
        m_poolDetector->Stop();
    }
    if (m_startedGpu && m_gpuDetector) {
        m_gpuDetector->Stop();
    }
    if (m_startedCpu && m_cpuDetector) {
        m_cpuDetector->Stop();
    }

    m_startedCpu = false;
    m_startedGpu = false;
    m_startedPool = false;
    m_status.store(m_initialized.load(std::memory_order_acquire) ? ModuleStatus::Stopped : ModuleStatus::Uninitialized,
        std::memory_order_release);
    return true;
}

void CryptoMinerDetectorImpl::Pause() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }
    m_paused.store(true, std::memory_order_release);
    m_status.store(ModuleStatus::Paused, std::memory_order_release);
}

void CryptoMinerDetectorImpl::Resume() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }
    m_paused.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Running, std::memory_order_release);
    m_monitorCv.notify_all();
}

bool CryptoMinerDetectorImpl::IsRunning() const noexcept {
    return m_running.load(std::memory_order_acquire) && !m_paused.load(std::memory_order_acquire);
}

bool CryptoMinerDetectorImpl::TryBeginOperation() noexcept {
    std::shared_lock lock(m_stateMutex);
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    m_activeOperations.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

void CryptoMinerDetectorImpl::EndOperation() noexcept {
    if (m_activeOperations.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        std::lock_guard lock(m_operationMutex);
        m_operationCv.notify_all();
    }
}

bool CryptoMinerDetectorImpl::PopulateProcessInfo(uint32_t processId, ProcessMinerInfo& info) const {
    info = {};
    info.processId = processId;

    const auto record = FindProcessRecord(processId);
    if (!record.has_value()) {
        return false;
    }

    info.parentPid = record->parentPid;
    info.threadCount = record->threadCount;
    info.processName = record->processName;

    if (const auto imagePath = QueryProcessImagePath(processId); imagePath.has_value()) {
        info.processPath = *imagePath;
    }
    if (const auto commandLine = QueryProcessCommandLine(processId); commandLine.has_value()) {
        info.commandLine = *commandLine;
    }

    info.is64Bit = QueryIs64BitProcess(processId);

    PROCESS_MEMORY_COUNTERS_EX counters{};
    if (QueryProcessMemoryStats(processId, counters)) {
        info.memoryUsage = static_cast<uint64_t>(counters.PrivateUsage);
    }

    return true;
}

MinerDetectionResult CryptoMinerDetectorImpl::ScanProcessInternal(uint32_t processId) {
    MinerDetectionResult result{};
    const auto start = Clock::now();
    result.detectionId = GenerateDetectionId();
    result.detectionTime = SystemClock::now();
    result.processInfo.processId = processId;
    m_statistics.totalScans.fetch_add(1, std::memory_order_relaxed);

    std::string whitelistReason;
    if (IsWhitelistedInternal(processId, &whitelistReason)) {
        result.isWhitelisted = true;
        result.whitelistReason = whitelistReason;
        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        m_statistics.whitelistedPasses.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    if (!PopulateProcessInfo(processId, result.processInfo)) {
        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        return result;
    }

    std::vector<DetectionSource> sources;

    if (m_config.enableCPUMonitoring && DetectCPUMining(processId, result)) {
        sources.push_back(DetectionSource::CPUHeuristic);
        result.isMinerDetected = true;
    }
    if (m_config.enableGPUMonitoring && DetectGPUMining(processId, result)) {
        sources.push_back(DetectionSource::GPUHeuristic);
        result.isMinerDetected = true;
    }
    if (m_config.enableNetworkMonitoring && DetectNetworkMining(processId, result)) {
        const auto primaryNetworkSource = std::any_of(result.networkConnections.begin(), result.networkConnections.end(),
            [](const auto& connection) {
                return connection.protocol == MiningProtocol::Stratum ||
                    connection.protocol == MiningProtocol::StratumV2 ||
                    connection.protocol == MiningProtocol::NiceHash ||
                    connection.protocol == MiningProtocol::CryptoNight;
            }) ? DetectionSource::NetworkStratum : DetectionSource::NetworkPoolDomain;
        sources.push_back(primaryNetworkSource);
        result.isMinerDetected = true;
    }
    if (m_config.enableBrowserScanning && DetectBrowserMining(processId, result)) {
        sources.push_back(result.browserInfo.has_value() && result.browserInfo->isWASM ? DetectionSource::BrowserWASM : DetectionSource::BrowserScript);
        result.isMinerDetected = true;
    }
    if (m_config.enableSignatureScanning && DetectSignatureMining(processId, result)) {
        sources.push_back(DetectionSource::SignatureBinary);
        result.isMinerDetected = true;
    }
    if (m_config.enableBehavioralAnalysis && DetectBehavioralMining(processId, result)) {
        sources.push_back(DetectionSource::ProcessBehavior);
        result.isMinerDetected = true;
    }

    if (result.isMinerDetected) {
        std::sort(sources.begin(), sources.end(), [](DetectionSource lhs, DetectionSource rhs) {
            return DetectionSourceWeight(lhs) > DetectionSourceWeight(rhs);
        });
        sources.erase(std::unique(sources.begin(), sources.end()), sources.end());
        result.source = sources.front();
        result.additionalSources = sources;
        AggregateResult(result);
        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        PublishDetection(result, true);
    }

    if (result.analysisDuration.count() == 0) {
        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
    }
    return result;
}

std::vector<MinerDetectionResult> CryptoMinerDetectorImpl::ScanAllProcessesInternal() {
    std::vector<MinerDetectionResult> detections;
    for (const auto& process : EnumerateProcessesSnapshot()) {
        auto result = ScanProcessInternal(process.pid);
        if (result.isMinerDetected) {
            detections.push_back(std::move(result));
        }
    }
    return detections;
}

std::vector<uint32_t> CryptoMinerDetectorImpl::CollectQuickScanTargets() const {
    std::set<uint32_t> targets;

    if (m_cpuDetector) {
        for (const auto& signature : m_cpuDetector->GetHighCPUProcesses(m_config.cpuUsageThreshold)) {
            if (signature.processId != 0) {
                targets.insert(signature.processId);
            }
        }
    }

    if (m_gpuDetector) {
        for (const auto processId : m_gpuDetector->IdentifyMiningProcesses()) {
            if (processId != 0) {
                targets.insert(processId);
            }
        }
    }

    if (m_poolDetector) {
        for (const auto& connection : m_poolDetector->GetActiveConnections()) {
            if (connection.processId != 0) {
                targets.insert(connection.processId);
            }
        }
    }

    if (m_browserDetector) {
        for (const auto& tab : m_browserDetector->GetMiningTabs()) {
            if (tab.browserPid != 0) {
                targets.insert(tab.browserPid);
            }
        }
    }

    return {targets.begin(), targets.end()};
}

std::vector<MinerDetectionResult> CryptoMinerDetectorImpl::QuickScanInternal() {
    std::vector<MinerDetectionResult> detections;
    for (const auto processId : CollectQuickScanTargets()) {
        auto result = ScanProcessInternal(processId);
        if (result.isMinerDetected) {
            detections.push_back(std::move(result));
        }
    }
    return detections;
}

bool CryptoMinerDetectorImpl::DetectCPUMining(uint32_t processId, MinerDetectionResult& result) const {
    bool detected = false;

    if (m_cpuDetector) {
        const auto signature = m_cpuDetector->AnalyzeProcess(processId);
        result.processInfo.cpuUsage = std::max(result.processInfo.cpuUsage, signature.totalUsagePercent);
        result.resourceStats.cpuUsagePercent = std::max(result.resourceStats.cpuUsagePercent, signature.totalUsagePercent);
        result.resourceStats.perCoreCpuUsage = m_cpuDetector->GetPerCoreUsage();

        if (signature.miningProbability >= 0.60 || m_cpuDetector->IsMiningBehavior(processId)) {
            detected = true;
            result.minerType = result.minerType == MinerType::GPUMiner ? MinerType::HybridMiner : MinerType::CPUMiner;
            result.algorithm = MapSuspectedAlgorithm(signature.suspectedAlgorithm);
            if (result.algorithm == MiningAlgorithm::RandomX || result.algorithm == MiningAlgorithm::CryptoNightR) {
                result.cryptocurrency = Cryptocurrency::Monero;
            }
            if (result.minerFamily == MinerFamily::Unknown) {
                result.minerFamily = IdentifyMinerFamily(result.processInfo.processName, result.processInfo.commandLine);
            }
            if (result.minerName.empty()) {
                result.minerName = result.minerFamily != MinerFamily::Unknown ? std::string(GetMinerFamilyName(result.minerFamily)) : "CPU Miner";
            }
        }
    }

    if (!detected && IsSuspiciousExecutableName(result.processInfo.processName)) {
        detected = true;
        result.minerType = MinerType::CPUMiner;
        result.minerFamily = IdentifyMinerFamily(result.processInfo.processName, result.processInfo.commandLine);
        result.minerName = std::string(GetMinerFamilyName(result.minerFamily));
    }

    if (!detected && IsLikelyMinerCommandLine(result.processInfo.commandLine)) {
        detected = true;
        result.minerType = MinerType::CPUMiner;
        result.algorithm = DetectAlgorithm(result.processInfo.commandLine);
        result.cryptocurrency = DetectCryptocurrency(result.processInfo.commandLine);
        result.minerName = "CPU Miner";
    }

    return detected;
}

bool CryptoMinerDetectorImpl::DetectGPUMining(uint32_t processId, MinerDetectionResult& result) const {
    if (!m_gpuDetector) {
        return false;
    }

    bool detected = false;
    const auto deviceCount = std::max<size_t>(1, m_gpuDetector->GetDeviceCount());
    for (size_t index = 0; index < deviceCount; ++index) {
        for (const auto& gpuProcess : m_gpuDetector->GetGPUProcesses(static_cast<uint32_t>(index))) {
            if (gpuProcess.processId != processId) {
                continue;
            }

            result.resourceStats.gpuUsagePercent = std::max(result.resourceStats.gpuUsagePercent, gpuProcess.gpuUtilization);
            result.minerType = result.minerType == MinerType::CPUMiner ? MinerType::HybridMiner : MinerType::GPUMiner;
            result.minerFamily = IdentifyMinerFamily(gpuProcess.processName, result.processInfo.commandLine);
            result.algorithm = MapGpuAlgorithm(gpuProcess.suspectedAlgorithm);
            result.minerName = result.minerFamily != MinerFamily::Unknown ? std::string(GetMinerFamilyName(result.minerFamily)) : "GPU Miner";

            if (gpuProcess.isSuspectedMiner || gpuProcess.isComputeIntensive || gpuProcess.gpuUtilization >= m_config.gpuUsageThreshold) {
                detected = true;
            }
        }
    }

    if (!detected && m_gpuDetector->DetectDAGGenerated(processId)) {
        detected = true;
        result.minerType = result.minerType == MinerType::CPUMiner ? MinerType::HybridMiner : MinerType::GPUMiner;
        result.algorithm = MiningAlgorithm::Ethash;
        result.cryptocurrency = Cryptocurrency::Ethereum;
        result.minerName = "GPU Miner";
    }

    if (detected) {
        const auto devices = m_gpuDetector->ScanDevices();
        if (!devices.empty()) {
            double totalGpu = 0.0;
            double totalTemp = 0.0;
            for (const auto& device : devices) {
                totalGpu += device.gpuLoadPercent;
                totalTemp += device.temperatureC;
            }
            result.resourceStats.gpuUsagePercent = std::max(result.resourceStats.gpuUsagePercent, totalGpu / static_cast<double>(devices.size()));
            result.resourceStats.gpuTemperatureCelsius = totalTemp / static_cast<double>(devices.size());
        }
    }

    return detected;
}

bool CryptoMinerDetectorImpl::DetectNetworkMining(uint32_t processId, MinerDetectionResult& result) const {
    if (!m_poolDetector) {
        return false;
    }

    bool detected = false;
    for (const auto& connection : m_poolDetector->GetProcessConnections(processId)) {
        detected = true;
        MinerNetworkConnection mapped{};
        mapped.remoteIP = connection.remoteIP;
        mapped.remotePort = connection.remotePort;
        mapped.localPort = connection.localPort;
        mapped.protocol = MapPoolProtocol(connection.protocol);
        mapped.poolAddress = !connection.poolInfo.address.empty() ? connection.poolInfo.address : connection.remoteHostname;
        mapped.poolName = connection.poolInfo.poolName;
        mapped.walletAddress = connection.walletAddress;
        mapped.workerName = connection.workerName;
        mapped.bytesSent = connection.bytesSent;
        mapped.bytesReceived = connection.bytesReceived;
        mapped.isEncrypted = connection.isEncrypted;
        mapped.connectionTime = connection.connectionTime;
        result.networkConnections.push_back(mapped);

        if (!mapped.poolAddress.empty()) {
            result.poolAddresses.push_back(mapped.poolAddress);
        }
        if (!mapped.walletAddress.empty()) {
            result.walletAddresses.push_back(mapped.walletAddress);
        }
        if (result.cryptocurrency == Cryptocurrency::Unknown) {
            result.cryptocurrency = MapPoolCurrency(connection.cryptocurrency);
        }
    }

    if (detected) {
        result.minerType = result.minerType == MinerType::GPUMiner ? MinerType::HybridMiner : (result.minerType == MinerType::BrowserMiner ? MinerType::BrowserMiner : MinerType::CPUMiner);
        if (result.minerName.empty()) {
            result.minerName = "Mining Pool Client";
        }
    }

    return detected;
}

bool CryptoMinerDetectorImpl::DetectBrowserMining(uint32_t processId, MinerDetectionResult& result) const {
    if (!m_browserDetector) {
        return false;
    }

    for (const auto& tab : m_browserDetector->GetMiningTabs()) {
        if (tab.browserPid != processId || !tab.isMining) {
            continue;
        }

        BrowserMinerInfo browserInfo{};
        browserInfo.browserPid = tab.browserPid;
        browserInfo.browserType = result.processInfo.processName.empty() ? "browser" : WideToUtf8(result.processInfo.processName);
        browserInfo.url = tab.url;
        browserInfo.domain = tab.domain;
        browserInfo.isWASM = tab.hasWASM;
        browserInfo.coresUsed = tab.workerCount;
        browserInfo.throttlePercent = 0;
        result.browserInfo = browserInfo;
        result.resourceStats.cpuUsagePercent = std::max(result.resourceStats.cpuUsagePercent, tab.cpuUsage);
        result.minerType = MinerType::BrowserMiner;
        result.minerFamily = MinerFamily::Custom;
        result.minerName = tab.hasWASM ? "Browser WASM Miner" : "Browser Script Miner";
        return true;
    }

    return false;
}

bool CryptoMinerDetectorImpl::DetectSignatureMining(uint32_t, MinerDetectionResult& result) const {
    if (result.processInfo.processPath.empty()) {
        return false;
    }

    const auto markers = ReadFileMarkers(result.processInfo.processPath);
    if (markers.empty()) {
        return false;
    }

    result.minerType = result.minerType == MinerType::Unknown ? MinerType::CPUMiner : result.minerType;
    if (result.minerFamily == MinerFamily::Unknown) {
        result.minerFamily = IdentifyMinerFamily(result.processInfo.processName, result.processInfo.commandLine);
    }
    if (result.minerName.empty()) {
        result.minerName = result.minerFamily != MinerFamily::Unknown ? std::string(GetMinerFamilyName(result.minerFamily)) : "Signed Miner Artifact";
    }

    const auto marker = FirstSignatureMarker(markers);
    if ((result.algorithm == MiningAlgorithm::Unknown) && !marker.empty()) {
        result.algorithm = DetectAlgorithm(Utf8ToWide(std::string(marker)));
    }
    if (result.cryptocurrency == Cryptocurrency::Unknown) {
        result.cryptocurrency = DetectCryptocurrency(result.processInfo.commandLine);
    }

    return true;
}

bool CryptoMinerDetectorImpl::DetectBehavioralMining(uint32_t processId, MinerDetectionResult& result) const {
    uint32_t score = 0;

    if (IsPathTransient(result.processInfo.processPath)) {
        score += 20;
    }
    if (IsLikelyMinerCommandLine(result.processInfo.commandLine)) {
        score += 25;
    }
    if (result.processInfo.threadCount >= 32) {
        score += 10;
    }
    if (result.processInfo.memoryUsage >= 256ULL * 1024ULL * 1024ULL) {
        score += 10;
    }

    if (result.processInfo.parentPid != 0) {
        if (const auto parent = FindProcessRecord(result.processInfo.parentPid); parent.has_value()) {
            const auto parentName = ToLowerWide(parent->processName);
            if (parentName.find(L"powershell") != std::wstring::npos ||
                parentName.find(L"cmd.exe") != std::wstring::npos ||
                parentName.find(L"wscript") != std::wstring::npos ||
                parentName.find(L"cscript") != std::wstring::npos) {
                score += 20;
            }
        }
    }

    if (result.resourceStats.cpuUsagePercent >= m_config.cpuUsageThreshold) {
        score += 20;
    }
    if (!result.poolAddresses.empty()) {
        score += 30;
    }

    if (score < 50) {
        return false;
    }

    if (result.minerType == MinerType::Unknown) {
        result.minerType = MinerType::CPUMiner;
    }
    if (result.minerName.empty()) {
        result.minerName = "Behavioral Miner";
    }
    return true;
}

void CryptoMinerDetectorImpl::AggregateResult(MinerDetectionResult& result) const {
    double confidence = 0.0;
    DetectionSource primarySource = result.source;
    size_t strongestWeight = 0;

    for (const auto source : result.additionalSources) {
        const auto weight = DetectionSourceWeight(source);
        confidence += static_cast<double>(weight);
        if (weight > strongestWeight) {
            strongestWeight = weight;
            primarySource = source;
        }
    }

    if (!result.additionalSources.empty()) {
        confidence /= static_cast<double>(result.additionalSources.size());
    }

    if (result.browserInfo.has_value()) {
        confidence = std::max(confidence, result.browserInfo->isWASM ? 88.0 : 78.0);
    }
    if (!result.walletAddresses.empty()) {
        confidence += 8.0;
    }
    if (!result.poolAddresses.empty()) {
        confidence += 10.0;
    }
    if (result.minerFamily != MinerFamily::Unknown && result.minerFamily != MinerFamily::Custom) {
        confidence += 5.0;
    }
    if (result.resourceStats.cpuUsagePercent >= MinerConstants::CPU_USAGE_HIGH) {
        confidence += 5.0;
    }
    if (result.resourceStats.gpuUsagePercent >= MinerConstants::GPU_LOAD_THRESHOLD) {
        confidence += 5.0;
    }

    result.source = primarySource;
    result.confidenceScore = std::clamp(confidence, 0.0, 100.0);

    double threatScore = result.confidenceScore;
    if (result.minerType == MinerType::HybridMiner) {
        threatScore += 8.0;
    }
    if (!result.walletAddresses.empty()) {
        threatScore += 5.0;
    }
    if (!result.networkConnections.empty()) {
        threatScore += 10.0;
    }
    if (result.browserInfo.has_value()) {
        threatScore += 8.0;
    }
    result.threatScore = std::clamp(threatScore, 0.0, 100.0);

    if (result.threatScore >= 90.0) {
        result.severity = ThreatSeverity::Critical;
    } else if (result.threatScore >= 75.0) {
        result.severity = ThreatSeverity::High;
    } else if (result.threatScore >= 55.0) {
        result.severity = ThreatSeverity::Medium;
    } else {
        result.severity = ThreatSeverity::Low;
    }

    result.mitreTechniques = {"T1496"};
    if (!result.networkConnections.empty()) {
        result.mitreTechniques.push_back("T1071");
    }

    if (result.minerType == MinerType::Unknown) {
        result.minerType = result.browserInfo.has_value() ? MinerType::BrowserMiner : MinerType::CPUMiner;
    }
    if (result.minerName.empty()) {
        result.minerName = std::string(GetMinerTypeName(result.minerType));
    }
}

bool CryptoMinerDetectorImpl::ShouldPublishDetection(const MinerDetectionResult& result) {
    const auto key = BuildDetectionKey(result);
    const auto now = Clock::now();
    std::lock_guard lock(m_cooldownMutex);
    const auto it = m_detectionCooldowns.find(key);
    if (it != m_detectionCooldowns.end() && (now - it->second) < kDetectionCooldown) {
        return false;
    }
    m_detectionCooldowns[key] = now;
    return true;
}

void CryptoMinerDetectorImpl::PublishDetection(MinerDetectionResult& result, bool executeRemediation) {
    if (!result.isMinerDetected || result.isWhitelisted) {
        return;
    }

    if (!ShouldPublishDetection(result)) {
        return;
    }

    if (executeRemediation) {
        if (m_config.terminateOnDetection) {
            if (TerminateMinerInternal(result.processInfo.processId)) {
                result.actionTaken = DetectionAction::Terminate;
            }
        } else if (m_config.blockStratumProtocol) {
            bool blocked = false;
            if (result.browserInfo.has_value() && m_browserDetector && !result.browserInfo->domain.empty()) {
                m_browserDetector->BlockDomain(result.browserInfo->domain);
                blocked = true;
            }
            if (!result.poolAddresses.empty()) {
                blocked = BlockMinerNetworkInternal(result.processInfo.processId) || blocked;
            }
            if (blocked) {
                result.actionTaken = DetectionAction::BlockNetwork;
            }
        }

        if (result.actionTaken == DetectionAction::None && m_config.alertOnDetection) {
            result.actionTaken = DetectionAction::Alert;
        }
    }

    if (std::find(result.additionalSources.begin(), result.additionalSources.end(), DetectionSource::NetworkStratum) != result.additionalSources.end()) {
        m_statistics.stratumConnectionsDetected.fetch_add(1, std::memory_order_relaxed);
    }

    {
        std::unique_lock lock(m_detectionsMutex);
        m_recentDetections.push_back(result);
        if (m_recentDetections.size() > kMaxRecentDetections) {
            m_recentDetections.pop_front();
        }
    }

    m_statistics.minersDetected.fetch_add(1, std::memory_order_relaxed);
    if (result.minerType == MinerType::CPUMiner || result.minerType == MinerType::HybridMiner) {
        m_statistics.cpuMinersDetected.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.minerType == MinerType::GPUMiner || result.minerType == MinerType::HybridMiner) {
        m_statistics.gpuMinersDetected.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.minerType == MinerType::BrowserMiner) {
        m_statistics.browserMinersDetected.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.actionTaken == DetectionAction::Terminate) {
        m_statistics.minersTerminated.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.actionTaken == DetectionAction::BlockNetwork) {
        m_statistics.poolConnectionsBlocked.fetch_add(1, std::memory_order_relaxed);
    }
    if (const auto familyIndex = FamilyIndex(result.minerFamily); familyIndex.has_value()) {
        m_statistics.byFamily[*familyIndex].fetch_add(1, std::memory_order_relaxed);
    }
    if (const auto algorithmIndex = AlgorithmIndex(result.algorithm); algorithmIndex.has_value()) {
        m_statistics.byAlgorithm[*algorithmIndex].fetch_add(1, std::memory_order_relaxed);
    }
    m_statistics.lastDetectionTime = result.detectionTime;

    std::vector<MinerDetectedCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        callbacks = m_detectionCallbacks;
    }
    for (const auto& callback : callbacks) {
        try {
            callback(result);
        } catch (const std::exception& exception) {
            Utils::Logger::Error("CryptoMinerDetector detection callback failed: {}", exception.what());
        } catch (...) {
            Utils::Logger::Error("CryptoMinerDetector detection callback failed with unknown exception");
        }
    }
}

void CryptoMinerDetectorImpl::PublishResourceAnomaly(const ResourceUsageStats& stats) const {
    std::vector<ResourceAnomalyCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        callbacks = m_resourceCallbacks;
    }

    for (const auto& callback : callbacks) {
        try {
            callback(stats);
        } catch (const std::exception& exception) {
            Utils::Logger::Error("CryptoMinerDetector resource callback failed: {}", exception.what());
        } catch (...) {
            Utils::Logger::Error("CryptoMinerDetector resource callback failed with unknown exception");
        }
    }
}

void CryptoMinerDetectorImpl::InvokeErrorCallbacks(const std::string& message, int code) const {
    std::vector<ErrorCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        callbacks = m_errorCallbacks;
    }

    for (const auto& callback : callbacks) {
        try {
            callback(message, code);
        } catch (const std::exception& exception) {
            Utils::Logger::Error("CryptoMinerDetector error callback failed: {}", exception.what());
        } catch (...) {
            Utils::Logger::Error("CryptoMinerDetector error callback failed with unknown exception");
        }
    }
}

std::vector<BrowserMinerInfo> CryptoMinerDetectorImpl::ScanBrowsersInternal() const {
    std::vector<BrowserMinerInfo> results;
    if (!m_browserDetector) {
        return results;
    }

    for (const auto& tab : m_browserDetector->GetMiningTabs()) {
        BrowserMinerInfo info{};
        info.browserPid = tab.browserPid;
        info.browserType = "browser";
        info.url = tab.url;
        info.domain = tab.domain;
        info.isWASM = tab.hasWASM;
        info.coresUsed = tab.workerCount;
        results.push_back(std::move(info));
    }
    return results;
}

void CryptoMinerDetectorImpl::AnalyzeSystemResourcesInternal() {
    const auto stats = GetResourceUsageInternal();
    if (stats.cpuUsagePercent >= m_config.cpuUsageThreshold || stats.gpuUsagePercent >= m_config.gpuUsageThreshold) {
        PublishResourceAnomaly(stats);
    }
}

ResourceUsageStats CryptoMinerDetectorImpl::GetResourceUsageInternal() const {
    ResourceUsageStats stats{};
    stats.sampleTime = SystemClock::now();

    if (m_cpuDetector) {
        stats.cpuUsagePercent = m_cpuDetector->GetOverallCPUUsage();
        stats.perCoreCpuUsage = m_cpuDetector->GetPerCoreUsage();
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus)) {
        stats.memoryUsagePercent = static_cast<double>(memoryStatus.dwMemoryLoad);
    }

    if (m_gpuDetector) {
        const auto devices = m_gpuDetector->ScanDevices();
        if (!devices.empty()) {
            double gpuLoad = 0.0;
            double gpuTemp = 0.0;
            double gpuMemory = 0.0;
            double gpuPower = 0.0;
            for (const auto& device : devices) {
                gpuLoad += device.gpuLoadPercent;
                gpuTemp += device.temperatureC;
                gpuMemory += device.memoryUsedPercent;
                gpuPower += device.powerDrawWatts;
            }
            const auto divisor = static_cast<double>(devices.size());
            stats.gpuUsagePercent = gpuLoad / divisor;
            stats.gpuTemperatureCelsius = gpuTemp / divisor;
            stats.gpuMemoryPercent = gpuMemory / divisor;
            stats.gpuPowerDrawWatts = gpuPower / divisor;
        }
    }

    return stats;
}

ResourceUsageStats CryptoMinerDetectorImpl::GetProcessResourceUsageInternal(uint32_t processId) const {
    ResourceUsageStats stats = GetResourceUsageInternal();
    PROCESS_MEMORY_COUNTERS_EX counters{};
    if (QueryProcessMemoryStats(processId, counters)) {
        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        if (::GlobalMemoryStatusEx(&memoryStatus) && memoryStatus.ullTotalPhys != 0) {
            stats.memoryUsagePercent = (static_cast<double>(counters.PrivateUsage) * 100.0) /
                static_cast<double>(memoryStatus.ullTotalPhys);
        }
    }

    if (m_cpuDetector) {
        const auto signature = m_cpuDetector->AnalyzeProcess(processId);
        stats.cpuUsagePercent = signature.totalUsagePercent;
    }

    if (m_gpuDetector) {
        const auto deviceCount = std::max<size_t>(1, m_gpuDetector->GetDeviceCount());
        for (size_t index = 0; index < deviceCount; ++index) {
            for (const auto& process : m_gpuDetector->GetGPUProcesses(static_cast<uint32_t>(index))) {
                if (process.processId == processId) {
                    stats.gpuUsagePercent = std::max(stats.gpuUsagePercent, process.gpuUtilization);
                }
            }
        }
    }

    return stats;
}

bool CryptoMinerDetectorImpl::IsMiningPoolInternal(const std::string& host, uint16_t port) const {
    const auto normalized = TrimAndNormalizeHost(host);
    if (normalized.empty()) {
        return false;
    }

    {
        std::shared_lock lock(m_whitelistMutex);
        if (m_whitelistedPools.contains(normalized)) {
            return false;
        }
    }

    {
        std::shared_lock lock(m_poolMutex);
        if (m_poolDatabase.contains(normalized)) {
            return true;
        }
        for (const auto& [address, info] : m_poolDatabase) {
            if (normalized == address ||
                (normalized.size() > address.size() && normalized.ends_with(address) && normalized[normalized.size() - address.size() - 1] == '.')) {
                if (port == 0 || info.port == 0 || info.port == port || IsMiningPort(port)) {
                    return true;
                }
            }
        }
    }

    return (m_poolDetector && (m_poolDetector->IsPoolHostname(normalized) || (port != 0 && m_poolDetector->IsPoolEndpoint(normalized, port))));
}

std::optional<MiningPoolInfo> CryptoMinerDetectorImpl::GetPoolInfoInternal(const std::string& host) const {
    const auto normalized = TrimAndNormalizeHost(host);
    std::shared_lock lock(m_poolMutex);
    if (const auto it = m_poolDatabase.find(normalized); it != m_poolDatabase.end()) {
        return it->second;
    }

    for (const auto& [address, info] : m_poolDatabase) {
        if (normalized.size() > address.size() && normalized.ends_with(address) && normalized[normalized.size() - address.size() - 1] == '.') {
            return info;
        }
    }

    return std::nullopt;
}

std::vector<MinerNetworkConnection> CryptoMinerDetectorImpl::GetActiveMiningConnectionsInternal() const {
    std::vector<MinerNetworkConnection> connections;
    if (!m_poolDetector) {
        return connections;
    }

    for (const auto& connection : m_poolDetector->GetActiveConnections()) {
        MinerNetworkConnection mapped{};
        mapped.remoteIP = connection.remoteIP;
        mapped.remotePort = connection.remotePort;
        mapped.localPort = connection.localPort;
        mapped.protocol = MapPoolProtocol(connection.protocol);
        mapped.poolAddress = connection.poolInfo.address;
        mapped.poolName = connection.poolInfo.poolName;
        mapped.walletAddress = connection.walletAddress;
        mapped.workerName = connection.workerName;
        mapped.bytesSent = connection.bytesSent;
        mapped.bytesReceived = connection.bytesReceived;
        mapped.isEncrypted = connection.isEncrypted;
        mapped.connectionTime = connection.connectionTime;
        connections.push_back(std::move(mapped));
    }

    return connections;
}

bool CryptoMinerDetectorImpl::LoadPoolBlacklistInternal(const std::filesystem::path& path) {
    if (path.empty() || !std::filesystem::exists(path)) {
        return false;
    }

    std::ifstream input(path);
    if (!input) {
        return false;
    }

    std::string line;
    while (std::getline(input, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos) {
            line.erase(comment);
        }
        line = TrimAndNormalizeHost(line);
        if (line.empty()) {
            continue;
        }

        MiningPoolInfo info{};
        info.address = line;
        info.name = line;
        info.isMalicious = true;
        AddPoolToBlacklistInternal(info);
    }

    if (m_poolDetector) {
        m_poolDetector->LoadPoolBlacklist(path);
    }
    return true;
}

void CryptoMinerDetectorImpl::AddPoolToBlacklistInternal(const MiningPoolInfo& poolInfo) {
    MiningPoolInfo normalized = poolInfo;
    normalized.address = TrimAndNormalizeHost(normalized.address);
    normalized.name = normalized.name.empty() ? normalized.address : normalized.name;
    normalized.isMalicious = true;
    {
        std::unique_lock lock(m_poolMutex);
        m_poolDatabase[normalized.address] = normalized;
    }

    if (m_poolDetector && !normalized.address.empty()) {
        PoolEndpointInfo endpoint{};
        endpoint.address = normalized.address;
        endpoint.port = normalized.port;
        endpoint.poolName = normalized.name;
        endpoint.status = PoolStatus::KnownMalicious;
        endpoint.isBlacklisted = true;
        m_poolDetector->AddToBlacklist(endpoint);
    }
}

bool CryptoMinerDetectorImpl::BlockPoolConnectionInternal(const std::string& poolAddress) {
    const auto normalized = TrimAndNormalizeHost(poolAddress);
    if (normalized.empty()) {
        return false;
    }

    bool blocked = false;
    if (m_poolDetector) {
        blocked = m_poolDetector->BlockPoolAddress(normalized);
    }

    MiningPoolInfo info{};
    info.address = normalized;
    info.name = normalized;
    info.isMalicious = true;
    AddPoolToBlacklistInternal(info);
    return blocked || !normalized.empty();
}

bool CryptoMinerDetectorImpl::TerminateMinerInternal(uint32_t processId) const {
    UniqueHandle process(::OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
    if (!process) {
        return false;
    }

    return ::TerminateProcess(process.Get(), 1) != FALSE;
}

bool CryptoMinerDetectorImpl::QuarantineMinerInternal(uint32_t processId) const {
    ProcessMinerInfo info{};
    if (!PopulateProcessInfo(processId, info) || info.processPath.empty()) {
        return false;
    }

    TerminateMinerInternal(processId);
    const auto result = Core::Engine::QuarantineManager::Instance().QuarantineFile(
        info.processPath,
        Utf8ToWide("CryptoMiner." + std::string(GetMinerFamilyName(IdentifyMinerFamily(info.processName, info.commandLine)))),
        processId);
    return result.IsSuccess();
}

bool CryptoMinerDetectorImpl::BlockMinerNetworkInternal(uint32_t processId) const {
    if (!m_poolDetector) {
        return false;
    }

    bool blockedAny = false;
    for (const auto& connection : m_poolDetector->GetProcessConnections(processId)) {
        const auto address = !connection.poolInfo.address.empty() ? connection.poolInfo.address : connection.remoteHostname;
        if (!address.empty()) {
            blockedAny = m_poolDetector->BlockPoolAddress(address) || blockedAny;
        }
    }
    return blockedAny;
}

bool CryptoMinerDetectorImpl::IsWhitelistedInternal(uint32_t processId, std::string* reason) const {
    std::shared_lock lock(m_whitelistMutex);
    if (const auto it = m_whitelistedPids.find(processId); it != m_whitelistedPids.end()) {
        if (reason) {
            *reason = it->second;
        }
        return true;
    }

    ProcessMinerInfo info{};
    if (!PopulateProcessInfo(processId, info)) {
        return false;
    }

    const auto normalizedName = ToLowerWide(info.processName);
    if (m_whitelistedProcessNames.contains(normalizedName)) {
        if (reason) {
            *reason = "configured application whitelist";
        }
        return true;
    }

    const auto normalizedPath = ToLowerWide(info.processPath);
    if (const auto it = m_whitelistedPaths.find(normalizedPath); it != m_whitelistedPaths.end()) {
        if (reason) {
            *reason = it->second;
        }
        return true;
    }

    return false;
}

void CryptoMinerDetectorImpl::AddToWhitelistInternal(uint32_t processId, const std::string& reason) {
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedPids[processId] = reason;
}

void CryptoMinerDetectorImpl::AddPathToWhitelistInternal(const std::filesystem::path& path, const std::string& reason) {
    if (path.empty()) {
        return;
    }
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedPaths[ToLowerWide(path.wstring())] = reason;
}

void CryptoMinerDetectorImpl::RemoveFromWhitelistInternal(uint32_t processId) {
    std::unique_lock lock(m_whitelistMutex);
    m_whitelistedPids.erase(processId);
}

void CryptoMinerDetectorImpl::RegisterDetectionCallback(MinerDetectedCallback callback) {
    if (!callback) {
        return;
    }
    std::lock_guard lock(m_callbackMutex);
    m_detectionCallbacks.push_back(std::move(callback));
}

void CryptoMinerDetectorImpl::RegisterResourceAnomalyCallback(ResourceAnomalyCallback callback) {
    if (!callback) {
        return;
    }
    std::lock_guard lock(m_callbackMutex);
    m_resourceCallbacks.push_back(std::move(callback));
}

void CryptoMinerDetectorImpl::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) {
        return;
    }
    std::lock_guard lock(m_callbackMutex);
    m_errorCallbacks.push_back(std::move(callback));
}

void CryptoMinerDetectorImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_detectionCallbacks.clear();
    m_resourceCallbacks.clear();
    m_errorCallbacks.clear();
}

MinerDetectionStatistics CryptoMinerDetectorImpl::GetStatisticsSnapshot() const {
    return m_statistics;
}

void CryptoMinerDetectorImpl::ResetStatistics() {
    m_statistics.Reset();
}

std::vector<MinerDetectionResult> CryptoMinerDetectorImpl::GetRecentDetections(size_t maxCount) const {
    std::vector<MinerDetectionResult> results;
    std::shared_lock lock(m_detectionsMutex);
    const auto count = std::min(maxCount, m_recentDetections.size());
    results.reserve(count);
    auto iterator = m_recentDetections.rbegin();
    for (size_t index = 0; index < count && iterator != m_recentDetections.rend(); ++index, ++iterator) {
        results.push_back(*iterator);
    }
    return results;
}

bool CryptoMinerDetectorImpl::SelfTest() const {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (m_config.enableNetworkMonitoring && !IsMiningPoolInternal("supportxmr.com", MinerConstants::STRATUM_PORT_DEFAULT)) {
        return false;
    }

    if (!ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", Cryptocurrency::Ethereum)) {
        return false;
    }

    return !CryptoMinerDetector::GetVersionString().empty();
}

MinerFamily CryptoMinerDetectorImpl::IdentifyMinerFamily(const std::wstring& processName, const std::wstring& commandLine) const {
    const auto lowerName = ToLowerUtf8(WideToUtf8(ToLowerWide(processName)));
    const auto lowerCommand = ToLowerUtf8(WideToUtf8(ToLowerWide(commandLine)));

    if (lowerName.find("xmrig") != std::string::npos || lowerCommand.find("xmrig") != std::string::npos) return MinerFamily::XMRig;
    if (lowerName.find("xmr-stak") != std::string::npos || lowerCommand.find("xmr-stak") != std::string::npos) return MinerFamily::XMRStak;
    if (lowerName.find("cgminer") != std::string::npos) return MinerFamily::CGMiner;
    if (lowerName.find("bfgminer") != std::string::npos) return MinerFamily::BFGMiner;
    if (lowerName.find("phoenixminer") != std::string::npos) return MinerFamily::PhoenixMiner;
    if (lowerName.find("t-rex") != std::string::npos || lowerName.find("trex") != std::string::npos) return MinerFamily::TRexMiner;
    if (lowerName.find("lolminer") != std::string::npos) return MinerFamily::LolMiner;
    if (lowerName.find("ethminer") != std::string::npos) return MinerFamily::Ethminer;
    if (lowerName.find("claymore") != std::string::npos) return MinerFamily::Claymore;
    if (lowerName.find("nicehash") != std::string::npos || lowerCommand.find("nicehash") != std::string::npos) return MinerFamily::NiceHash;
    if (lowerName.find("nbminer") != std::string::npos) return MinerFamily::NBMiner;
    if (lowerName.find("teamredminer") != std::string::npos) return MinerFamily::TeamRedMiner;
    if (lowerName.find("gminer") != std::string::npos) return MinerFamily::GMiner;
    if (lowerName.find("coinhive") != std::string::npos || lowerCommand.find("coinhive") != std::string::npos) return MinerFamily::Coinhive;
    if (lowerName.find("cryptoloot") != std::string::npos || lowerCommand.find("cryptoloot") != std::string::npos) return MinerFamily::CryptoLoot;
    if (lowerName.find("coinimp") != std::string::npos || lowerCommand.find("coinimp") != std::string::npos) return MinerFamily::CoinIMP;
    if (lowerName.find("jsecoin") != std::string::npos || lowerCommand.find("jsecoin") != std::string::npos) return MinerFamily::JSECoin;
    return MinerFamily::Unknown;
}

MiningAlgorithm CryptoMinerDetectorImpl::DetectAlgorithm(const std::wstring& commandLine) const {
    const auto lower = ToLowerUtf8(WideToUtf8(ToLowerWide(commandLine)));
    if (lower.find("randomx") != std::string::npos) return MiningAlgorithm::RandomX;
    if (lower.find("cryptonight") != std::string::npos) return MiningAlgorithm::CryptoNightR;
    if (lower.find("ethash") != std::string::npos) return MiningAlgorithm::Ethash;
    if (lower.find("etchash") != std::string::npos) return MiningAlgorithm::Etchash;
    if (lower.find("kawpow") != std::string::npos) return MiningAlgorithm::Kawpow;
    if (lower.find("autolykos") != std::string::npos) return MiningAlgorithm::Autolykos;
    if (lower.find("equihash") != std::string::npos) return MiningAlgorithm::Equihash;
    if (lower.find("cuckoo") != std::string::npos) return MiningAlgorithm::CuckooCycle;
    if (lower.find("progpow") != std::string::npos) return MiningAlgorithm::ProgPow;
    if (lower.find("scrypt") != std::string::npos) return MiningAlgorithm::Scrypt;
    if (lower.find("sha256") != std::string::npos) return MiningAlgorithm::SHA256;
    return MiningAlgorithm::Unknown;
}

Cryptocurrency CryptoMinerDetectorImpl::DetectCryptocurrency(const std::wstring& commandLine) const {
    const auto lower = ToLowerUtf8(WideToUtf8(ToLowerWide(commandLine)));
    if (lower.find("xmr") != std::string::npos || lower.find("monero") != std::string::npos) return Cryptocurrency::Monero;
    if (lower.find("eth") != std::string::npos || lower.find("ethereum") != std::string::npos) return Cryptocurrency::Ethereum;
    if (lower.find("etc") != std::string::npos || lower.find("ethereumclassic") != std::string::npos) return Cryptocurrency::EthClassic;
    if (lower.find("btc") != std::string::npos || lower.find("bitcoin") != std::string::npos) return Cryptocurrency::Bitcoin;
    if (lower.find("ltc") != std::string::npos || lower.find("litecoin") != std::string::npos) return Cryptocurrency::Litecoin;
    if (lower.find("rvn") != std::string::npos || lower.find("ravencoin") != std::string::npos) return Cryptocurrency::Ravencoin;
    if (lower.find("zec") != std::string::npos || lower.find("zcash") != std::string::npos) return Cryptocurrency::Zcash;
    if (lower.find("ergo") != std::string::npos) return Cryptocurrency::Ergo;
    return Cryptocurrency::Unknown;
}

void CryptoMinerDetectorImpl::LoadBuiltinPools() {
    std::unique_lock lock(m_poolMutex);
    for (const auto domain : kMiningPoolDomains) {
        MiningPoolInfo info{};
        info.address = std::string(domain);
        info.name = std::string(domain);
        info.isMalicious = true;
        if (info.address.find("xmr") != std::string::npos || info.address.find("monero") != std::string::npos) {
            info.algorithms = {MiningAlgorithm::RandomX, MiningAlgorithm::CryptoNightR};
            info.cryptocurrencies = {Cryptocurrency::Monero};
        } else if (info.address.find("eth") != std::string::npos || info.address.find("ether") != std::string::npos) {
            info.algorithms = {MiningAlgorithm::Ethash, MiningAlgorithm::Etchash};
            info.cryptocurrencies = {Cryptocurrency::Ethereum, Cryptocurrency::EthClassic};
        } else if (info.address.find("btc") != std::string::npos) {
            info.algorithms = {MiningAlgorithm::SHA256};
            info.cryptocurrencies = {Cryptocurrency::Bitcoin};
        } else if (info.address.find("raven") != std::string::npos) {
            info.algorithms = {MiningAlgorithm::Kawpow};
            info.cryptocurrencies = {Cryptocurrency::Ravencoin};
        }
        m_poolDatabase.emplace(info.address, std::move(info));
    }
}

void CryptoMinerDetectorImpl::MonitorLoop() {
    auto nextQuickScan = Clock::now();

    std::unique_lock lock(m_monitorMutex);
    while (m_running.load(std::memory_order_acquire)) {
        if (m_paused.load(std::memory_order_acquire)) {
            m_monitorCv.wait(lock, [this]() {
                return !m_running.load(std::memory_order_acquire) || !m_paused.load(std::memory_order_acquire);
            });
            continue;
        }

        lock.unlock();
        AnalyzeSystemResourcesInternal();
        if (Clock::now() >= nextQuickScan) {
            QuickScanInternal();
            nextQuickScan = Clock::now() + kQuickScanInterval;
        }
        lock.lock();
        m_monitorCv.wait_for(lock, kMonitorWakeInterval, [this]() {
            return !m_running.load(std::memory_order_acquire) || m_paused.load(std::memory_order_acquire);
        });
    }
}

std::string CryptoMinerDetectorImpl::GenerateDetectionId() const {
    const auto sequence = m_detectionSequence.fetch_add(1, std::memory_order_relaxed);
    const auto timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        SystemClock::now().time_since_epoch()).count());
    std::ostringstream stream;
    stream << "MINER-" << std::hex << std::setw(16) << std::setfill('0') << timestamp
           << '-' << std::setw(8) << sequence;
    return stream.str();
}

std::atomic<bool> CryptoMinerDetector::s_instanceCreated{false};

CryptoMinerDetector& CryptoMinerDetector::Instance() noexcept {
    static CryptoMinerDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool CryptoMinerDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

CryptoMinerDetector::CryptoMinerDetector()
    : m_impl(std::make_unique<CryptoMinerDetectorImpl>()) {
}

CryptoMinerDetector::~CryptoMinerDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool CryptoMinerDetector::Initialize(const CryptoMinerDetectorConfiguration& config) {
    return m_impl && m_impl->Initialize(config);
}

void CryptoMinerDetector::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool CryptoMinerDetector::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

ModuleStatus CryptoMinerDetector::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire) : ModuleStatus::Uninitialized;
}

bool CryptoMinerDetector::IsRunning() const noexcept {
    return m_impl && m_impl->IsRunning();
}

bool CryptoMinerDetector::Start() {
    return m_impl && m_impl->Start();
}

bool CryptoMinerDetector::Stop() {
    return m_impl && m_impl->Stop();
}

void CryptoMinerDetector::Pause() {
    if (m_impl) {
        m_impl->Pause();
    }
}

void CryptoMinerDetector::Resume() {
    if (m_impl) {
        m_impl->Resume();
    }
}

bool CryptoMinerDetector::UpdateConfiguration(const CryptoMinerDetectorConfiguration& config) {
    if (!m_impl || !config.IsValid()) {
        return false;
    }

    std::unique_lock lock(m_impl->m_stateMutex);
    m_impl->m_config = config;
    m_impl->m_whitelistedProcessNames.clear();
    m_impl->m_whitelistedPools.clear();
    for (const auto& name : config.whitelistedApplications) {
        m_impl->m_whitelistedProcessNames.insert(ToLowerWide(name));
    }
    for (const auto& pool : config.whitelistedPools) {
        m_impl->m_whitelistedPools.insert(TrimAndNormalizeHost(pool));
    }

    if (m_impl->m_cpuDetector) {
        CPUUsageAnalyzerConfiguration cpuConfig{};
        cpuConfig.highUsageThreshold = config.cpuUsageThreshold;
        cpuConfig.miningThreshold = std::max(0.0, std::min(config.cpuUsageThreshold, 100.0));
        cpuConfig.observationWindowSecs = config.sustainedUsageTriggerSecs;
        cpuConfig.verboseLogging = config.verboseLogging;
        m_impl->m_cpuDetector->UpdateConfiguration(cpuConfig);
    }
    if (m_impl->m_gpuDetector) {
        GPUMiningDetectorConfiguration gpuConfig{};
        gpuConfig.gpuLoadThreshold = config.gpuUsageThreshold;
        gpuConfig.verboseLogging = config.verboseLogging;
        gpuConfig.whitelistedApplications = config.whitelistedApplications;
        m_impl->m_gpuDetector->UpdateConfiguration(gpuConfig);
    }
    if (m_impl->m_browserDetector) {
        BrowserMinerDetectorConfiguration browserConfig{};
        browserConfig.blockKnownDomains = config.blockStratumProtocol;
        browserConfig.enableDomainBlocking = config.blockStratumProtocol;
        browserConfig.enableWorkerMonitoring = false;
        browserConfig.terminateMiningWorkers = false;
        browserConfig.verboseLogging = config.verboseLogging;
        m_impl->m_browserDetector->UpdateConfiguration(browserConfig);
    }
    if (m_impl->m_poolDetector) {
        PoolConnectionDetectorConfiguration poolConfig{};
        poolConfig.blockStratumTraffic = config.blockStratumProtocol;
        poolConfig.blockMaliciousPools = config.blockStratumProtocol;
        poolConfig.poolBlacklistPath = config.poolBlacklistPath;
        poolConfig.whitelistedPools = config.whitelistedPools;
        poolConfig.verboseLogging = config.verboseLogging;
        m_impl->m_poolDetector->UpdateConfiguration(poolConfig);
    }
    return true;
}

CryptoMinerDetectorConfiguration CryptoMinerDetector::GetConfiguration() const {
    if (!m_impl) {
        return {};
    }
    std::shared_lock lock(m_impl->m_stateMutex);
    return m_impl->m_config;
}

MinerDetectionResult CryptoMinerDetector::ScanProcess(uint32_t processId) {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->ScanProcessInternal(processId) : MinerDetectionResult{};
}

MinerDetectionResult CryptoMinerDetector::ScanProcessByName(std::wstring_view processName) {
    if (!m_impl || processName.empty()) {
        return {};
    }

    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    if (!operation.Acquired()) {
        return {};
    }

    const auto normalizedTarget = ToLowerWide(std::wstring(processName));
    MinerDetectionResult best{};
    for (const auto& process : EnumerateProcessesSnapshot()) {
        if (ToLowerWide(process.processName) != normalizedTarget) {
            continue;
        }

        auto current = m_impl->ScanProcessInternal(process.pid);
        if (current.isMinerDetected && current.threatScore >= best.threatScore) {
            best = std::move(current);
        }
    }
    return best;
}

std::vector<MinerDetectionResult> CryptoMinerDetector::ScanAllProcesses() {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->ScanAllProcessesInternal() : std::vector<MinerDetectionResult>{};
}

std::vector<MinerDetectionResult> CryptoMinerDetector::QuickScan() {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->QuickScanInternal() : std::vector<MinerDetectionResult>{};
}

std::vector<BrowserMinerInfo> CryptoMinerDetector::ScanBrowsers() {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->ScanBrowsersInternal() : std::vector<BrowserMinerInfo>{};
}

bool CryptoMinerDetector::ScanBrowserScript(const std::string& scriptContent) {
    if (!m_impl || !m_impl->m_browserDetector) {
        return false;
    }

    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    if (!operation.Acquired()) {
        return false;
    }

    auto browserResult = m_impl->m_browserDetector->AnalyzeScript(scriptContent);
    if (!browserResult.isMinerDetected) {
        return false;
    }

    MinerDetectionResult result{};
    result.detectionId = m_impl->GenerateDetectionId();
    result.isMinerDetected = true;
    result.source = DetectionSource::BrowserScript;
    result.additionalSources = {DetectionSource::BrowserScript};
    result.minerType = MinerType::BrowserMiner;
    result.minerFamily = MapBrowserFamily(browserResult.minerFamily);
    result.minerName = browserResult.familyName.empty() ? "Browser Miner" : browserResult.familyName;
    result.confidenceScore = browserResult.confidenceScore;
    result.severity = browserResult.severity;
    result.detectionTime = browserResult.detectionTime;

    BrowserMinerInfo browserInfo{};
    browserInfo.browserPid = browserResult.scriptInfo.browserPid;
    browserInfo.url = browserResult.scriptInfo.sourceUrl;
    browserInfo.domain = browserResult.scriptInfo.domain;
    browserInfo.scriptSource = browserResult.scriptInfo.contentPreview;
    browserInfo.isWASM = false;
    browserInfo.coresUsed = static_cast<uint32_t>(browserResult.relatedWorkers.size());
    browserInfo.minerLibrary = browserResult.familyName;
    result.browserInfo = browserInfo;
    result.poolAddresses = browserResult.poolAddresses;
    if (!browserResult.walletAddress.empty()) {
        result.walletAddresses.push_back(browserResult.walletAddress);
    }

    m_impl->AggregateResult(result);
    m_impl->PublishDetection(result, true);
    return true;
}

bool CryptoMinerDetector::ScanWASMModule(std::span<const uint8_t> wasmData) {
    if (!m_impl || !m_impl->m_browserDetector) {
        return false;
    }

    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    if (!operation.Acquired()) {
        return false;
    }

    auto browserResult = m_impl->m_browserDetector->AnalyzeWASM(wasmData);
    if (!browserResult.isMinerDetected) {
        return false;
    }

    MinerDetectionResult result{};
    result.detectionId = m_impl->GenerateDetectionId();
    result.isMinerDetected = true;
    result.source = DetectionSource::BrowserWASM;
    result.additionalSources = {DetectionSource::BrowserWASM};
    result.minerType = MinerType::BrowserMiner;
    result.minerFamily = MapBrowserFamily(browserResult.minerFamily);
    result.minerName = browserResult.familyName.empty() ? "Browser WASM Miner" : browserResult.familyName;
    result.confidenceScore = browserResult.confidenceScore;
    result.severity = browserResult.severity;
    result.detectionTime = browserResult.detectionTime;

    BrowserMinerInfo browserInfo{};
    browserInfo.browserPid = browserResult.scriptInfo.browserPid;
    browserInfo.url = browserResult.scriptInfo.sourceUrl;
    browserInfo.domain = browserResult.scriptInfo.domain;
    browserInfo.isWASM = true;
    browserInfo.minerLibrary = browserResult.familyName;
    result.browserInfo = browserInfo;
    result.poolAddresses = browserResult.poolAddresses;

    m_impl->AggregateResult(result);
    m_impl->PublishDetection(result, true);
    return true;
}

bool CryptoMinerDetector::IsMiningPool(const std::string& host, uint16_t port) const {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->IsMiningPoolInternal(host, port);
}

bool CryptoMinerDetector::DetectStratumProtocol(std::span<const uint8_t> payload) const {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->m_poolDetector && m_impl->m_poolDetector->IsStratumTraffic(payload);
}

std::vector<MinerNetworkConnection> CryptoMinerDetector::GetActiveMiningConnections() const {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->GetActiveMiningConnectionsInternal() : std::vector<MinerNetworkConnection>{};
}

bool CryptoMinerDetector::BlockPoolConnection(const std::string& poolAddress) {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->BlockPoolConnectionInternal(poolAddress);
}

void CryptoMinerDetector::AnalyzeSystemResources() {
    if (!m_impl) {
        return;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    if (operation.Acquired()) {
        m_impl->AnalyzeSystemResourcesInternal();
    }
}

ResourceUsageStats CryptoMinerDetector::GetResourceUsage() const {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->GetResourceUsageInternal() : ResourceUsageStats{};
}

ResourceUsageStats CryptoMinerDetector::GetProcessResourceUsage(uint32_t processId) const {
    if (!m_impl) {
        return {};
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->GetProcessResourceUsageInternal(processId) : ResourceUsageStats{};
}

bool CryptoMinerDetector::LoadPoolBlacklist(const std::filesystem::path& path) {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->LoadPoolBlacklistInternal(path);
}

void CryptoMinerDetector::AddPoolToBlacklist(const MiningPoolInfo& pool) {
    if (!m_impl) {
        return;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    if (operation.Acquired()) {
        m_impl->AddPoolToBlacklistInternal(pool);
    }
}

std::optional<MiningPoolInfo> CryptoMinerDetector::GetPoolInfo(const std::string& address) const {
    if (!m_impl) {
        return std::nullopt;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() ? m_impl->GetPoolInfoInternal(address) : std::nullopt;
}

bool CryptoMinerDetector::TerminateMiner(uint32_t processId) {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->TerminateMinerInternal(processId);
}

bool CryptoMinerDetector::QuarantineMiner(uint32_t processId) {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->QuarantineMinerInternal(processId);
}

bool CryptoMinerDetector::BlockMinerNetwork(uint32_t processId) {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->BlockMinerNetworkInternal(processId);
}

bool CryptoMinerDetector::IsWhitelisted(uint32_t processId) const {
    if (!m_impl) {
        return false;
    }
    CryptoMinerDetectorImpl::ActiveOperation operation(*m_impl);
    return operation.Acquired() && m_impl->IsWhitelistedInternal(processId);
}

void CryptoMinerDetector::AddToWhitelist(uint32_t processId, const std::string& reason) {
    if (m_impl) {
        m_impl->AddToWhitelistInternal(processId, reason);
    }
}

void CryptoMinerDetector::AddPathToWhitelist(const std::filesystem::path& path, const std::string& reason) {
    if (m_impl) {
        m_impl->AddPathToWhitelistInternal(path, reason);
    }
}

void CryptoMinerDetector::RemoveFromWhitelist(uint32_t processId) {
    if (m_impl) {
        m_impl->RemoveFromWhitelistInternal(processId);
    }
}

void CryptoMinerDetector::RegisterDetectionCallback(MinerDetectedCallback callback) {
    if (m_impl) {
        m_impl->RegisterDetectionCallback(std::move(callback));
    }
}

void CryptoMinerDetector::RegisterResourceAnomalyCallback(ResourceAnomalyCallback callback) {
    if (m_impl) {
        m_impl->RegisterResourceAnomalyCallback(std::move(callback));
    }
}

void CryptoMinerDetector::RegisterErrorCallback(ErrorCallback callback) {
    if (m_impl) {
        m_impl->RegisterErrorCallback(std::move(callback));
    }
}

void CryptoMinerDetector::UnregisterCallbacks() {
    if (m_impl) {
        m_impl->UnregisterCallbacks();
    }
}

MinerDetectionStatistics CryptoMinerDetector::GetStatistics() const {
    return m_impl ? m_impl->GetStatisticsSnapshot() : MinerDetectionStatistics{};
}

void CryptoMinerDetector::ResetStatistics() {
    if (m_impl) {
        m_impl->ResetStatistics();
    }
}

std::vector<MinerDetectionResult> CryptoMinerDetector::GetRecentDetections(size_t maxCount) const {
    return m_impl ? m_impl->GetRecentDetections(maxCount) : std::vector<MinerDetectionResult>{};
}

bool CryptoMinerDetector::SelfTest() {
    return m_impl && m_impl->SelfTest();
}

std::string CryptoMinerDetector::GetVersionString() noexcept {
    std::ostringstream stream;
    stream << MinerConstants::VERSION_MAJOR << '.' << MinerConstants::VERSION_MINOR << '.' << MinerConstants::VERSION_PATCH;
    return stream.str();
}

MinerDetectionStatistics::MinerDetectionStatistics(const MinerDetectionStatistics& other) noexcept {
    *this = other;
}

MinerDetectionStatistics& MinerDetectionStatistics::operator=(const MinerDetectionStatistics& other) noexcept {
    if (this != &other) {
        totalScans.store(other.totalScans.load(std::memory_order_relaxed), std::memory_order_relaxed);
        minersDetected.store(other.minersDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cpuMinersDetected.store(other.cpuMinersDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        gpuMinersDetected.store(other.gpuMinersDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        browserMinersDetected.store(other.browserMinersDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        minersTerminated.store(other.minersTerminated.load(std::memory_order_relaxed), std::memory_order_relaxed);
        poolConnectionsBlocked.store(other.poolConnectionsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stratumConnectionsDetected.store(other.stratumConnectionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        whitelistedPasses.store(other.whitelistedPasses.load(std::memory_order_relaxed), std::memory_order_relaxed);
        falsePositives.store(other.falsePositives.load(std::memory_order_relaxed), std::memory_order_relaxed);
        for (size_t index = 0; index < byFamily.size(); ++index) {
            byFamily[index].store(other.byFamily[index].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        for (size_t index = 0; index < byAlgorithm.size(); ++index) {
            byAlgorithm[index].store(other.byAlgorithm[index].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        startTime = other.startTime;
        lastDetectionTime = other.lastDetectionTime;
    }
    return *this;
}

void MinerDetectionStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    minersDetected.store(0, std::memory_order_relaxed);
    cpuMinersDetected.store(0, std::memory_order_relaxed);
    gpuMinersDetected.store(0, std::memory_order_relaxed);
    browserMinersDetected.store(0, std::memory_order_relaxed);
    minersTerminated.store(0, std::memory_order_relaxed);
    poolConnectionsBlocked.store(0, std::memory_order_relaxed);
    stratumConnectionsDetected.store(0, std::memory_order_relaxed);
    whitelistedPasses.store(0, std::memory_order_relaxed);
    falsePositives.store(0, std::memory_order_relaxed);
    for (auto& counter : byFamily) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byAlgorithm) {
        counter.store(0, std::memory_order_relaxed);
    }
    startTime = Clock::now();
    lastDetectionTime = {};
}

std::string MinerDetectionStatistics::ToJson() const {
    nlohmann::json json;
    json["totalScans"] = totalScans.load(std::memory_order_relaxed);
    json["minersDetected"] = minersDetected.load(std::memory_order_relaxed);
    json["cpuMinersDetected"] = cpuMinersDetected.load(std::memory_order_relaxed);
    json["gpuMinersDetected"] = gpuMinersDetected.load(std::memory_order_relaxed);
    json["browserMinersDetected"] = browserMinersDetected.load(std::memory_order_relaxed);
    json["minersTerminated"] = minersTerminated.load(std::memory_order_relaxed);
    json["poolConnectionsBlocked"] = poolConnectionsBlocked.load(std::memory_order_relaxed);
    json["stratumConnectionsDetected"] = stratumConnectionsDetected.load(std::memory_order_relaxed);
    json["whitelistedPasses"] = whitelistedPasses.load(std::memory_order_relaxed);
    json["falsePositives"] = falsePositives.load(std::memory_order_relaxed);
    json["lastDetectionTime"] = ToUnixMillis(lastDetectionTime);
    return json.dump(2);
}

bool CryptoMinerDetectorConfiguration::IsValid() const noexcept {
    return cpuUsageThreshold >= 0.0 && cpuUsageThreshold <= 100.0 &&
        gpuUsageThreshold >= 0.0 && gpuUsageThreshold <= 100.0 &&
        sustainedUsageTriggerSecs > 0;
}

std::string ResourceUsageStats::ToJson() const {
    nlohmann::json json;
    json["cpuUsagePercent"] = cpuUsagePercent;
    json["perCoreCpuUsage"] = perCoreCpuUsage;
    json["gpuUsagePercent"] = gpuUsagePercent;
    json["gpuMemoryPercent"] = gpuMemoryPercent;
    json["gpuTemperatureCelsius"] = gpuTemperatureCelsius;
    json["gpuFanSpeedRpm"] = gpuFanSpeedRpm;
    json["gpuPowerDrawWatts"] = gpuPowerDrawWatts;
    json["memoryUsagePercent"] = memoryUsagePercent;
    json["sampleTime"] = ToUnixMillis(sampleTime);
    return json.dump(2);
}

std::string MinerNetworkConnection::ToJson() const {
    nlohmann::json json;
    json["remoteIP"] = remoteIP;
    json["remotePort"] = remotePort;
    json["localPort"] = localPort;
    json["protocol"] = std::string(GetMiningProtocolName(protocol));
    json["poolAddress"] = poolAddress;
    json["poolName"] = poolName;
    json["walletAddress"] = walletAddress;
    json["workerName"] = workerName;
    json["bytesSent"] = bytesSent;
    json["bytesReceived"] = bytesReceived;
    json["isEncrypted"] = isEncrypted;
    json["connectionTime"] = ToUnixMillis(connectionTime);
    return json.dump(2);
}

std::string ProcessMinerInfo::ToJson() const {
    nlohmann::json json;
    json["processId"] = processId;
    json["processName"] = WideToUtf8(processName);
    json["processPath"] = WideToUtf8(processPath);
    json["commandLine"] = WideToUtf8(commandLine);
    json["parentPid"] = parentPid;
    json["fileHash"] = HashToHex(fileHash);
    json["is64Bit"] = is64Bit;
    json["creationTime"] = ToUnixMillis(creationTime);
    json["cpuUsage"] = cpuUsage;
    json["memoryUsage"] = memoryUsage;
    json["threadCount"] = threadCount;
    json["isSigned"] = isSigned;
    json["signerName"] = WideToUtf8(signerName);
    return json.dump(2);
}

std::string BrowserMinerInfo::ToJson() const {
    nlohmann::json json;
    json["browserPid"] = browserPid;
    json["browserType"] = browserType;
    json["url"] = url;
    json["domain"] = domain;
    json["scriptSource"] = scriptSource;
    json["isWASM"] = isWASM;
    json["isWebWorker"] = isWebWorker;
    json["coresUsed"] = coresUsed;
    json["throttlePercent"] = throttlePercent;
    json["minerLibrary"] = minerLibrary;
    json["poolConnection"] = nlohmann::json::parse(poolConnection.ToJson());
    return json.dump(2);
}

std::string MinerDetectionResult::ToJson() const {
    nlohmann::json json;
    json["detectionId"] = detectionId;
    json["isMinerDetected"] = isMinerDetected;
    json["minerType"] = std::string(GetMinerTypeName(minerType));
    json["minerFamily"] = std::string(GetMinerFamilyName(minerFamily));
    json["minerName"] = minerName;
    json["minerVersion"] = minerVersion;
    json["algorithm"] = std::string(GetMiningAlgorithmName(algorithm));
    json["cryptocurrency"] = std::string(GetCryptocurrencyName(cryptocurrency));
    json["source"] = std::string(GetDetectionSourceName(source));
    json["additionalSources"] = nlohmann::json::array();
    for (const auto additionalSource : additionalSources) {
        json["additionalSources"].push_back(std::string(GetDetectionSourceName(additionalSource)));
    }
    json["severity"] = static_cast<int>(severity);
    json["confidenceScore"] = confidenceScore;
    json["threatScore"] = threatScore;
    json["processInfo"] = nlohmann::json::parse(processInfo.ToJson());
    if (browserInfo.has_value()) {
        json["browserInfo"] = nlohmann::json::parse(browserInfo->ToJson());
    }
    json["resourceStats"] = nlohmann::json::parse(resourceStats.ToJson());
    json["poolAddresses"] = poolAddresses;
    json["walletAddresses"] = walletAddresses;
    json["actionTaken"] = static_cast<int>(actionTaken);
    json["detectionTime"] = ToUnixMillis(detectionTime);
    json["analysisDurationMs"] = analysisDuration.count();
    json["isWhitelisted"] = isWhitelisted;
    json["whitelistReason"] = whitelistReason;
    json["mitreTechniques"] = mitreTechniques;
    return json.dump(2);
}

std::string MiningPoolInfo::ToJson() const {
    nlohmann::json json;
    json["address"] = address;
    json["port"] = port;
    json["name"] = name;
    json["isMalicious"] = isMalicious;
    json["ipAddresses"] = ipAddresses;
    json["algorithms"] = nlohmann::json::array();
    for (const auto algorithm : algorithms) {
        json["algorithms"].push_back(std::string(GetMiningAlgorithmName(algorithm)));
    }
    json["cryptocurrencies"] = nlohmann::json::array();
    for (const auto currency : cryptocurrencies) {
        json["cryptocurrencies"].push_back(std::string(GetCryptocurrencyName(currency)));
    }
    return json.dump(2);
}

std::string_view GetMinerTypeName(MinerType type) noexcept {
    switch (type) {
        case MinerType::CPUMiner: return "CPU Miner";
        case MinerType::GPUMiner: return "GPU Miner";
        case MinerType::BrowserMiner: return "Browser Miner";
        case MinerType::BotnetMiner: return "Botnet Miner";
        case MinerType::CloudMiner: return "Cloud Miner";
        case MinerType::HybridMiner: return "Hybrid Miner";
        default: return "Unknown";
    }
}

std::string_view GetMiningProtocolName(MiningProtocol protocol) noexcept {
    switch (protocol) {
        case MiningProtocol::Stratum: return "Stratum";
        case MiningProtocol::StratumV2: return "StratumV2";
        case MiningProtocol::GetBlockTemplate: return "GetBlockTemplate";
        case MiningProtocol::GetWork: return "GetWork";
        case MiningProtocol::NiceHash: return "NiceHash";
        case MiningProtocol::EthProxy: return "EthProxy";
        case MiningProtocol::CryptoNight: return "CryptoNight";
        case MiningProtocol::RandomX: return "RandomX";
        default: return "Unknown";
    }
}

std::string_view GetMiningAlgorithmName(MiningAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case MiningAlgorithm::SHA256: return "SHA256";
        case MiningAlgorithm::Scrypt: return "Scrypt";
        case MiningAlgorithm::Ethash: return "Ethash";
        case MiningAlgorithm::Etchash: return "Etchash";
        case MiningAlgorithm::CryptoNightR: return "CryptoNightR";
        case MiningAlgorithm::RandomX: return "RandomX";
        case MiningAlgorithm::Kawpow: return "Kawpow";
        case MiningAlgorithm::Autolykos: return "Autolykos";
        case MiningAlgorithm::Equihash: return "Equihash";
        case MiningAlgorithm::CuckooCycle: return "CuckooCycle";
        case MiningAlgorithm::ProgPow: return "ProgPow";
        default: return "Unknown";
    }
}

std::string_view GetCryptocurrencyName(Cryptocurrency crypto) noexcept {
    switch (crypto) {
        case Cryptocurrency::Bitcoin: return "Bitcoin";
        case Cryptocurrency::Ethereum: return "Ethereum";
        case Cryptocurrency::Monero: return "Monero";
        case Cryptocurrency::Litecoin: return "Litecoin";
        case Cryptocurrency::Ravencoin: return "Ravencoin";
        case Cryptocurrency::Zcash: return "Zcash";
        case Cryptocurrency::EthClassic: return "Ethereum Classic";
        case Cryptocurrency::Ergo: return "Ergo";
        case Cryptocurrency::Other: return "Other";
        default: return "Unknown";
    }
}

std::string_view GetDetectionSourceName(DetectionSource source) noexcept {
    switch (source) {
        case DetectionSource::CPUHeuristic: return "CPUHeuristic";
        case DetectionSource::GPUHeuristic: return "GPUHeuristic";
        case DetectionSource::NetworkStratum: return "NetworkStratum";
        case DetectionSource::NetworkPoolIP: return "NetworkPoolIP";
        case DetectionSource::NetworkPoolDomain: return "NetworkPoolDomain";
        case DetectionSource::SignatureBinary: return "SignatureBinary";
        case DetectionSource::SignatureMemory: return "SignatureMemory";
        case DetectionSource::SignatureConfig: return "SignatureConfig";
        case DetectionSource::BrowserScript: return "BrowserScript";
        case DetectionSource::BrowserWASM: return "BrowserWASM";
        case DetectionSource::ProcessBehavior: return "ProcessBehavior";
        case DetectionSource::ImportTable: return "ImportTable";
        case DetectionSource::ThreatIntel: return "ThreatIntel";
        default: return "Unknown";
    }
}

std::string_view GetMinerFamilyName(MinerFamily family) noexcept {
    switch (family) {
        case MinerFamily::XMRig: return "XMRig";
        case MinerFamily::XMRStak: return "XMR-Stak";
        case MinerFamily::CGMiner: return "CGMiner";
        case MinerFamily::BFGMiner: return "BFGMiner";
        case MinerFamily::PhoenixMiner: return "PhoenixMiner";
        case MinerFamily::TRexMiner: return "T-Rex";
        case MinerFamily::LolMiner: return "lolMiner";
        case MinerFamily::Ethminer: return "Ethminer";
        case MinerFamily::Claymore: return "Claymore";
        case MinerFamily::NiceHash: return "NiceHash";
        case MinerFamily::NBMiner: return "NBMiner";
        case MinerFamily::TeamRedMiner: return "TeamRedMiner";
        case MinerFamily::GMiner: return "GMiner";
        case MinerFamily::Coinhive: return "Coinhive";
        case MinerFamily::CryptoLoot: return "CryptoLoot";
        case MinerFamily::CoinIMP: return "CoinIMP";
        case MinerFamily::JSECoin: return "JSECoin";
        case MinerFamily::WebMinePool: return "WebMinePool";
        case MinerFamily::Custom: return "Custom";
        default: return "Unknown";
    }
}

bool IsMiningPort(uint16_t port) noexcept {
    return std::find(std::begin(MinerConstants::STRATUM_PORTS), std::end(MinerConstants::STRATUM_PORTS), port) != std::end(MinerConstants::STRATUM_PORTS);
}

bool ValidateWalletAddress(std::string_view address, Cryptocurrency crypto) {
    if (address.empty() || address.size() > 256) {
        return false;
    }

    const std::string value(address);
    switch (crypto) {
        case Cryptocurrency::Ethereum:
            return std::regex_match(value, std::regex(R"(^0x[a-fA-F0-9]{40}$)"));
        case Cryptocurrency::Bitcoin:
            return std::regex_match(value, std::regex(R"(^(bc1|[13])[a-zA-HJ-NP-Z0-9]{20,90}$)"));
        case Cryptocurrency::Monero:
            return std::regex_match(value, std::regex(R"(^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93,104}$)"));
        case Cryptocurrency::Litecoin:
            return std::regex_match(value, std::regex(R"(^(ltc1|[LM3])[a-km-zA-HJ-NP-Z1-9]{25,90}$)"));
        case Cryptocurrency::Ravencoin:
            return std::regex_match(value, std::regex(R"(^R[a-km-zA-HJ-NP-Z1-9]{25,34}$)"));
        case Cryptocurrency::Zcash:
            return std::regex_match(value, std::regex(R"(^(t1|t3|zs)[A-Za-z0-9]{30,120}$)"));
        case Cryptocurrency::EthClassic:
        case Cryptocurrency::Ergo:
        case Cryptocurrency::Other:
        case Cryptocurrency::Unknown:
        default:
            return std::none_of(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch) != 0; });
    }
}

} // namespace CryptoMiners
} // namespace ShadowStrike
