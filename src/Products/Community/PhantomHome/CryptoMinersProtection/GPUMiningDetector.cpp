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
#include "GPUMiningDetector.hpp"

#include "PhantomCore/HashStore/HashStore.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelLookup.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/SystemUtils.hpp"
#include "PhantomCore/Whitelist/WhiteListStore.hpp"

#include <Windows.h>
#include <dxgi1_6.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <psapi.h>
#include <wrl/client.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;
using Microsoft::WRL::ComPtr;

namespace ShadowStrike {
namespace CryptoMiners {

namespace {

constexpr std::chrono::seconds kMinimumSustainedWindow{10};
constexpr std::chrono::seconds kIntermittentWindow{60};
constexpr std::chrono::seconds kAlertCooldown{30};
constexpr std::chrono::milliseconds kMonitorWakeQuantum{200};
constexpr DWORD kPdhWarmupMs = 120;
constexpr size_t kMaxRecentDetections = 100;
constexpr size_t kMaxHistorySamples = 96;
constexpr size_t kMaxDagDirectoryEntries = 512;
constexpr double kComputeDetectionFloor = 60.0;
constexpr double kIntermittentDetectionFloor = 45.0;
constexpr double kGraphicsFalsePositiveFloor = 35.0;
constexpr double kCandidateProcessFloor = 12.5;
constexpr double kProcessMiningFloor = 20.0;

const std::unordered_set<std::wstring> kTrustedSystemProcesses = {
    L"dwm.exe",
    L"csrss.exe",
    L"winlogon.exe",
    L"explorer.exe",
    L"sihost.exe"
};

const std::vector<std::wstring> kKnownMinerProcesses = {
    L"ethminer.exe",
    L"phoenixminer.exe",
    L"lolminer.exe",
    L"t-rex.exe",
    L"gminer.exe",
    L"nbminer.exe",
    L"teamredminer.exe",
    L"xmrig.exe",
    L"nicehash.exe",
    L"cgminer.exe",
    L"bfgminer.exe",
    L"claymore.exe",
    L"kawpowminer.exe",
    L"nanominer.exe",
    L"trex.exe"
};

const std::vector<std::wstring> kDagFilePatterns = {
    L"dag-",
    L"ethash",
    L"etchash"
};

[[nodiscard]] std::wstring ToLowerCopy(std::wstring_view value) {
    return Utils::StringUtils::ToLowerCopy(value);
}

[[nodiscard]] std::string EscapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20U) {
                std::ostringstream hex;
                hex << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(ch));
                escaped += hex.str();
            } else {
                escaped.push_back(ch);
            }
            break;
        }
    }

    return escaped;
}

[[nodiscard]] std::string EscapeJson(const std::wstring& value) {
    return EscapeJson(Utils::StringUtils::WStringToString(value));
}

[[nodiscard]] double ClampPercent(double value) noexcept {
    if (!std::isfinite(value)) {
        return 0.0;
    }
    return std::clamp(value, 0.0, 100.0);
}

[[nodiscard]] uint64_t MakeLuidKey(const LUID& luid) noexcept {
    const auto high = static_cast<uint64_t>(static_cast<unsigned long>(luid.HighPart) & 0xFFFFFFFFUL);
    const auto low = static_cast<uint64_t>(static_cast<unsigned long>(luid.LowPart) & 0xFFFFFFFFUL);
    return (high << 32U) | low;
}

[[nodiscard]] GPUVendor VendorFromId(UINT vendorId) noexcept {
    switch (vendorId) {
    case 0x10DE: return GPUVendor::NVIDIA;
    case 0x1002:
    case 0x1022: return GPUVendor::AMD;
    case 0x8086: return GPUVendor::Intel;
    default: return vendorId == 0U ? GPUVendor::Unknown : GPUVendor::Other;
    }
}

[[nodiscard]] std::string LuidToString(const LUID& luid) {
    std::ostringstream oss;
    oss << "LUID-" << std::hex << std::setfill('0')
        << std::setw(8) << static_cast<uint32_t>(luid.HighPart)
        << '-' << std::setw(8) << static_cast<uint32_t>(luid.LowPart);
    return oss.str();
}

[[nodiscard]] bool IsSuspiciousProcessName(const std::wstring& processName) {
    const std::wstring lowered = ToLowerCopy(processName);
    if (lowered.empty()) {
        return false;
    }

    if (kTrustedSystemProcesses.contains(lowered)) {
        return false;
    }

    for (const auto& minerName : kKnownMinerProcesses) {
        if (lowered.find(ToLowerCopy(minerName)) != std::wstring::npos) {
            return true;
        }
    }

    return lowered.find(L"miner") != std::wstring::npos ||
           lowered.find(L"xmr") != std::wstring::npos ||
           lowered.find(L"stratum") != std::wstring::npos ||
           lowered.find(L"eth") != std::wstring::npos ||
           lowered.find(L"kawpow") != std::wstring::npos;
}

[[nodiscard]] bool IsSuspiciousCommandLine(const std::wstring& commandLine) {
    const std::wstring lowered = ToLowerCopy(commandLine);
    return lowered.find(L"--algo") != std::wstring::npos ||
           lowered.find(L"--pool") != std::wstring::npos ||
           lowered.find(L"stratum+") != std::wstring::npos ||
           lowered.find(L"wallet") != std::wstring::npos ||
           lowered.find(L"nicehash") != std::wstring::npos ||
           lowered.find(L"ethash") != std::wstring::npos ||
           lowered.find(L"etchash") != std::wstring::npos;
}

[[nodiscard]] bool IsWhitelistedProcess(
    const GPUMiningDetectorConfiguration& config,
    const std::wstring& processName,
    const std::wstring& processPath)
{
    const std::wstring loweredName = ToLowerCopy(processName);
    const std::wstring loweredPath = ToLowerCopy(processPath);

    for (const auto& entry : config.whitelistedApplications) {
        const std::wstring loweredEntry = ToLowerCopy(entry);

        // Exact match on process name (e.g., "blender.exe" == "blender.exe")
        if (!loweredName.empty() && loweredName == loweredEntry) {
            return true;
        }

        // Exact match on full path (e.g., "C:\Program Files\Blender\blender.exe")
        if (!loweredPath.empty() && loweredPath == loweredEntry) {
            return true;
        }

        // Path ends with the whitelisted entry as a full path component.
        // Requires a path separator immediately before the match to prevent
        // partial filename matches (e.g., "miner.exe" must not match "notminer.exe").
        if (!loweredPath.empty() && !loweredEntry.empty() &&
            loweredPath.size() > loweredEntry.size()) {
            const size_t expectedPos = loweredPath.size() - loweredEntry.size();
            if (loweredPath.compare(expectedPos, loweredEntry.size(), loweredEntry) == 0) {
                const wchar_t precedingChar = loweredPath[expectedPos - 1];
                if (precedingChar == L'\\' || precedingChar == L'/') {
                    return true;
                }
            }
        }
    }

    return false;
}

[[nodiscard]] std::optional<unsigned long long> ParseHexU64(const std::wstring& token) {
    if (token.empty()) {
        return std::nullopt;
    }

    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long value = std::wcstoull(token.c_str(), &end, 16);
    if (errno != 0 || end == token.c_str() || *end != L'\0') {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<unsigned long> ParseU32(const std::wstring& token) {
    if (token.empty()) {
        return std::nullopt;
    }

    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long value = std::wcstoul(token.c_str(), &end, 10);
    if (errno != 0 || end == token.c_str() || *end != L'\0') {
        return std::nullopt;
    }
    return value;
}

struct AdapterInventoryEntry {
    uint32_t index = 0;
    LUID luid{};
    uint64_t luidKey = 0;
    GPUDeviceStats stats;
};

struct ProcessTelemetry {
    uint32_t pid = 0;
    uint64_t luidKey = 0;
    double compute = 0.0;
    double graphics = 0.0;
    double copy = 0.0;
    double encode = 0.0;
    double decode = 0.0;
    uint64_t dedicatedBytes = 0;
    uint64_t sharedBytes = 0;
};

struct DeviceTelemetry {
    double compute = 0.0;
    double graphics = 0.0;
    double copy = 0.0;
    double encode = 0.0;
    double decode = 0.0;
    std::unordered_map<uint32_t, ProcessTelemetry> processes;
};

struct PdhSnapshot {
    bool engineTelemetryAvailable = false;
    bool processMemoryTelemetryAvailable = false;
    std::unordered_map<uint64_t, DeviceTelemetry> byAdapter;
};

struct DeviceHistorySample {
    TimePoint sampleTime{};
    double computeLoad = 0.0;
    double graphicsLoad = 0.0;
    double memoryUsedPercent = 0.0;
    bool dagDetected = false;
    size_t suspiciousProcessCount = 0;
};

struct RuntimeStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> devicesMonitored{0};
    std::atomic<uint64_t> miningDetections{0};
    std::atomic<uint64_t> processesTerminated{0};
    std::atomic<uint64_t> dagDetections{0};
    std::array<std::atomic<uint64_t>, 16> byAlgorithm{};
    std::atomic<int64_t> startTimeNs{Clock::now().time_since_epoch().count()};

    [[nodiscard]] TimePoint GetStartTime() const noexcept {
        return TimePoint(Clock::duration(startTimeNs.load(std::memory_order_relaxed)));
    }

    void Reset() noexcept {
        totalScans.store(0, std::memory_order_relaxed);
        devicesMonitored.store(0, std::memory_order_relaxed);
        miningDetections.store(0, std::memory_order_relaxed);
        processesTerminated.store(0, std::memory_order_relaxed);
        dagDetections.store(0, std::memory_order_relaxed);
        for (auto& counter : byAlgorithm) {
            counter.store(0, std::memory_order_relaxed);
        }
        startTimeNs.store(Clock::now().time_since_epoch().count(), std::memory_order_relaxed);
    }
};

struct ScanExecutionResult {
    std::vector<GPUDeviceStats> devices;
    std::vector<GPUDeviceStats> anomalies;
    std::vector<GPUMiningDetectionResult> detections;
};

class ScopedModule final {
public:
    ScopedModule() = default;
    explicit ScopedModule(HMODULE module) noexcept : m_module(module) {}
    ~ScopedModule() noexcept { Reset(); }

    ScopedModule(const ScopedModule&) = delete;
    ScopedModule& operator=(const ScopedModule&) = delete;

    ScopedModule(ScopedModule&& other) noexcept : m_module(other.m_module) {
        other.m_module = nullptr;
    }

    ScopedModule& operator=(ScopedModule&& other) noexcept {
        if (this != &other) {
            Reset();
            m_module = other.m_module;
            other.m_module = nullptr;
        }
        return *this;
    }

    void Reset(HMODULE module = nullptr) noexcept {
        if (m_module != nullptr) {
            ::FreeLibrary(m_module);
        }
        m_module = module;
    }

    [[nodiscard]] HMODULE Get() const noexcept { return m_module; }
    [[nodiscard]] bool IsValid() const noexcept { return m_module != nullptr; }

private:
    HMODULE m_module = nullptr;
};

class ScopedPdhQuery final {
public:
    ScopedPdhQuery() = default;
    ~ScopedPdhQuery() noexcept { Reset(); }

    ScopedPdhQuery(const ScopedPdhQuery&) = delete;
    ScopedPdhQuery& operator=(const ScopedPdhQuery&) = delete;

    [[nodiscard]] bool Open() noexcept {
        Reset();
        return ::PdhOpenQueryW(nullptr, 0, &m_query) == ERROR_SUCCESS;
    }

    void Reset() noexcept {
        if (m_query != nullptr) {
            ::PdhCloseQuery(m_query);
            m_query = nullptr;
        }
    }

    [[nodiscard]] PDH_HQUERY Get() const noexcept { return m_query; }

private:
    PDH_HQUERY m_query = nullptr;
};

/// @brief RAII wrapper for Win32 HANDLE (process handles, etc.)
class ScopedHandle final {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) noexcept : m_handle(h) {}
    ~ScopedHandle() noexcept { Reset(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    void Reset(HANDLE h = nullptr) noexcept {
        if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
        }
        m_handle = h;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE m_handle = nullptr;
};

struct CounterRegistration {
    std::wstring path;
    std::wstring instance;
    std::wstring counterName;
    PDH_HCOUNTER handle = nullptr;
};

[[nodiscard]] HMODULE LoadSystemLibrary(std::wstring_view name) noexcept {
    return ::LoadLibraryExW(std::wstring(name).c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
}

[[nodiscard]] std::vector<std::wstring> ReadMultiSz(const std::vector<wchar_t>& buffer) {
    std::vector<std::wstring> values;
    size_t offset = 0;

    while (offset < buffer.size() && buffer[offset] != L'\0') {
        const std::wstring value(&buffer[offset]);
        offset += value.size() + 1;
        if (!value.empty()) {
            values.push_back(value);
        }
    }

    return values;
}

[[nodiscard]] std::vector<std::wstring> ExpandPdhPaths(const std::wstring& wildcardPath) {
    DWORD requiredSize = 0;
    PDH_STATUS status = ::PdhExpandWildCardPathW(nullptr, wildcardPath.c_str(), nullptr, &requiredSize, 0);
    if (status != PDH_MORE_DATA || requiredSize == 0) {
        return {};
    }

    std::vector<wchar_t> buffer(requiredSize);
    status = ::PdhExpandWildCardPathW(nullptr, wildcardPath.c_str(), buffer.data(), &requiredSize, 0);
    if (status != ERROR_SUCCESS) {
        return {};
    }

    return ReadMultiSz(buffer);
}

[[nodiscard]] std::wstring ExtractInstanceFromPdhPath(const std::wstring& counterPath) {
    const size_t openPos = counterPath.find(L'(');
    const size_t closePos = counterPath.rfind(L")\\");
    if (openPos == std::wstring::npos || closePos == std::wstring::npos || closePos <= openPos + 1) {
        return {};
    }

    std::wstring instance = counterPath.substr(openPos + 1, closePos - openPos - 1);
    size_t escapedPos = 0;
    while ((escapedPos = instance.find(L"))", escapedPos)) != std::wstring::npos) {
        instance.replace(escapedPos, 2, L")");
        ++escapedPos;
    }
    return instance;
}

[[nodiscard]] std::wstring EscapePdhInstance(std::wstring instance) {
    size_t pos = 0;
    while ((pos = instance.find(L')', pos)) != std::wstring::npos) {
        instance.insert(pos, 1, L')');
        pos += 2;
    }
    return instance;
}

[[nodiscard]] bool AddEnglishCounter(
    PDH_HQUERY query,
    const std::wstring& path,
    PDH_HCOUNTER& counter) noexcept
{
    return ::PdhAddEnglishCounterW(query, path.c_str(), 0, &counter) == ERROR_SUCCESS;
}

[[nodiscard]] std::optional<double> ReadPdhDouble(PDH_HCOUNTER counter) noexcept {
    PDH_FMT_COUNTERVALUE value{};
    const PDH_STATUS status = ::PdhGetFormattedCounterValue(
        counter,
        PDH_FMT_DOUBLE | PDH_FMT_NOCAP100,
        nullptr,
        &value);

    if (status != ERROR_SUCCESS ||
        (value.CStatus != ERROR_SUCCESS && value.CStatus != PDH_CSTATUS_VALID_DATA)) {
        return std::nullopt;
    }

    return value.doubleValue;
}

struct ParsedGpuInstance {
    bool valid = false;
    uint32_t pid = 0;
    uint64_t luidKey = 0;
    std::wstring engineType;
};

[[nodiscard]] ParsedGpuInstance ParseGpuInstance(const std::wstring& instance) {
    ParsedGpuInstance parsed;
    std::vector<std::wstring> tokens;
    std::wstring token;
    std::wistringstream stream(instance);

    while (std::getline(stream, token, L'_')) {
        tokens.push_back(token);
    }

    for (size_t index = 0; index < tokens.size(); ++index) {
        if (tokens[index] == L"pid" && index + 1 < tokens.size()) {
            if (const auto pid = ParseU32(tokens[index + 1])) {
                parsed.pid = static_cast<uint32_t>(*pid);
            }
        } else if (tokens[index] == L"luid" && index + 2 < tokens.size()) {
            const auto high = ParseHexU64(tokens[index + 1]);
            const auto low = ParseHexU64(tokens[index + 2]);
            if (high && low) {
                parsed.luidKey = ((*high & 0xFFFFFFFFULL) << 32U) | (*low & 0xFFFFFFFFULL);
            }
        } else if (tokens[index] == L"engtype" && index + 1 < tokens.size()) {
            parsed.engineType = tokens[index + 1];
            for (size_t engineIndex = index + 2; engineIndex < tokens.size(); ++engineIndex) {
                parsed.engineType += L'_';
                parsed.engineType += tokens[engineIndex];
            }
            break;
        }
    }

    parsed.valid = parsed.luidKey != 0;
    return parsed;
}

enum class EngineCategory : uint8_t {
    Unknown = 0,
    Compute,
    Graphics,
    Copy,
    Encode,
    Decode
};

[[nodiscard]] EngineCategory ClassifyEngineType(const std::wstring& engineType) {
    const std::wstring lowered = ToLowerCopy(engineType);
    if (lowered.find(L"compute") != std::wstring::npos) {
        return EngineCategory::Compute;
    }
    if (lowered.find(L"3d") != std::wstring::npos || lowered.find(L"graphics") != std::wstring::npos) {
        return EngineCategory::Graphics;
    }
    if (lowered.find(L"copy") != std::wstring::npos) {
        return EngineCategory::Copy;
    }
    if (lowered.find(L"encode") != std::wstring::npos) {
        return EngineCategory::Encode;
    }
    if (lowered.find(L"decode") != std::wstring::npos || lowered.find(L"video") != std::wstring::npos) {
        return EngineCategory::Decode;
    }
    return EngineCategory::Unknown;
}

void AccumulateEngineValue(ProcessTelemetry& process, EngineCategory category, double value) {
    switch (category) {
    case EngineCategory::Compute:
        process.compute += value;
        break;
    case EngineCategory::Graphics:
        process.graphics += value;
        break;
    case EngineCategory::Copy:
        process.copy += value;
        break;
    case EngineCategory::Encode:
        process.encode += value;
        break;
    case EngineCategory::Decode:
        process.decode += value;
        break;
    case EngineCategory::Unknown:
        break;
    }
}

void AccumulateEngineValue(DeviceTelemetry& device, EngineCategory category, double value) {
    switch (category) {
    case EngineCategory::Compute:
        device.compute += value;
        break;
    case EngineCategory::Graphics:
        device.graphics += value;
        break;
    case EngineCategory::Copy:
        device.copy += value;
        break;
    case EngineCategory::Encode:
        device.encode += value;
        break;
    case EngineCategory::Decode:
        device.decode += value;
        break;
    case EngineCategory::Unknown:
        break;
    }
}

[[nodiscard]] std::optional<ComputeAPI> DetectComputeApi(uint32_t processId) {
    std::vector<Utils::ProcessUtils::ProcessModuleInfo> modules;
    if (!Utils::ProcessUtils::EnumerateProcessModules(processId, modules, nullptr)) {
        return std::nullopt;
    }

    for (const auto& module : modules) {
        const std::wstring lowered = ToLowerCopy(module.name);
        if (lowered.find(L"cudart") != std::wstring::npos ||
            lowered.find(L"nvcuda") != std::wstring::npos ||
            lowered.find(L"nvopencl") != std::wstring::npos) {
            return ComputeAPI::CUDA;
        }
        if (lowered.find(L"opencl") != std::wstring::npos ||
            lowered.find(L"amdocl") != std::wstring::npos) {
            return ComputeAPI::OpenCL;
        }
        if (lowered.find(L"d3d12") != std::wstring::npos ||
            lowered.find(L"d3d11") != std::wstring::npos) {
            return ComputeAPI::DirectCompute;
        }
        if (lowered.find(L"vulkan") != std::wstring::npos) {
            return ComputeAPI::VulkanCompute;
        }
    }

    return ComputeAPI::Unknown;
}

[[nodiscard]] bool IsMiningProcessCandidate(const GPUProcessInfo& process) noexcept {
    return !process.isWhitelisted &&
           (process.isSuspectedMiner || process.computeLoadPercent >= kProcessMiningFloor);
}

[[nodiscard]] GPUMiningAlgorithm DetectAlgorithmFromPattern(
    double computeLoad,
    double memoryPercent,
    uint64_t vramUsed,
    bool dagDetected) noexcept
{
    const uint64_t dagMin = static_cast<uint64_t>(GPUMiningConstants::DAG_MIN_SIZE_GB * 1024.0 * 1024.0 * 1024.0);
    const uint64_t dagMax = static_cast<uint64_t>(GPUMiningConstants::DAG_MAX_SIZE_GB * 1024.0 * 1024.0 * 1024.0);

    if (dagDetected || (vramUsed >= dagMin && vramUsed <= dagMax && memoryPercent >= 60.0)) {
        return GPUMiningAlgorithm::Ethash;
    }
    if (computeLoad >= 90.0 && memoryPercent >= 45.0 && memoryPercent <= 80.0) {
        return GPUMiningAlgorithm::Kawpow;
    }
    if (computeLoad >= 65.0 && computeLoad < 85.0 && memoryPercent >= 70.0) {
        return GPUMiningAlgorithm::Autolykos;
    }
    if (computeLoad >= 75.0 && memoryPercent >= 80.0) {
        return GPUMiningAlgorithm::Equihash;
    }
    if (computeLoad >= 95.0) {
        return GPUMiningAlgorithm::ProgPow;
    }
    return GPUMiningAlgorithm::Unknown;
}

[[nodiscard]] std::optional<uint64_t> FindDagFileSizeInternal(uint32_t processId) {
    auto processPath = Utils::ProcessUtils::GetProcessPath(processId, nullptr);
    if (!processPath || processPath->empty()) {
        return std::nullopt;
    }

    std::error_code ec;
    const fs::path processImagePath(*processPath);
    const fs::path workingDirectory = processImagePath.parent_path();
    if (workingDirectory.empty() || !fs::exists(workingDirectory, ec) || ec) {
        return std::nullopt;
    }

    size_t entriesScanned = 0;
    for (fs::directory_iterator iterator(workingDirectory, fs::directory_options::skip_permission_denied, ec);
         !ec && iterator != fs::directory_iterator(); iterator.increment(ec)) {
        if (entriesScanned++ >= kMaxDagDirectoryEntries) {
            break;
        }

        const fs::directory_entry& entry = *iterator;
        if (!entry.is_regular_file(ec) || ec) {
            continue;
        }

        const std::wstring loweredName = ToLowerCopy(entry.path().filename().wstring());
        bool nameMatches = false;
        for (const auto& pattern : kDagFilePatterns) {
            if (loweredName.find(pattern) != std::wstring::npos) {
                nameMatches = true;
                break;
            }
        }

        if (!nameMatches) {
            continue;
        }

        const uint64_t fileSize = entry.file_size(ec);
        if (ec) {
            continue;
        }

        const uint64_t dagMin = static_cast<uint64_t>(GPUMiningConstants::DAG_MIN_SIZE_GB * 1024.0 * 1024.0 * 1024.0);
        const uint64_t dagMax = static_cast<uint64_t>(GPUMiningConstants::DAG_MAX_SIZE_GB * 1024.0 * 1024.0 * 1024.0);
        if (fileSize >= dagMin && fileSize <= dagMax) {
            return fileSize;
        }
    }

    return std::nullopt;
}

} // namespace

[[nodiscard]] std::string GPUProcessInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"processId\":" << processId;
    oss << ",\"processName\":\"" << EscapeJson(processName) << "\"";
    oss << ",\"processPath\":\"" << EscapeJson(processPath) << "\"";
    oss << ",\"vramUsedBytes\":" << vramUsedBytes;
    oss << ",\"hasComputeContext\":" << (hasComputeContext ? "true" : "false");
    oss << ",\"computeAPI\":\"" << GetComputeAPIName(computeAPI) << "\"";
    oss << ",\"gpuUtilization\":" << std::fixed << std::setprecision(2) << gpuUtilization;
    oss << ",\"computeLoadPercent\":" << computeLoadPercent;
    oss << ",\"graphicsLoadPercent\":" << graphicsLoadPercent;
    oss << ",\"copyLoadPercent\":" << copyLoadPercent;
    oss << ",\"telemetryAvailable\":" << (telemetryAvailable ? "true" : "false");
    oss << ",\"isComputeIntensive\":" << (isComputeIntensive ? "true" : "false");
    oss << ",\"isWhitelisted\":" << (isWhitelisted ? "true" : "false");
    oss << ",\"isSuspectedMiner\":" << (isSuspectedMiner ? "true" : "false");
    oss << ",\"suspectedAlgorithm\":\"" << GetGPUMiningAlgorithmName(suspectedAlgorithm) << "\"";
    oss << ",\"confidence\":\"" << GetDetectionConfidenceName(confidence) << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string GPUDeviceStats::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"deviceIndex\":" << deviceIndex;
    oss << ",\"deviceName\":\"" << EscapeJson(deviceName) << "\"";
    oss << ",\"vendor\":\"" << GetGPUVendorName(vendor) << "\"";
    oss << ",\"pciBusId\":\"" << EscapeJson(pciBusId) << "\"";
    oss << ",\"gpuLoadPercent\":" << std::fixed << std::setprecision(2) << gpuLoadPercent;
    oss << ",\"computeLoadPercent\":" << computeLoadPercent;
    oss << ",\"graphicsLoadPercent\":" << graphicsLoadPercent;
    oss << ",\"copyLoadPercent\":" << copyLoadPercent;
    oss << ",\"encodeLoadPercent\":" << encodeLoadPercent;
    oss << ",\"decodeLoadPercent\":" << decodeLoadPercent;
    oss << ",\"memoryUsedPercent\":" << memoryUsedPercent;
    oss << ",\"memoryTotalBytes\":" << memoryTotalBytes;
    oss << ",\"memoryUsedBytes\":" << memoryUsedBytes;
    oss << ",\"telemetryAvailable\":" << (telemetryAvailable ? "true" : "false");
    oss << ",\"processTelemetryAvailable\":" << (processTelemetryAvailable ? "true" : "false");
    oss << ",\"vendorTelemetryAvailable\":" << (vendorTelemetryAvailable ? "true" : "false");
    oss << ",\"isMiningActivity\":" << (isMiningActivity ? "true" : "false");
    oss << ",\"dagDetected\":" << (dagDetected ? "true" : "false");
    oss << ",\"suspectedAlgorithm\":\"" << GetGPUMiningAlgorithmName(suspectedAlgorithm) << "\"";
    oss << ",\"confidence\":\"" << GetDetectionConfidenceName(confidence) << "\"";
    oss << ",\"detectionSummary\":\"" << EscapeJson(detectionSummary) << "\"";
    oss << ",\"processCount\":" << processes.size();
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string GPUMiningDetectionResult::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"detectionId\":\"" << EscapeJson(detectionId) << "\"";
    oss << ",\"isMiningDetected\":" << (isMiningDetected ? "true" : "false");
    oss << ",\"deviceStats\":" << deviceStats.ToJson();
    oss << ",\"miningProcessCount\":" << miningProcesses.size();
    oss << ",\"primaryAlgorithm\":\"" << GetGPUMiningAlgorithmName(primaryAlgorithm) << "\"";
    oss << ",\"confidence\":\"" << GetDetectionConfidenceName(confidence) << "\"";
    oss << ",\"detectionSummary\":\"" << EscapeJson(detectionSummary) << "\"";
    oss << ",\"analysisDurationMs\":" << analysisDuration.count();
    oss << "}";
    return oss.str();
}

void GPUMiningStatistics::Reset() noexcept {
    totalScans = 0;
    devicesMonitored = 0;
    miningDetections = 0;
    processesTerminated = 0;
    dagDetections = 0;
    byAlgorithm.fill(0);
    startTime = Clock::now();
}

[[nodiscard]] std::string GPUMiningStatistics::ToJson() const {
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - startTime);
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalScans\":" << totalScans;
    oss << ",\"devicesMonitored\":" << devicesMonitored;
    oss << ",\"miningDetections\":" << miningDetections;
    oss << ",\"processesTerminated\":" << processesTerminated;
    oss << ",\"dagDetections\":" << dagDetections;
    oss << ",\"uptimeSeconds\":" << uptime.count();
    oss << "}";
    return oss.str();
}

[[nodiscard]] bool GPUMiningDetectorConfiguration::IsValid() const noexcept {
    static constexpr size_t kMaxWhitelistedApps = 256;
    return std::isfinite(gpuLoadThreshold) && gpuLoadThreshold >= 0.0 && gpuLoadThreshold <= 100.0 &&
           std::isfinite(memoryThreshold) && memoryThreshold >= 0.0 && memoryThreshold <= 100.0 &&
           std::isfinite(temperatureWarning) && temperatureWarning >= 0.0 && temperatureWarning <= 150.0 &&
           scanIntervalMs >= 500U && scanIntervalMs <= 60000U &&
           whitelistedApplications.size() <= kMaxWhitelistedApps;
}

class GPUMiningDetectorImpl final {
public:
    GPUMiningDetectorImpl() = default;
    ~GPUMiningDetectorImpl() {
        Shutdown();
    }

    GPUMiningDetectorImpl(const GPUMiningDetectorImpl&) = delete;
    GPUMiningDetectorImpl& operator=(const GPUMiningDetectorImpl&) = delete;
    GPUMiningDetectorImpl(GPUMiningDetectorImpl&&) = delete;
    GPUMiningDetectorImpl& operator=(GPUMiningDetectorImpl&&) = delete;

    [[nodiscard]] bool Initialize(const GPUMiningDetectorConfiguration& config) {
        if (!config.IsValid()) {
            Utils::Logger::Error("GPUMiningDetector: invalid configuration");
            return false;
        }

        const bool alreadyInitialized = m_initialized.exchange(true, std::memory_order_acq_rel);
        if (alreadyInitialized) {
            Utils::Logger::Warn("GPUMiningDetector: already initialized");
            std::unique_lock lock(m_mutex);
            m_config = config;
            return true;
        }

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        try {
            {
                std::unique_lock lock(m_mutex);
                m_config = config;
                m_recentDetections.clear();
                m_deviceHistory.clear();
                m_lastDetectionsByDevice.clear();
                m_lastScanResults.clear();
                m_deviceCount = 0;
                m_loggedTelemetryUnavailable = false;
            }

            InitializeVendorLibraries();

            auto initialScan = ExecuteScan(false);
            {
                std::unique_lock lock(m_mutex);
                m_lastScanResults = initialScan.devices;
                m_deviceCount = initialScan.devices.size();
                m_lastScanTime = Clock::now();
            }

            m_status.store(ModuleStatus::Stopped, std::memory_order_release);
            Utils::Logger::Info(
                "GPUMiningDetector: initialized (devices={}, nvml={}, adl={})",
                initialScan.devices.size(),
                m_nvmlAvailable.load(std::memory_order_acquire),
                m_adlAvailable.load(std::memory_order_acquire));
            return true;
        } catch (const std::exception& ex) {
            Utils::Logger::Error("GPUMiningDetector: initialization failed - {}", ex.what());
            ShutdownVendorLibraries();
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }
    }

    void Shutdown() noexcept {
        try {
            (void)Stop();

            std::unique_lock lock(m_mutex);
            m_anomalyCallbacks.clear();
            m_miningCallbacks.clear();
            m_errorCallbacks.clear();
            m_recentDetections.clear();
            m_deviceHistory.clear();
            m_lastDetectionsByDevice.clear();
            m_lastScanResults.clear();
            m_deviceCount = 0;
            ShutdownVendorLibraries();
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Uninitialized, std::memory_order_release);
        } catch (...) {
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
        }
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool Start() {
        if (!IsInitialized()) {
            Utils::Logger::Error("GPUMiningDetector: cannot start before initialization");
            return false;
        }

        std::thread threadToJoin;
        {
            std::unique_lock monitorLock(m_monitorMutex);
            m_monitorStateCv.wait(monitorLock, [this]() noexcept { return !m_monitorTransitionInProgress; });

            const auto status = m_status.load(std::memory_order_acquire);
            if (status == ModuleStatus::Running || status == ModuleStatus::Scanning || status == ModuleStatus::Paused) {
                return true;
            }

            m_monitorTransitionInProgress = true;
            if (m_monitorThread.joinable()) {
                threadToJoin = std::move(m_monitorThread);
            }
        }

        if (threadToJoin.joinable()) {
            threadToJoin.join();
        }

        try {
            std::lock_guard monitorLock(m_monitorMutex);
            m_stopRequested.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Running, std::memory_order_release);
            m_monitorThread = std::thread([this]() { MonitorThreadProc(); });
            m_monitorTransitionInProgress = false;
        } catch (const std::exception& ex) {
            {
                std::lock_guard monitorLock(m_monitorMutex);
                m_monitorTransitionInProgress = false;
            }
            m_status.store(ModuleStatus::Stopped, std::memory_order_release);
            m_monitorStateCv.notify_all();
            Utils::Logger::Error("GPUMiningDetector: failed to create monitor thread - {}", ex.what());
            return false;
        }

        m_monitorStateCv.notify_all();
        Utils::Logger::Info("GPUMiningDetector: monitoring started");
        return true;
    }

    [[nodiscard]] bool Stop() {
        m_status.store(ModuleStatus::Stopping, std::memory_order_release);
        m_stopRequested.store(true, std::memory_order_release);
        m_monitorCv.notify_all();

        std::thread threadToJoin;
        {
            std::unique_lock monitorLock(m_monitorMutex);
            m_monitorStateCv.wait(monitorLock, [this]() noexcept { return !m_monitorTransitionInProgress; });
            if (m_monitorThread.joinable()) {
                threadToJoin = std::move(m_monitorThread);
            }
        }

        if (threadToJoin.joinable()) {
            threadToJoin.join();
        }

        if (IsInitialized()) {
            m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        }
        return true;
    }

    void Pause() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("GPUMiningDetector: Pause rejected — module is not initialized");
            return;
        }
        const auto current = m_status.load(std::memory_order_acquire);
        if (current == ModuleStatus::Running || current == ModuleStatus::Scanning) {
            m_status.store(ModuleStatus::Paused, std::memory_order_release);
            m_monitorCv.notify_all();
        }
    }

    void Resume() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("GPUMiningDetector: Resume rejected — module is not initialized");
            return;
        }
        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
            m_status.store(ModuleStatus::Running, std::memory_order_release);
            m_monitorCv.notify_all();
        }
    }

    [[nodiscard]] bool UpdateConfiguration(const GPUMiningDetectorConfiguration& config) {
        if (!config.IsValid()) {
            Utils::Logger::Error("GPUMiningDetector: rejected invalid configuration update");
            return false;
        }

        {
            std::unique_lock lock(m_mutex);
            m_config = config;
        }
        m_monitorCv.notify_all();
        return true;
    }

    [[nodiscard]] GPUMiningDetectorConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    [[nodiscard]] std::vector<GPUDeviceStats> ScanDevices() {
        const auto scanResult = ExecuteScan(false);
        return scanResult.devices;
    }

    [[nodiscard]] std::optional<GPUDeviceStats> GetDeviceStats(uint32_t deviceIndex) const {
        {
            std::shared_lock lock(m_mutex);
            for (const auto& device : m_lastScanResults) {
                if (device.deviceIndex == deviceIndex) {
                    return device;
                }
            }
        }

        const auto devices = CollectReadOnlyDevices(GetConfiguration());
        for (const auto& device : devices) {
            if (device.deviceIndex == deviceIndex) {
                return device;
            }
        }

        return std::nullopt;
    }

    [[nodiscard]] std::vector<uint32_t> IdentifyMiningProcesses() {
        auto scanResult = ExecuteScan(false);
        std::set<uint32_t> minerPids;

        for (const auto& device : scanResult.devices) {
            for (const auto& process : device.processes) {
                if (process.isSuspectedMiner && !process.isWhitelisted) {
                    minerPids.insert(process.processId);
                }
            }
        }

        return {minerPids.begin(), minerPids.end()};
    }

    [[nodiscard]] std::vector<GPUProcessInfo> GetGPUProcesses(uint32_t deviceIndex) const {
        {
            std::shared_lock lock(m_mutex);
            for (const auto& device : m_lastScanResults) {
                if (device.deviceIndex == deviceIndex) {
                    return device.processes;
                }
            }
        }

        const auto devices = CollectReadOnlyDevices(GetConfiguration());
        for (const auto& device : devices) {
            if (device.deviceIndex == deviceIndex) {
                return device.processes;
            }
        }

        return {};
    }

    [[nodiscard]] bool DetectDAGGenerated(uint32_t processId) {
        const auto dagSize = FindDagFileSizeInternal(processId);
        if (dagSize) {
            m_stats.dagDetections.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        return false;
    }

    [[nodiscard]] std::optional<uint64_t> GetDetectedDAGSize(uint32_t processId) const {
        return FindDagFileSizeInternal(processId);
    }

    [[nodiscard]] size_t GetDeviceCount() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_deviceCount;
    }

    [[nodiscard]] bool IsNVMLAvailable() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_nvmlAvailable.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool IsADLAvailable() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_adlAvailable.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool TerminateMiningProcess(uint32_t processId) {
        GPUMiningDetectorConfiguration configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;
        }

        if (!configSnapshot.terminateMiningProcesses) {
            Utils::Logger::Warn("GPUMiningDetector: termination requested while disabled by policy");
            return false;
        }

        if (processId == 0 || processId == 4 || processId == ::GetCurrentProcessId() ||
            Utils::ProcessUtils::IsProcessCritical(processId, nullptr) ||
            Utils::ProcessUtils::IsProcessProtected(processId, nullptr)) {
            Utils::Logger::Warn("GPUMiningDetector: refusing to terminate protected/system PID {}", processId);
            return false;
        }

        // Pin the kernel process object by opening a handle early.
        // This eliminates the TOCTOU window: even if the PID is recycled by the OS,
        // this handle continues to reference the ORIGINAL process.
        ScopedHandle pinnedHandle(::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, processId));
        if (!pinnedHandle) {
            Utils::Logger::Warn("GPUMiningDetector: could not open handle for PID {}; aborting termination", processId);
            return false;
        }

        // Capture identity via the pinned handle (not PID) to avoid races
        const auto originalPath = Utils::ProcessUtils::GetProcessPath(processId, nullptr);
        const auto originalName = Utils::ProcessUtils::GetProcessName(processId, nullptr);
        if (!originalPath && !originalName) {
            Utils::Logger::Warn("GPUMiningDetector: refusing to terminate PID {} because identity could not be verified", processId);
            return false;
        }

        auto currentMiners = IdentifyMiningProcesses();
        if (std::find(currentMiners.begin(), currentMiners.end(), processId) == currentMiners.end()) {
            Utils::Logger::Warn("GPUMiningDetector: refusing to terminate PID {} without active mining evidence", processId);
            return false;
        }

        // Revalidate identity using the SAME pinned handle — if the process exited
        // and PID was recycled, the handle still points to the original (now-exited) process,
        // and GetProcessPath will fail or return the original path, not the new process's path.
        const auto revalidatedPath = Utils::ProcessUtils::GetProcessPath(processId, nullptr);
        const auto revalidatedName = Utils::ProcessUtils::GetProcessName(processId, nullptr);
        if ((originalPath && revalidatedPath && *originalPath != *revalidatedPath) ||
            (originalName && revalidatedName && *originalName != *revalidatedName) ||
            Utils::ProcessUtils::IsProcessCritical(processId, nullptr) ||
            Utils::ProcessUtils::IsProcessProtected(processId, nullptr)) {
            Utils::Logger::Warn("GPUMiningDetector: PID {} changed identity during validation; aborting termination", processId);
            return false;
        }

        // Terminate using the pinned handle — guaranteed to target the original process
        if (::TerminateProcess(pinnedHandle.Get(), 1) == FALSE) {
            Utils::Logger::Error("GPUMiningDetector: failed to terminate PID {} (Win32={})",
                processId, ::GetLastError());
            return false;
        }

        m_stats.processesTerminated.fetch_add(1, std::memory_order_relaxed);
        Utils::Logger::Warn("GPUMiningDetector: terminated suspected miner PID {}", processId);
        return true;
    }

    void RegisterAnomalyCallback(GPUAnomalyCallback callback) {
        if (!callback) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_anomalyCallbacks.push_back(std::move(callback));
    }

    void RegisterMiningDetectedCallback(GPUMiningDetectedCallback callback) {
        if (!callback) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_miningCallbacks.push_back(std::move(callback));
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        if (!callback) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_errorCallbacks.push_back(std::move(callback));
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_anomalyCallbacks.clear();
        m_miningCallbacks.clear();
        m_errorCallbacks.clear();
    }

    [[nodiscard]] GPUMiningStatistics GetStatistics() const {
        GPUMiningStatistics snapshot;
        snapshot.totalScans = m_stats.totalScans.load(std::memory_order_relaxed);
        snapshot.devicesMonitored = m_stats.devicesMonitored.load(std::memory_order_relaxed);
        snapshot.miningDetections = m_stats.miningDetections.load(std::memory_order_relaxed);
        snapshot.processesTerminated = m_stats.processesTerminated.load(std::memory_order_relaxed);
        snapshot.dagDetections = m_stats.dagDetections.load(std::memory_order_relaxed);
        snapshot.startTime = m_stats.GetStartTime();
        for (size_t index = 0; index < snapshot.byAlgorithm.size(); ++index) {
            snapshot.byAlgorithm[index] = m_stats.byAlgorithm[index].load(std::memory_order_relaxed);
        }
        return snapshot;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    [[nodiscard]] std::vector<GPUMiningDetectionResult> GetRecentDetections(size_t maxCount) const {
        std::shared_lock lock(m_mutex);
        const size_t count = std::min(maxCount, m_recentDetections.size());

        std::vector<GPUMiningDetectionResult> results;
        results.reserve(count);
        auto iterator = m_recentDetections.rbegin();
        for (size_t index = 0; index < count && iterator != m_recentDetections.rend(); ++index, ++iterator) {
            results.push_back(*iterator);
        }
        return results;
    }

    [[nodiscard]] bool SelfTest() {
        try {
            if (!IsInitialized()) {
                return Initialize({});
            }

            auto scan = ExecuteScan(false);
            Utils::Logger::Info(
                "GPUMiningDetector: self-test completed (devices={}, detections={})",
                scan.devices.size(),
                scan.detections.size());
            return true;
        } catch (const std::exception& ex) {
            Utils::Logger::Error("GPUMiningDetector: self-test failed - {}", ex.what());
            return false;
        }
    }

private:
    void InitializeVendorLibraries() {
        std::unique_lock lock(m_mutex);
        m_nvmlModule.Reset(LoadSystemLibrary(L"nvml.dll"));
        m_adlModule.Reset(LoadSystemLibrary(L"atiadlxx.dll"));
        if (!m_adlModule.IsValid()) {
            m_adlModule.Reset(LoadSystemLibrary(L"atiadlxy.dll"));
        }

        m_nvmlAvailable.store(m_nvmlModule.IsValid(), std::memory_order_release);
        m_adlAvailable.store(m_adlModule.IsValid(), std::memory_order_release);
    }

    void ShutdownVendorLibraries() {
        m_nvmlModule.Reset();
        m_adlModule.Reset();
        m_nvmlAvailable.store(false, std::memory_order_release);
        m_adlAvailable.store(false, std::memory_order_release);
    }

    void MonitorThreadProc() {
        while (!m_stopRequested.load(std::memory_order_acquire)) {
            try {
                const auto status = m_status.load(std::memory_order_acquire);
                if (status == ModuleStatus::Paused) {
                    std::unique_lock waitLock(m_waitMutex);
                    m_monitorCv.wait_for(waitLock, kMonitorWakeQuantum, [this]() {
                        return m_stopRequested.load(std::memory_order_acquire) ||
                               m_status.load(std::memory_order_acquire) != ModuleStatus::Paused;
                    });
                    continue;
                }

                m_status.store(ModuleStatus::Scanning, std::memory_order_release);
                auto scanResult = ExecuteScan(true);
                (void)scanResult;
                if (!m_stopRequested.load(std::memory_order_acquire)) {
                    m_status.store(ModuleStatus::Running, std::memory_order_release);
                }
            } catch (const std::exception& ex) {
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                InvokeErrorCallbacks("Monitor thread failure", -1);
                Utils::Logger::Error("GPUMiningDetector: monitor thread failure - {}", ex.what());
            }

            GPUMiningDetectorConfiguration configSnapshot;
            {
                std::shared_lock lock(m_mutex);
                configSnapshot = m_config;
            }

            std::unique_lock waitLock(m_waitMutex);
            m_monitorCv.wait_for(waitLock,
                                 std::chrono::milliseconds(configSnapshot.scanIntervalMs),
                                 [this]() { return m_stopRequested.load(std::memory_order_acquire); });
        }
    }

    [[nodiscard]] std::vector<AdapterInventoryEntry> EnumerateAdapters() const {
        std::vector<AdapterInventoryEntry> adapters;

        ComPtr<IDXGIFactory6> factory;
        HRESULT hr = ::CreateDXGIFactory1(IID_PPV_ARGS(&factory));
        if (FAILED(hr)) {
            Utils::Logger::Error("GPUMiningDetector: CreateDXGIFactory1 failed (hr=0x{:08X})", static_cast<uint32_t>(hr));
            return adapters;
        }

        for (UINT adapterIndex = 0; adapterIndex < GPUMiningConstants::MAX_GPU_DEVICES; ++adapterIndex) {
            ComPtr<IDXGIAdapter1> adapter;
            hr = factory->EnumAdapters1(adapterIndex, &adapter);
            if (hr == DXGI_ERROR_NOT_FOUND) {
                break;
            }
            if (FAILED(hr) || !adapter) {
                continue;
            }

            DXGI_ADAPTER_DESC1 description{};
            if (FAILED(adapter->GetDesc1(&description))) {
                continue;
            }
            if ((description.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0U) {
                continue;
            }

            AdapterInventoryEntry entry;
            entry.index = static_cast<uint32_t>(adapterIndex);
            entry.luid = description.AdapterLuid;
            entry.luidKey = MakeLuidKey(description.AdapterLuid);
            entry.stats.deviceIndex = static_cast<uint32_t>(adapterIndex);
            entry.stats.vendor = VendorFromId(description.VendorId);
            entry.stats.deviceName = Utils::StringUtils::WStringToString(description.Description);
            entry.stats.pciBusId = LuidToString(description.AdapterLuid);
            entry.stats.memoryTotalBytes = static_cast<uint64_t>(description.DedicatedVideoMemory);
            entry.stats.memoryFreeBytes = entry.stats.memoryTotalBytes;
            entry.stats.sampleTime = std::chrono::system_clock::now();

            ComPtr<IDXGIAdapter3> adapter3;
            if (SUCCEEDED(adapter.As(&adapter3)) && adapter3) {
                DXGI_QUERY_VIDEO_MEMORY_INFO localMemory{};
                if (SUCCEEDED(adapter3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &localMemory))) {
                    entry.stats.memoryTotalBytes = static_cast<uint64_t>(localMemory.Budget);
                    entry.stats.memoryUsedBytes = static_cast<uint64_t>(localMemory.CurrentUsage);
                    entry.stats.memoryFreeBytes = (entry.stats.memoryTotalBytes > entry.stats.memoryUsedBytes)
                        ? entry.stats.memoryTotalBytes - entry.stats.memoryUsedBytes
                        : 0;
                }
            }

            if (entry.stats.memoryTotalBytes != 0U) {
                entry.stats.memoryUsedPercent = ClampPercent(
                    (static_cast<double>(entry.stats.memoryUsedBytes) * 100.0) /
                    static_cast<double>(entry.stats.memoryTotalBytes));
            }

            adapters.push_back(std::move(entry));
        }

        return adapters;
    }

    [[nodiscard]] PdhSnapshot CollectPdhSnapshot() const {
        PdhSnapshot snapshot;

        std::vector<std::wstring> enginePaths = ExpandPdhPaths(L"\\GPU Engine(*)\\Utilization Percentage");
        std::vector<std::wstring> dedicatedPaths = ExpandPdhPaths(L"\\GPU Process Memory(*)\\Dedicated Usage");
        std::vector<std::wstring> sharedPaths = ExpandPdhPaths(L"\\GPU Process Memory(*)\\Shared Usage");

        if (enginePaths.empty() && dedicatedPaths.empty() && sharedPaths.empty()) {
            return snapshot;
        }

        ScopedPdhQuery query;
        if (!query.Open()) {
            return snapshot;
        }

        std::vector<CounterRegistration> counters;
        counters.reserve(enginePaths.size() + dedicatedPaths.size() + sharedPaths.size());

        auto registerPaths = [&](const std::vector<std::wstring>& paths, const wchar_t* counterName) {
            for (const auto& path : paths) {
                CounterRegistration registration;
                registration.path = path;
                registration.instance = ExtractInstanceFromPdhPath(path);
                registration.counterName = counterName;
                if (!registration.instance.empty() && AddEnglishCounter(query.Get(), path, registration.handle)) {
                    counters.push_back(std::move(registration));
                }
            }
        };

        registerPaths(enginePaths, L"Utilization Percentage");
        registerPaths(dedicatedPaths, L"Dedicated Usage");
        registerPaths(sharedPaths, L"Shared Usage");

        if (counters.empty()) {
            return snapshot;
        }

        if (::PdhCollectQueryData(query.Get()) != ERROR_SUCCESS) {
            return snapshot;
        }
        ::Sleep(kPdhWarmupMs);
        if (::PdhCollectQueryData(query.Get()) != ERROR_SUCCESS) {
            return snapshot;
        }

        for (const auto& registration : counters) {
            const auto value = ReadPdhDouble(registration.handle);
            if (!value.has_value()) {
                continue;
            }

            ParsedGpuInstance parsed = ParseGpuInstance(registration.instance);
            if (!parsed.valid) {
                continue;
            }

            auto& device = snapshot.byAdapter[parsed.luidKey];
            auto& process = device.processes[parsed.pid];
            process.pid = parsed.pid;
            process.luidKey = parsed.luidKey;

            if (registration.counterName == L"Utilization Percentage") {
                const auto category = ClassifyEngineType(parsed.engineType);
                const double metric = ClampPercent(*value);
                AccumulateEngineValue(device, category, metric);
                AccumulateEngineValue(process, category, metric);
                snapshot.engineTelemetryAvailable = true;
            } else if (registration.counterName == L"Dedicated Usage") {
                process.dedicatedBytes = static_cast<uint64_t>(std::max(0.0, *value));
                snapshot.processMemoryTelemetryAvailable = true;
            } else if (registration.counterName == L"Shared Usage") {
                process.sharedBytes = static_cast<uint64_t>(std::max(0.0, *value));
                snapshot.processMemoryTelemetryAvailable = true;
            }
        }

        for (auto& [_, device] : snapshot.byAdapter) {
            device.compute = ClampPercent(device.compute);
            device.graphics = ClampPercent(device.graphics);
            device.copy = ClampPercent(device.copy);
            device.encode = ClampPercent(device.encode);
            device.decode = ClampPercent(device.decode);
            for (auto& [__, process] : device.processes) {
                process.compute = ClampPercent(process.compute);
                process.graphics = ClampPercent(process.graphics);
                process.copy = ClampPercent(process.copy);
                process.encode = ClampPercent(process.encode);
                process.decode = ClampPercent(process.decode);
            }
        }

        return snapshot;
    }

    [[nodiscard]] GPUProcessInfo BuildProcessInfo(
        const ProcessTelemetry& telemetry,
        const GPUMiningDetectorConfiguration& config,
        bool& dagDetected) const
    {
        GPUProcessInfo process;
        process.processId = telemetry.pid;
        process.vramUsedBytes = telemetry.dedicatedBytes + telemetry.sharedBytes;
        process.telemetryAvailable = true;
        process.computeLoadPercent = telemetry.compute;
        process.graphicsLoadPercent = telemetry.graphics;
        process.copyLoadPercent = telemetry.copy;
        process.gpuUtilization = std::max({telemetry.compute, telemetry.graphics, telemetry.copy, telemetry.encode, telemetry.decode});
        process.isComputeIntensive = process.computeLoadPercent >= kCandidateProcessFloor;

        if (const auto processName = Utils::ProcessUtils::GetProcessName(telemetry.pid, nullptr)) {
            process.processName = *processName;
        }
        if (const auto processPath = Utils::ProcessUtils::GetProcessPath(telemetry.pid, nullptr)) {
            process.processPath = *processPath;
        }

        process.isWhitelisted = IsWhitelistedProcess(config, process.processName, process.processPath);

        if (const auto api = DetectComputeApi(telemetry.pid)) {
            process.computeAPI = *api;
        }
        process.hasComputeContext = process.computeLoadPercent >= 5.0 || process.computeAPI != ComputeAPI::Unknown;

        const bool suspiciousName = IsSuspiciousProcessName(process.processName);
        bool suspiciousCommandLine = false;
        if (!process.isWhitelisted && process.computeLoadPercent >= kCandidateProcessFloor) {
            if (const auto commandLine = Utils::ProcessUtils::GetProcessCommandLine(telemetry.pid, nullptr)) {
                suspiciousCommandLine = IsSuspiciousCommandLine(*commandLine);
            }
        }

        dagDetected = false;
        if (!process.isWhitelisted && config.detectDAGAllocation && process.vramUsedBytes != 0U) {
            dagDetected = FindDagFileSizeInternal(telemetry.pid).has_value();
        }

        process.suspectedAlgorithm = DetectAlgorithmFromPattern(
            process.computeLoadPercent,
            0.0,
            process.vramUsedBytes,
            dagDetected);

        int score = 0;
        if (process.computeLoadPercent >= kProcessMiningFloor) {
            score += 2;
        }
        if (process.computeLoadPercent >= config.gpuLoadThreshold) {
            score += 2;
        }
        if (suspiciousName) {
            score += 3;
        }
        if (suspiciousCommandLine) {
            score += 2;
        }
        if (dagDetected) {
            score += 4;
        }
        if (process.computeAPI == ComputeAPI::CUDA || process.computeAPI == ComputeAPI::OpenCL) {
            score += 1;
        }
        if (process.isWhitelisted || kTrustedSystemProcesses.contains(ToLowerCopy(process.processName))) {
            score = 0;
        }

        if (score >= 7) {
            process.confidence = DetectionConfidence::Confirmed;
        } else if (score >= 5) {
            process.confidence = DetectionConfidence::High;
        } else if (score >= 3) {
            process.confidence = DetectionConfidence::Medium;
        } else if (score >= 1) {
            process.confidence = DetectionConfidence::Low;
        }

        process.isSuspectedMiner = process.confidence >= DetectionConfidence::Medium;
        return process;
    }

    void AnalyzeDevice(
        const GPUMiningDetectorConfiguration& config,
        GPUDeviceStats& device,
        TimePoint now,
        const std::chrono::milliseconds& analysisDuration)
    {
        std::unique_lock lock(m_mutex);
        auto& history = m_deviceHistory[MakeHistoryKey(device)];
        history.push_back(DeviceHistorySample{
            now,
            device.computeLoadPercent,
            device.graphicsLoadPercent,
            device.memoryUsedPercent,
            device.dagDetected,
            CountCandidateProcesses(device)});

        while (!history.empty() && (now - history.front().sampleTime) > kIntermittentWindow) {
            history.pop_front();
        }
        while (history.size() > kMaxHistorySamples) {
            history.pop_front();
        }

        size_t totalSamples = 0;
        size_t sustainedSamples = 0;
        size_t dominantComputeSamples = 0;
        size_t candidateSamples = 0;
        TimePoint firstRelevantSample = now;

        for (const auto& sample : history) {
            if ((now - sample.sampleTime) > kIntermittentWindow) {
                continue;
            }
            if (totalSamples == 0) {
                firstRelevantSample = sample.sampleTime;
            }
            ++totalSamples;
            if (sample.computeLoad >= std::max(kComputeDetectionFloor, config.gpuLoadThreshold - 15.0)) {
                ++sustainedSamples;
            }
            if (sample.computeLoad >= sample.graphicsLoad + 20.0 && sample.graphicsLoad <= kGraphicsFalsePositiveFloor) {
                ++dominantComputeSamples;
            }
            if (sample.dagDetected || sample.suspiciousProcessCount > 0 || sample.memoryUsedPercent >= config.memoryThreshold) {
                ++candidateSamples;
            }
        }

        const bool sustainedWindowReached = totalSamples >= 2 && (now - firstRelevantSample) >= kMinimumSustainedWindow;
        const bool computeDominant = totalSamples > 0 && dominantComputeSamples * 2 >= totalSamples;
        const bool intermittentHighCompute = totalSamples > 0 && sustainedSamples * 2 >= totalSamples;
        const bool candidateCorrelated = candidateSamples > 0;
        const bool graphicsHeavy = device.graphicsLoadPercent >= std::max(50.0, device.computeLoadPercent);

        device.suspectedAlgorithm = DetectAlgorithmFromPattern(
            device.computeLoadPercent,
            device.memoryUsedPercent,
            device.memoryUsedBytes,
            device.dagDetected);
        device.detectionSummary.clear();
        device.confidence = DetectionConfidence::None;
        device.isMiningActivity = false;

        if (!device.telemetryAvailable || !device.processTelemetryAvailable) {
            device.detectionSummary = "Hardware telemetry unavailable; monitoring degraded but non-deceptive.";
            return;
        }
        if (graphicsHeavy) {
            device.detectionSummary = "High graphics/3D utilization dominates workload; suppressing mining verdict.";
            return;
        }
        if (!candidateCorrelated) {
            device.detectionSummary = "GPU compute activity lacks miner-specific process correlation.";
            return;
        }

        if (sustainedWindowReached && computeDominant && intermittentHighCompute) {
            device.confidence = device.dagDetected ? DetectionConfidence::Confirmed : DetectionConfidence::High;
            device.isMiningActivity = true;
            device.detectionSummary = device.dagDetected
                ? "Sustained compute-dominant GPU load with DAG evidence and non-whitelisted process correlation."
                : "Sustained compute-dominant GPU load with non-whitelisted process correlation.";
        } else if (device.computeLoadPercent >= std::max(kIntermittentDetectionFloor, config.gpuLoadThreshold - 25.0) &&
                   computeDominant) {
            device.confidence = DetectionConfidence::Medium;
            device.isMiningActivity = true;
            device.detectionSummary = "Intermittent compute-heavy GPU pattern suggests throttled mining behavior.";
        }

        if (device.isMiningActivity) {
            auto& lastDetection = m_lastDetectionsByDevice[MakeHistoryKey(device)];
            if (lastDetection != TimePoint{} && (now - lastDetection) < kAlertCooldown) {
                device.isMiningActivity = false;
                device.detectionSummary = "Mining signal suppressed by cooldown to prevent alert floods.";
            } else {
                lastDetection = now;
                (void)analysisDuration;
            }
        }
    }

    void AssessDeviceReadOnly(const GPUMiningDetectorConfiguration& config, GPUDeviceStats& device) const {
        device.suspectedAlgorithm = DetectAlgorithmFromPattern(
            device.computeLoadPercent,
            device.memoryUsedPercent,
            device.memoryUsedBytes,
            device.dagDetected);
        device.detectionSummary.clear();
        device.confidence = DetectionConfidence::None;
        device.isMiningActivity = false;

        if (!device.telemetryAvailable || !device.processTelemetryAvailable) {
            device.detectionSummary = "Hardware telemetry unavailable; monitoring degraded but non-deceptive.";
            return;
        }

        const bool candidateCorrelated = CountCandidateProcesses(device) > 0 ||
                                        device.dagDetected ||
                                        device.memoryUsedPercent >= config.memoryThreshold;
        const bool computeDominant = device.computeLoadPercent >= device.graphicsLoadPercent + 20.0 &&
                                     device.graphicsLoadPercent <= kGraphicsFalsePositiveFloor;
        const bool graphicsHeavy = device.graphicsLoadPercent >= std::max(50.0, device.computeLoadPercent);

        if (graphicsHeavy) {
            device.detectionSummary = "High graphics/3D utilization dominates workload; suppressing mining verdict.";
            return;
        }
        if (!candidateCorrelated) {
            device.detectionSummary = "GPU compute activity lacks miner-specific process correlation.";
            return;
        }

        if (device.computeLoadPercent >= std::max(kComputeDetectionFloor, config.gpuLoadThreshold - 15.0) && computeDominant) {
            device.confidence = device.dagDetected ? DetectionConfidence::Confirmed : DetectionConfidence::High;
            device.isMiningActivity = true;
            device.detectionSummary = device.dagDetected
                ? "Compute-dominant GPU load with DAG evidence and non-whitelisted process correlation."
                : "Compute-dominant GPU load with non-whitelisted process correlation.";
        } else if (device.computeLoadPercent >= std::max(kIntermittentDetectionFloor, config.gpuLoadThreshold - 25.0) && computeDominant) {
            device.confidence = DetectionConfidence::Medium;
            device.isMiningActivity = true;
            device.detectionSummary = "Current sample shows compute-heavy GPU activity consistent with miner throttling.";
        }
    }

    [[nodiscard]] std::vector<GPUDeviceStats> CollectReadOnlyDevices(const GPUMiningDetectorConfiguration& config) const {
        std::vector<GPUDeviceStats> devices;
        const auto adapters = EnumerateAdapters();
        const auto pdhSnapshot = CollectPdhSnapshot();

        for (const auto& adapter : adapters) {
            GPUDeviceStats device = adapter.stats;
            device.sampleTime = std::chrono::system_clock::now();
            auto telemetryIterator = pdhSnapshot.byAdapter.find(adapter.luidKey);

            if (telemetryIterator != pdhSnapshot.byAdapter.end()) {
                const DeviceTelemetry& telemetry = telemetryIterator->second;
                device.telemetryAvailable = pdhSnapshot.engineTelemetryAvailable;
                device.processTelemetryAvailable = pdhSnapshot.processMemoryTelemetryAvailable;
                device.vendorTelemetryAvailable =
                    (device.vendor == GPUVendor::NVIDIA && m_nvmlAvailable.load(std::memory_order_acquire)) ||
                    (device.vendor == GPUVendor::AMD && m_adlAvailable.load(std::memory_order_acquire));
                device.computeLoadPercent = telemetry.compute;
                device.graphicsLoadPercent = telemetry.graphics;
                device.copyLoadPercent = telemetry.copy;
                device.encodeLoadPercent = telemetry.encode;
                device.decodeLoadPercent = telemetry.decode;
                device.gpuLoadPercent = std::max({
                    device.computeLoadPercent,
                    device.graphicsLoadPercent,
                    device.copyLoadPercent,
                    device.encodeLoadPercent,
                    device.decodeLoadPercent});

                std::vector<GPUProcessInfo> processes;
                processes.reserve(telemetry.processes.size());
                bool dagDetected = false;
                for (const auto& [_, processTelemetry] : telemetry.processes) {
                    try {
                        bool processDagDetected = false;
                        GPUProcessInfo processInfo = BuildProcessInfo(processTelemetry, config, processDagDetected);
                        dagDetected = dagDetected || processDagDetected;
                        if (processInfo.gpuUtilization > 0.0 || processInfo.vramUsedBytes > 0U) {
                            processes.push_back(std::move(processInfo));
                        }
                    } catch (const std::exception& ex) {
                        Utils::Logger::Debug("GPUMiningDetector: skipped volatile PID {} during read-only scan - {}", processTelemetry.pid, ex.what());
                    }
                }

                std::sort(processes.begin(), processes.end(), [](const GPUProcessInfo& left, const GPUProcessInfo& right) {
                    return left.gpuUtilization > right.gpuUtilization;
                });

                device.processes = std::move(processes);
                device.dagDetected = dagDetected;
            }

            if (device.memoryTotalBytes != 0U && device.memoryUsedBytes != 0U) {
                device.memoryUsedPercent = ClampPercent(
                    (static_cast<double>(device.memoryUsedBytes) * 100.0) /
                    static_cast<double>(device.memoryTotalBytes));
            }

            AssessDeviceReadOnly(config, device);
            devices.push_back(std::move(device));
        }

        return devices;
    }

    [[nodiscard]] size_t CountCandidateProcesses(const GPUDeviceStats& device) const noexcept {
        return static_cast<size_t>(std::count_if(
            device.processes.begin(),
            device.processes.end(),
            [](const GPUProcessInfo& process) { return IsMiningProcessCandidate(process); }));
    }

    [[nodiscard]] uint64_t MakeHistoryKey(const GPUDeviceStats& device) const noexcept {
        return (static_cast<uint64_t>(device.deviceIndex) << 32U) |
               static_cast<uint64_t>(static_cast<uint8_t>(device.vendor));
    }

    [[nodiscard]] ScanExecutionResult ExecuteScan(bool emitCallbacks) {
        ScanExecutionResult result;
        const auto scanStart = Clock::now();

        GPUMiningDetectorConfiguration configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;
        }

        const auto adapters = EnumerateAdapters();
        const auto pdhSnapshot = CollectPdhSnapshot();

        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
        m_stats.devicesMonitored.store(static_cast<uint64_t>(adapters.size()), std::memory_order_relaxed);

        if (!pdhSnapshot.engineTelemetryAvailable) {
            std::unique_lock lock(m_mutex);
            if (!m_loggedTelemetryUnavailable) {
                Utils::Logger::Warn(
                    "GPUMiningDetector: GPU engine counters unavailable; module will not fabricate utilization telemetry");
                m_loggedTelemetryUnavailable = true;
            }
        }

        for (const auto& adapter : adapters) {
            GPUDeviceStats device = adapter.stats;
            device.sampleTime = std::chrono::system_clock::now();
            auto telemetryIterator = pdhSnapshot.byAdapter.find(adapter.luidKey);

            if (telemetryIterator != pdhSnapshot.byAdapter.end()) {
                const DeviceTelemetry& telemetry = telemetryIterator->second;
                device.telemetryAvailable = pdhSnapshot.engineTelemetryAvailable;
                device.processTelemetryAvailable = pdhSnapshot.processMemoryTelemetryAvailable;
                device.vendorTelemetryAvailable =
                    (device.vendor == GPUVendor::NVIDIA && m_nvmlAvailable.load(std::memory_order_acquire)) ||
                    (device.vendor == GPUVendor::AMD && m_adlAvailable.load(std::memory_order_acquire));
                device.computeLoadPercent = telemetry.compute;
                device.graphicsLoadPercent = telemetry.graphics;
                device.copyLoadPercent = telemetry.copy;
                device.encodeLoadPercent = telemetry.encode;
                device.decodeLoadPercent = telemetry.decode;
                device.gpuLoadPercent = std::max({
                    device.computeLoadPercent,
                    device.graphicsLoadPercent,
                    device.copyLoadPercent,
                    device.encodeLoadPercent,
                    device.decodeLoadPercent});

                std::vector<GPUProcessInfo> processes;
                processes.reserve(telemetry.processes.size());
                bool dagDetected = false;
                for (const auto& [_, processTelemetry] : telemetry.processes) {
                    try {
                        bool processDagDetected = false;
                        GPUProcessInfo processInfo = BuildProcessInfo(processTelemetry, configSnapshot, processDagDetected);
                        dagDetected = dagDetected || processDagDetected;
                        if (processInfo.gpuUtilization > 0.0 || processInfo.vramUsedBytes > 0U) {
                            processes.push_back(std::move(processInfo));
                        }
                    } catch (const std::exception& ex) {
                        Utils::Logger::Debug("GPUMiningDetector: skipped volatile PID {} during monitoring scan - {}", processTelemetry.pid, ex.what());
                    }
                }

                std::sort(processes.begin(), processes.end(), [](const GPUProcessInfo& left, const GPUProcessInfo& right) {
                    return left.gpuUtilization > right.gpuUtilization;
                });

                device.processes = std::move(processes);
                device.dagDetected = dagDetected;
                if (device.dagDetected) {
                    m_stats.dagDetections.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                device.telemetryAvailable = false;
                device.processTelemetryAvailable = false;
                device.vendorTelemetryAvailable = false;
            }

            if (device.memoryTotalBytes != 0U && device.memoryUsedBytes != 0U) {
                device.memoryUsedPercent = ClampPercent(
                    (static_cast<double>(device.memoryUsedBytes) * 100.0) /
                    static_cast<double>(device.memoryTotalBytes));
            }

            const auto analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - scanStart);
            AnalyzeDevice(configSnapshot, device, Clock::now(), analysisDuration);
            if (configSnapshot.monitorTemperatures && device.temperatureC >= configSnapshot.temperatureWarning) {
                result.anomalies.push_back(device);
            }
            if (device.isMiningActivity) {
                GPUMiningDetectionResult detection;
                detection.detectionId = GenerateDetectionId();
                detection.isMiningDetected = true;
                detection.deviceStats = device;
                detection.primaryAlgorithm = device.suspectedAlgorithm;
                detection.confidence = device.confidence;
                detection.detectionSummary = device.detectionSummary;
                detection.detectionTime = std::chrono::system_clock::now();
                detection.analysisDuration = analysisDuration;
                for (const auto& process : device.processes) {
                    if (IsMiningProcessCandidate(process)) {
                        detection.miningProcesses.push_back(process);
                    }
                }
                result.detections.push_back(std::move(detection));
            }

            result.devices.push_back(std::move(device));
        }

        {
            std::unique_lock lock(m_mutex);
            m_lastScanResults = result.devices;
            m_lastScanTime = Clock::now();
            m_deviceCount = m_lastScanResults.size();
            for (const auto& detection : result.detections) {
                m_recentDetections.push_back(detection);
                if (m_recentDetections.size() > kMaxRecentDetections) {
                    m_recentDetections.pop_front();
                }
            }
        }

        for (const auto& detection : result.detections) {
            m_stats.miningDetections.fetch_add(1, std::memory_order_relaxed);
            const auto algorithmIndex = static_cast<size_t>(static_cast<uint8_t>(detection.primaryAlgorithm));
            if (algorithmIndex < m_stats.byAlgorithm.size()) {
                m_stats.byAlgorithm[algorithmIndex].fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (emitCallbacks) {
            for (const auto& anomaly : result.anomalies) {
                InvokeAnomalyCallbacks(anomaly);
            }
            for (const auto& detection : result.detections) {
                InvokeMiningCallbacks(detection);
                Utils::Logger::Warn(
                    "GPUMiningDetector: detected suspicious GPU mining on device {} ({})",
                    detection.deviceStats.deviceIndex,
                    detection.deviceStats.deviceName);
            }
        }

        return result;
    }

    void InvokeAnomalyCallbacks(const GPUDeviceStats& device) {
        std::vector<GPUAnomalyCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks = m_anomalyCallbacks;
        }

        for (const auto& callback : callbacks) {
            try {
                if (callback) {
                    callback(device);
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("GPUMiningDetector: anomaly callback failure - {}", ex.what());
            }
        }
    }

    void InvokeMiningCallbacks(const GPUMiningDetectionResult& detection) {
        std::vector<GPUMiningDetectedCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks = m_miningCallbacks;
        }

        for (const auto& callback : callbacks) {
            try {
                if (callback) {
                    callback(detection);
                }
            } catch (const std::exception& ex) {
                Utils::Logger::Error("GPUMiningDetector: detection callback failure - {}", ex.what());
            }
        }
    }

    void InvokeErrorCallbacks(const std::string& message, int code) {
        std::vector<ErrorCallback> callbacks;
        {
            std::shared_lock lock(m_mutex);
            callbacks = m_errorCallbacks;
        }

        for (const auto& callback : callbacks) {
            try {
                if (callback) {
                    callback(message, code);
                }
            } catch (...) {
            }
        }
    }

    [[nodiscard]] std::string GenerateDetectionId() {
        const uint64_t sequence = m_detectionSequence.fetch_add(1, std::memory_order_relaxed) + 1;
        const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        std::ostringstream oss;
        oss << "GPU-" << std::hex << millis << '-' << sequence;
        return oss.str();
    }

    mutable std::shared_mutex m_mutex;
    mutable std::mutex m_monitorMutex;
    mutable std::mutex m_waitMutex;
    std::condition_variable m_monitorCv;
    std::condition_variable m_monitorStateCv;

    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_stopRequested{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<uint64_t> m_detectionSequence{0};

    GPUMiningDetectorConfiguration m_config{};
    RuntimeStatistics m_stats{};

    std::atomic<bool> m_nvmlAvailable{false};
    std::atomic<bool> m_adlAvailable{false};
    bool m_loggedTelemetryUnavailable = false;
    size_t m_deviceCount = 0;

    ScopedModule m_nvmlModule;
    ScopedModule m_adlModule;

    std::thread m_monitorThread;
    bool m_monitorTransitionInProgress = false;

    std::vector<GPUAnomalyCallback> m_anomalyCallbacks;
    std::vector<GPUMiningDetectedCallback> m_miningCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    std::deque<GPUMiningDetectionResult> m_recentDetections;
    std::vector<GPUDeviceStats> m_lastScanResults;
    TimePoint m_lastScanTime{};
    std::unordered_map<uint64_t, std::deque<DeviceHistorySample>> m_deviceHistory;
    std::unordered_map<uint64_t, TimePoint> m_lastDetectionsByDevice;
};

std::atomic<bool> GPUMiningDetector::s_instanceCreated{false};

GPUMiningDetector& GPUMiningDetector::Instance() noexcept {
    static GPUMiningDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

[[nodiscard]] bool GPUMiningDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

GPUMiningDetector::GPUMiningDetector()
    : m_impl(std::make_unique<GPUMiningDetectorImpl>()) {}

GPUMiningDetector::~GPUMiningDetector() = default;

bool GPUMiningDetector::Initialize(const GPUMiningDetectorConfiguration& config) {
    return m_impl->Initialize(config);
}

void GPUMiningDetector::Shutdown() {
    m_impl->Shutdown();
}

bool GPUMiningDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus GPUMiningDetector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool GPUMiningDetector::Start() {
    return m_impl->Start();
}

bool GPUMiningDetector::Stop() {
    return m_impl->Stop();
}

void GPUMiningDetector::Pause() {
    m_impl->Pause();
}

void GPUMiningDetector::Resume() {
    m_impl->Resume();
}

bool GPUMiningDetector::UpdateConfiguration(const GPUMiningDetectorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

GPUMiningDetectorConfiguration GPUMiningDetector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

std::vector<GPUDeviceStats> GPUMiningDetector::ScanDevices() {
    return m_impl->ScanDevices();
}

std::optional<GPUDeviceStats> GPUMiningDetector::GetDeviceStats(uint32_t deviceIndex) const {
    return m_impl->GetDeviceStats(deviceIndex);
}

std::vector<uint32_t> GPUMiningDetector::IdentifyMiningProcesses() {
    return m_impl->IdentifyMiningProcesses();
}

std::vector<GPUProcessInfo> GPUMiningDetector::GetGPUProcesses(uint32_t deviceIndex) const {
    return m_impl->GetGPUProcesses(deviceIndex);
}

bool GPUMiningDetector::DetectDAGGenerated(uint32_t processId) {
    return m_impl->DetectDAGGenerated(processId);
}

std::optional<uint64_t> GPUMiningDetector::GetDetectedDAGSize(uint32_t processId) const {
    return m_impl->GetDetectedDAGSize(processId);
}

size_t GPUMiningDetector::GetDeviceCount() const noexcept {
    return m_impl->GetDeviceCount();
}

bool GPUMiningDetector::IsNVMLAvailable() const noexcept {
    return m_impl->IsNVMLAvailable();
}

bool GPUMiningDetector::IsADLAvailable() const noexcept {
    return m_impl->IsADLAvailable();
}

bool GPUMiningDetector::TerminateMiningProcess(uint32_t processId) {
    return m_impl->TerminateMiningProcess(processId);
}

void GPUMiningDetector::RegisterAnomalyCallback(GPUAnomalyCallback callback) {
    m_impl->RegisterAnomalyCallback(std::move(callback));
}

void GPUMiningDetector::RegisterMiningDetectedCallback(GPUMiningDetectedCallback callback) {
    m_impl->RegisterMiningDetectedCallback(std::move(callback));
}

void GPUMiningDetector::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void GPUMiningDetector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

GPUMiningStatistics GPUMiningDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void GPUMiningDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<GPUMiningDetectionResult> GPUMiningDetector::GetRecentDetections(size_t maxCount) const {
    return m_impl->GetRecentDetections(maxCount);
}

bool GPUMiningDetector::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string GPUMiningDetector::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << GPUMiningConstants::VERSION_MAJOR << '.'
        << GPUMiningConstants::VERSION_MINOR << '.'
        << GPUMiningConstants::VERSION_PATCH;
    return oss.str();
}

[[nodiscard]] std::string_view GetGPUVendorName(GPUVendor vendor) noexcept {
    switch (vendor) {
    case GPUVendor::NVIDIA: return "NVIDIA";
    case GPUVendor::AMD: return "AMD";
    case GPUVendor::Intel: return "Intel";
    case GPUVendor::Other: return "Other";
    default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetComputeAPIName(ComputeAPI api) noexcept {
    switch (api) {
    case ComputeAPI::CUDA: return "CUDA";
    case ComputeAPI::OpenCL: return "OpenCL";
    case ComputeAPI::DirectCompute: return "DirectCompute";
    case ComputeAPI::VulkanCompute: return "VulkanCompute";
    case ComputeAPI::Metal: return "Metal";
    case ComputeAPI::None: return "None";
    default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetGPUMiningAlgorithmName(GPUMiningAlgorithm algo) noexcept {
    switch (algo) {
    case GPUMiningAlgorithm::Ethash: return "Ethash";
    case GPUMiningAlgorithm::Etchash: return "Etchash";
    case GPUMiningAlgorithm::Kawpow: return "Kawpow";
    case GPUMiningAlgorithm::Autolykos: return "Autolykos";
    case GPUMiningAlgorithm::Equihash: return "Equihash";
    case GPUMiningAlgorithm::ProgPow: return "ProgPow";
    case GPUMiningAlgorithm::CuckooCycle: return "CuckooCycle";
    case GPUMiningAlgorithm::ZHash: return "ZHash";
    case GPUMiningAlgorithm::BeamHash: return "BeamHash";
    case GPUMiningAlgorithm::Generic: return "Generic";
    default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetDetectionConfidenceName(DetectionConfidence conf) noexcept {
    switch (conf) {
    case DetectionConfidence::Low: return "Low";
    case DetectionConfidence::Medium: return "Medium";
    case DetectionConfidence::High: return "High";
    case DetectionConfidence::Confirmed: return "Confirmed";
    default: return "None";
    }
}

} // namespace CryptoMiners
} // namespace ShadowStrike
