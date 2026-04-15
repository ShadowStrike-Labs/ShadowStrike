/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
/**
 * ============================================================================
 * ShadowStrike CryptoMiner Protection - BROWSER MINER DETECTOR IMPLEMENTATION
 * ============================================================================
 */

#include "pch.h"
#include "BrowserMinerDetector.hpp"

#include "../../../../PhantomCore/ThreatIntel/ThreatIntelManager.hpp"
#include "../../../../PhantomCore/Utils/FileUtils.hpp"
#include "../../../../PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <array>
#include <bcrypt.h>
#include <cctype>
#include <cmath>
#include <deque>
#include <format>
#include <iomanip>
#include <limits>
#include <condition_variable>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <random>
#include <regex>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

namespace ShadowStrike {
namespace CryptoMiners {

namespace {

constexpr wchar_t kLogCategory[] = L"BrowserMinerDetector";
constexpr uint8_t kWasmVersion1[4] = {0x01, 0x00, 0x00, 0x00};
constexpr uint8_t kWasmSectionMemory = 0x05;
constexpr uint8_t kWasmSectionCode = 0x0A;
constexpr uint8_t kWasmOpcodeI32Mul = 0x6C;
constexpr uint8_t kWasmOpcodeI64Mul = 0x7E;
constexpr uint8_t kWasmOpcodeI32Xor = 0x73;
constexpr uint8_t kWasmOpcodeI64Xor = 0x85;
constexpr uint8_t kWasmOpcodeI32Rotl = 0x77;
constexpr uint8_t kWasmOpcodeI32Rotr = 0x78;
constexpr uint8_t kWasmOpcodeLoop = 0x03;
constexpr uint32_t kLargeWasmMemoryPages = 128;
thread_local uint32_t g_browserMinerCallbackDepth = 0;

struct TabKey {
    uint32_t browserPid = 0;
    uint64_t tabId = 0;

    [[nodiscard]] bool operator==(const TabKey& other) const noexcept {
        return browserPid == other.browserPid && tabId == other.tabId;
    }
};

struct TabKeyHasher {
    [[nodiscard]] size_t operator()(const TabKey& key) const noexcept {
        const uint64_t pidComponent = static_cast<uint64_t>(key.browserPid) << 32U;
        return std::hash<uint64_t>{}(pidComponent ^ key.tabId);
    }
};

template <typename Enum, size_t N>
void IncrementCounter(std::array<std::atomic<uint64_t>, N>& counters, Enum value) noexcept {
    const size_t index = static_cast<size_t>(value);
    if (index < counters.size()) {
        counters[index].fetch_add(1, std::memory_order_relaxed);
    }
}

[[nodiscard]] std::string TrimAscii(std::string_view input) {
    size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
        ++start;
    }

    size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }

    return std::string(input.substr(start, end - start));
}

[[nodiscard]] std::string LowerAsciiCopy(std::string_view input) {
    std::string output(input);
    std::transform(output.begin(), output.end(), output.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return output;
}

[[nodiscard]] bool ContainsMethod(
    const std::vector<BrowserDetectionMethod>& methods,
    BrowserDetectionMethod method) noexcept
{
    return std::find(methods.begin(), methods.end(), method) != methods.end();
}

void AppendEvidence(std::string& evidence, std::string_view item) {
    if (item.empty()) {
        return;
    }

    if (!evidence.empty()) {
        evidence.append("; ");
    }

    evidence.append(item);
}

[[nodiscard]] bool DomainMatches(std::string_view candidate, std::string_view rule) noexcept {
    if (candidate.empty() || rule.empty()) {
        return false;
    }

    if (candidate == rule) {
        return true;
    }

    return candidate.size() > rule.size() &&
           candidate.ends_with(rule) &&
           candidate[candidate.size() - rule.size() - 1] == '.';
}

[[nodiscard]] std::string NormalizeDomainValue(std::string_view input) {
    std::string value = TrimAscii(input);
    if (value.empty()) {
        return {};
    }

    std::wstring wideValue = Utils::StringUtils::ToWide(value);
    if (wideValue.empty()) {
        return {};
    }

    if (Utils::NetworkUtils::IsValidUrl(wideValue)) {
        const std::wstring extracted = Utils::NetworkUtils::ExtractDomain(wideValue);
        if (!extracted.empty()) {
            wideValue = extracted;
        }
    }

    std::string host = TrimAscii(Utils::StringUtils::ToNarrow(wideValue));
    if (host.empty()) {
        return {};
    }

    const size_t schemePos = host.find("://");
    if (schemePos != std::string::npos) {
        host.erase(0, schemePos + 3);
    }

    const size_t terminatorPos = host.find_first_of("/?#");
    if (terminatorPos != std::string::npos) {
        host.erase(terminatorPos);
    }

    const size_t atPos = host.rfind('@');
    if (atPos != std::string::npos) {
        host.erase(0, atPos + 1);
    }

    if (!host.empty() && host.front() == '[') {
        const size_t bracketEnd = host.find(']');
        if (bracketEnd != std::string::npos) {
            host = host.substr(1, bracketEnd - 1);
        }
    } else {
        const size_t firstColon = host.find(':');
        const size_t lastColon = host.rfind(':');
        if (firstColon != std::string::npos && firstColon == lastColon) {
            host = host.substr(0, firstColon);
        }
    }

    while (!host.empty() && host.back() == '.') {
        host.pop_back();
    }

    return LowerAsciiCopy(host);
}

[[nodiscard]] std::optional<std::string> ResolveDomain(const BrowserScriptInfo& scriptInfo) {
    if (!scriptInfo.domain.empty()) {
        std::string normalized = NormalizeDomainValue(scriptInfo.domain);
        if (!normalized.empty()) {
            return normalized;
        }
    }

    if (!scriptInfo.sourceUrl.empty()) {
        std::string normalized = NormalizeDomainValue(scriptInfo.sourceUrl);
        if (!normalized.empty()) {
            return normalized;
        }
    }

    return std::nullopt;
}

[[nodiscard]] BrowserScriptInfo SanitizeScriptInfo(
    const BrowserScriptInfo& scriptInfo,
    size_t contentSize,
    ScriptType fallbackType)
{
    BrowserScriptInfo sanitized = scriptInfo;

    if (sanitized.scriptSize == 0) {
        sanitized.scriptSize = contentSize;
    }

    if (sanitized.scriptType == ScriptType::Unknown) {
        sanitized.scriptType = fallbackType;
    }

    if (auto normalizedDomain = ResolveDomain(scriptInfo)) {
        sanitized.domain = *normalizedDomain;
    } else {
        sanitized.domain.clear();
    }

    return sanitized;
}

template <typename CallbackList, typename Invoker>
void DispatchCallbackList(const CallbackList& callbacks, Invoker&& invoker, const wchar_t* failureLabel) {
    for (const auto& callback : callbacks) {
        if (!callback) {
            continue;
        }

        try {
            invoker(callback);
        } catch (const std::exception& exception) {
            SS_LOG_ERROR(kLogCategory, L"%ls callback threw exception: %ls",
                failureLabel,
                Utils::StringUtils::ToWide(exception.what()).c_str());
        } catch (...) {
            SS_LOG_ERROR(kLogCategory, L"%ls callback threw unknown exception", failureLabel);
        }
    }
}

[[nodiscard]] std::string GenerateRandomDetectionId() {
    std::array<unsigned char, 16> randomBytes{};
    const NTSTATUS status = ::BCryptGenRandom(
        nullptr,
        randomBytes.data(),
        static_cast<ULONG>(randomBytes.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    if (BCRYPT_SUCCESS(status)) {
        std::ostringstream stream;
        stream << "BMINE-" << std::uppercase << std::hex << std::setfill('0');
        for (const unsigned char value : randomBytes) {
            stream << std::setw(2) << static_cast<unsigned int>(value);
        }
        return stream.str();
    }

    std::random_device device;
    std::mt19937_64 generator(device());
    const uint64_t first = generator();
    const uint64_t second = generator();
    return std::format("BMINE-{0:016X}{1:016X}", first, second);
}

[[nodiscard]] bool TryDecodeLeb128(
    const uint8_t*& cursor,
    const uint8_t* end,
    uint64_t& value) noexcept
{
    value = 0;
    unsigned shift = 0;
    while (cursor < end && shift < 64U) {
        const uint8_t byte = *cursor++;
        value |= static_cast<uint64_t>(byte & 0x7FU) << shift;
        if ((byte & 0x80U) == 0U) {
            return true;
        }
        shift += 7U;
    }
    cursor = end;
    value = 0;
    return false;
}

[[nodiscard]] bool SkipLeb128(const uint8_t*& cursor, const uint8_t* end) noexcept {
    uint64_t ignored = 0;
    return TryDecodeLeb128(cursor, end, ignored);
}

[[nodiscard]] bool SkipFixed(const uint8_t*& cursor, const uint8_t* end, size_t size) noexcept {
    if (static_cast<size_t>(end - cursor) < size) {
        cursor = end;
        return false;
    }
    cursor += size;
    return true;
}

[[nodiscard]] bool SkipBlockType(const uint8_t*& cursor, const uint8_t* end) noexcept {
    if (cursor >= end) {
        return false;
    }

    switch (*cursor) {
        case 0x40:
        case 0x7F:
        case 0x7E:
        case 0x7D:
        case 0x7C:
        case 0x7B:
        case 0x70:
        case 0x6F:
            ++cursor;
            return true;
        default:
            return SkipLeb128(cursor, end);
    }
}

[[nodiscard]] bool SkipMemoryImmediate(const uint8_t*& cursor, const uint8_t* end) noexcept {
    return SkipLeb128(cursor, end) && SkipLeb128(cursor, end);
}

struct ControlFrame {
    uint8_t opcode = 0;
    bool seenElse = false;
};

[[nodiscard]] bool SkipWasmInstruction(
    uint8_t opcode,
    const uint8_t*& cursor,
    const uint8_t* end,
    std::vector<ControlFrame>& frames,
    bool& terminated) noexcept
{
    switch (opcode) {
        case 0x00:
        case 0x01:
        case 0x0F:
        case 0x1A:
        case 0x1B:
        case 0xD1:
            return true;
        case 0x02:
        case 0x03:
        case 0x04:
            frames.push_back(ControlFrame{opcode, false});
            return SkipBlockType(cursor, end);
        case 0x05:
            if (frames.empty() || frames.back().opcode != 0x04U || frames.back().seenElse) {
                return false;
            }
            frames.back().seenElse = true;
            return true;
        case 0x0B:
            if (frames.empty()) {
                terminated = true;
            } else {
                frames.pop_back();
            }
            return true;
        case 0x0C:
        case 0x0D:
        case 0x10:
        case 0x12:
        case 0x13:
        case 0x14:
        case 0x20:
        case 0x21:
        case 0x22:
        case 0x23:
        case 0x24:
        case 0x25:
        case 0x26:
        case 0xD2:
            return SkipLeb128(cursor, end);
        case 0x0E: {
            uint64_t entryCount = 0;
            if (!TryDecodeLeb128(cursor, end, entryCount) ||
                entryCount == std::numeric_limits<uint64_t>::max()) {
                return false;
            }

            if (entryCount >= std::numeric_limits<uint64_t>::max() - 1U) {
                return false;
            }

            const uint64_t labelCount = entryCount + 1U;
            if (labelCount > static_cast<uint64_t>(end - cursor)) {
                return false;
            }

            for (uint64_t index = 0; index < labelCount; ++index) {
                if (!SkipLeb128(cursor, end)) {
                    return false;
                }
            }
            return true;
        }
        case 0x11:
            return SkipLeb128(cursor, end) && SkipLeb128(cursor, end);
        case 0x28:
        case 0x29:
        case 0x2A:
        case 0x2B:
        case 0x2C:
        case 0x2D:
        case 0x2E:
        case 0x2F:
        case 0x30:
        case 0x31:
        case 0x32:
        case 0x33:
        case 0x34:
        case 0x35:
        case 0x36:
        case 0x37:
        case 0x38:
        case 0x39:
        case 0x3A:
        case 0x3B:
        case 0x3C:
        case 0x3D:
        case 0x3E:
            return SkipMemoryImmediate(cursor, end);
        case 0x3F:
        case 0x40:
            return SkipLeb128(cursor, end);
        case 0x41:
        case 0x42:
            return SkipLeb128(cursor, end);
        case 0x43:
            return SkipFixed(cursor, end, sizeof(uint32_t));
        case 0x44:
            return SkipFixed(cursor, end, sizeof(uint64_t));
        case 0xD0:
            return SkipBlockType(cursor, end);
        case 0xFC: {
            uint64_t subOpcode = 0;
            if (!TryDecodeLeb128(cursor, end, subOpcode)) {
                return false;
            }
            switch (subOpcode) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    return true;
                case 8:
                case 12:
                    return SkipLeb128(cursor, end) && SkipLeb128(cursor, end);
                case 9:
                case 11:
                case 13:
                case 15:
                case 16:
                case 17:
                    return SkipLeb128(cursor, end);
                case 10:
                case 14:
                    return SkipLeb128(cursor, end) && SkipLeb128(cursor, end);
                default:
                    return false;
            }
        }
        case 0xFD: {
            uint64_t subOpcode = 0;
            if (!TryDecodeLeb128(cursor, end, subOpcode)) {
                return false;
            }

            if (subOpcode <= 0x0BU) {
                return SkipMemoryImmediate(cursor, end);
            }
            if (subOpcode == 0x0CU || subOpcode == 0x0DU) {
                return SkipFixed(cursor, end, 16U);
            }
            if (subOpcode >= 0x15U && subOpcode <= 0x22U) {
                return SkipFixed(cursor, end, 1U);
            }
            if (subOpcode >= 0x54U && subOpcode <= 0x5BU) {
                return SkipMemoryImmediate(cursor, end) && SkipFixed(cursor, end, 1U);
            }

            return true;
        }
        default:
            return opcode >= 0x45U && opcode <= 0xC4U;
    }
}

[[nodiscard]] std::optional<std::unordered_set<std::string>> LoadBlacklistFileDomains(
    const std::filesystem::path& path,
    Utils::FileUtils::Error& error)
{
    std::string content;
    if (!Utils::FileUtils::ReadAllTextUtf8(path.native(), content, &error)) {
        return std::nullopt;
    }

    std::unordered_set<std::string> loadedDomains;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        line = TrimAscii(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }

        const std::string normalized = NormalizeDomainValue(line);
        if (!normalized.empty()) {
            loadedDomains.insert(normalized);
        }
    }

    return loadedDomains;
}

[[nodiscard]] size_t ComputeUniqueDomainCount(
    const std::unordered_set<std::string>& builtinDomains,
    const std::unordered_set<std::string>& customDomains,
    const std::unordered_set<std::string>& manualDomains)
{
    std::unordered_set<std::string> combined;
    combined.reserve(builtinDomains.size() + customDomains.size() + manualDomains.size());
    combined.insert(builtinDomains.begin(), builtinDomains.end());
    combined.insert(customDomains.begin(), customDomains.end());
    combined.insert(manualDomains.begin(), manualDomains.end());
    return combined.size();
}

}  // namespace

namespace MiningSignatures {

constexpr auto JS_MINER_STRINGS = std::to_array<std::string_view>({
    "coinhive", "coin-hive", "authedmine", "cryptoloot", "crypto-loot",
    "coinimp", "coin-imp", "jsecoin", "webminepool", "deepminer",
    "ppoi", "minemytraffic", "cryptonight", "randomx", "argon2",
    ".setthrottle(", ".setnumthreads(", ".gethashespersecond(",
    ".getacceptedhashes(", ".gettotalhashes(", "hashvault", "moneropool",
    "miningpool", "argon2id", "cn_heavy", "randomx_init", "hashrate",
    "acceptedhashes", "totalthreads", "wasmminer", "webminer",
    "threads:", "throttle:", "miner.start", "miner.stop"
});

constexpr auto POOL_ENDPOINTS = std::to_array<std::string_view>({
    "wss://ws.coinhive.com", "wss://ws.authedmine.com", "wss://cryptoloot.pro",
    "wss://webminepool.com", "wss://jsecoin.com", "wss://coin-have.com",
    "wss://kisshentai.net", "wss://kiwifarms.net", "wss://monerominer.rocks",
    "wss://ppoi.org", "wss://crypto-loot.com", "wss://coinblind.com",
    "wss://minero.cc", "wss://www.freecontent.stream", "wss://hemnes.win",
    "wss://kickass.cd", "wss://cloudcoins.co", "wss://2giga.link",
    "wss://ad-miner.com", "wss://afminer.com", "wss://beatingheart.pro",
    "wss://bmst.pw", "wss://cnt.statistic.date", "wss://cookiescript.info",
    "wss://coinerra.com", "wss://rocks.io", "wss://party-nngvitbizn.now.sh",
    "wss://vidoza.net", "wss://ajplugins.com", "wss://static-cnt.bid"
});

constexpr std::array<uint8_t, 4> WASM_MAGIC = {0x00, 0x61, 0x73, 0x6D};

constexpr auto KNOWN_MINING_DOMAINS = std::to_array<std::string_view>({
    "coinhive.com", "coin-hive.com", "authedmine.com", "cryptoloot.pro",
    "crypto-loot.com", "webminepool.com", "webminepool.tk", "jsecoin.com",
    "coinblind.com", "coin-have.com", "kisshentai.net", "kiwifarms.net",
    "monerominer.rocks", "ppoi.org", "minero.cc", "freecontent.stream",
    "hemnes.win", "kickass.cd", "cloudcoins.co", "2giga.link", "ad-miner.com",
    "afminer.com", "beatingheart.pro", "bmst.pw", "cnt.statistic.date",
    "cookiescript.info", "coinerra.com", "rocks.io", "vidoza.net", "ajplugins.com",
    "static-cnt.bid", "gus.host", "cdn.staticfile.tk", "crypto.csgostash.com",
    "noblock.pro", "miner.pr0gramm.com", "cpu2cash.link", "papoto.com",
    "party-nngvitbizn.now.sh", "hallaert.online", "hashing.win", "pazanchik.com",
    "bitcoincore.io", "moneone.ga", "jscdndel.com", "digxmr.com",
    "coin-service.com", "dmdamedia.hu", "joyreactor.cc", "okestream.com",
    "streamfe.com", "mine.torrent.pw"
});

}  // namespace MiningSignatures

class BrowserMinerDetectorImpl {
public:
    class OperationGuard {
    public:
        explicit OperationGuard(BrowserMinerDetectorImpl& owner)
            : m_owner(owner) {
            m_owner.m_activeOperations.fetch_add(1, std::memory_order_acq_rel);
        }

        ~OperationGuard() {
            Release();
        }

        void Release() {
            if (!m_active) {
                return;
            }

            std::lock_guard operationLock(m_owner.m_operationMutex);
            if (!m_active) {
                return;
            }

            m_active = false;
            m_owner.m_activeOperations.fetch_sub(1, std::memory_order_acq_rel);
            m_owner.m_operationCv.notify_all();
        }

    private:
        BrowserMinerDetectorImpl& m_owner;
        bool m_active{true};
    };

    class CallbackDispatchGuard {
    public:
        explicit CallbackDispatchGuard(BrowserMinerDetectorImpl& owner)
            : m_owner(owner) {
            m_owner.m_callbacksInFlight.fetch_add(1, std::memory_order_acq_rel);
            ++g_browserMinerCallbackDepth;
        }

        ~CallbackDispatchGuard() {
            Release();
        }

        void Release() {
            if (!m_active) {
                return;
            }

            std::lock_guard operationLock(m_owner.m_operationMutex);
            if (!m_active) {
                return;
            }

            m_active = false;
            --g_browserMinerCallbackDepth;
            m_owner.m_callbacksInFlight.fetch_sub(1, std::memory_order_acq_rel);
            m_owner.m_operationCv.notify_all();
        }

    private:
        BrowserMinerDetectorImpl& m_owner;
        bool m_active{true};
    };

    struct WASMInstructionStats {
        uint32_t xorCount = 0;
        uint32_t mulCount = 0;
        uint32_t rotateCount = 0;
        uint32_t loopCount = 0;
        uint32_t functionCount = 0;
        uint32_t totalInstructions = 0;
        uint32_t sequenceScore = 0;
        bool structurallyValid = true;
    };

    mutable std::shared_mutex m_mutex;
    BrowserMinerDetectorConfiguration m_config;
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::mutex m_lifecycleMutex;
    std::atomic<uint32_t> m_activeOperations{0};
    std::atomic<uint32_t> m_callbacksInFlight{0};
    std::mutex m_operationMutex;
    std::condition_variable m_operationCv;
    BrowserMinerStatistics m_statistics;

    std::deque<BrowserMinerDetectionResult> m_recentDetections;
    mutable std::shared_mutex m_detectionsMutex;
    static constexpr size_t MAX_RECENT_DETECTIONS = 1000;

    std::unordered_set<std::string> m_builtinBlockedDomains;
    std::unordered_set<std::string> m_customBlockedDomains;
    std::unordered_set<std::string> m_manualBlockedDomains;
    mutable std::shared_mutex m_domainsMutex;

    std::unordered_map<std::string, std::string> m_configWhitelistedDomains;
    std::unordered_map<std::string, std::string> m_manualWhitelistedDomains;
    mutable std::shared_mutex m_whitelistMutex;

    std::unordered_map<TabKey, TabMiningInfo, TabKeyHasher> m_monitoredTabs;
    mutable std::shared_mutex m_tabsMutex;

    std::unordered_map<TabKey, std::vector<WebWorkerInfo>, TabKeyHasher> m_workers;
    mutable std::shared_mutex m_workersMutex;

    std::vector<MinerFoundCallback> m_minerFoundCallbacks;
    std::vector<TabMiningCallback> m_tabMiningCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    mutable std::mutex m_callbacksMutex;

    BrowserMinerDetectorImpl() = default;
    ~BrowserMinerDetectorImpl() = default;

    [[nodiscard]] bool Initialize(const BrowserMinerDetectorConfiguration& config);
    void Shutdown();

    [[nodiscard]] BrowserMinerDetectionResult AnalyzeScriptInternal(
        const std::string& scriptSource,
        const BrowserScriptInfo& scriptInfo);
    [[nodiscard]] BrowserMinerDetectionResult AnalyzeWASMInternal(
        std::span<const uint8_t> wasmBinary,
        const BrowserScriptInfo& scriptInfo);

    [[nodiscard]] bool DetectJSMinerSignatures(
        const std::string& script,
        std::vector<std::string>& matchedSigs) const;
    [[nodiscard]] BrowserMinerFamily IdentifyMinerFamily(const std::string& script) const;
    [[nodiscard]] bool DetectObfuscation(const std::string& script) const;
    [[nodiscard]] std::optional<std::string> ExtractWalletAddress(const std::string& script) const;
    [[nodiscard]] std::optional<uint32_t> ExtractThrottle(const std::string& script) const;
    [[nodiscard]] std::vector<std::string> ExtractPoolAddresses(const std::string& script) const;

    [[nodiscard]] WASMAnalysisResult AnalyzeWASMBinary(std::span<const uint8_t> wasmBinary);
    [[nodiscard]] bool IsValidWASM(std::span<const uint8_t> data) const;
    [[nodiscard]] bool HasCryptoInstructions(std::span<const uint8_t> wasmBinary);
    [[nodiscard]] double CalculateLoopDensity(std::span<const uint8_t> wasmBinary);
    [[nodiscard]] static uint64_t DecodeLEB128(const uint8_t*& ptr, const uint8_t* end) noexcept;
    [[nodiscard]] WASMInstructionStats AnalyzeCodeSection(std::span<const uint8_t> sectionData) const;

    [[nodiscard]] bool IsDomainBlockedInternal(const std::string& domain) const;
    [[nodiscard]] bool IsDomainWhitelistedInternal(const std::string& domain) const;
    void BlockDomainInternal(const std::string& domain);
    void LoadBuiltinBlacklist();
    [[nodiscard]] bool LoadCustomBlacklistInternal(const std::filesystem::path& path);

    [[nodiscard]] bool IsTabMiningInternal(uint32_t browserPid, uint64_t tabId);
    [[nodiscard]] std::optional<TabMiningInfo> GetTabMiningInfoInternal(
        uint32_t browserPid,
        uint64_t tabId) const;
    [[nodiscard]] std::optional<TabMiningInfo> UpdateTabState(
        const BrowserScriptInfo& scriptInfo,
        const BrowserMinerDetectionResult& result,
        bool hasWasmSignal);

    [[nodiscard]] std::vector<MinerFoundCallback> SnapshotMinerFoundCallbacks() const;
    [[nodiscard]] std::vector<TabMiningCallback> SnapshotTabMiningCallbacks() const;
    [[nodiscard]] std::vector<ErrorCallback> SnapshotErrorCallbacks() const;

    [[nodiscard]] std::string GenerateDetectionId() const;
    [[nodiscard]] BrowserMinerDetectorConfiguration SnapshotConfiguration() const;
    [[nodiscard]] double CalculateConfidenceScore(
        const std::vector<BrowserDetectionMethod>& methods,
        bool hasWASM,
        bool hasPoolConnection) const;
    [[nodiscard]] ThreatSeverity DetermineSeverity(
        double confidence,
        BrowserMinerFamily family) const;

private:
    [[nodiscard]] bool IsOperational() const noexcept {
        return m_initialized.load(std::memory_order_acquire) &&
               m_status.load(std::memory_order_acquire) == ModuleStatus::Running;
    }

    void StoreDetection(const BrowserMinerDetectionResult& result);
};

bool BrowserMinerDetectorImpl::Initialize(
    const BrowserMinerDetectorConfiguration& config)
{
    try {
        std::lock_guard lifecycleLock(m_lifecycleMutex);
        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(kLogCategory, L"Browser miner detector already initialized");
            return true;
        }

        BrowserMinerDetectorConfiguration effectiveConfig = config;
        if (effectiveConfig.enableWorkerMonitoring || effectiveConfig.terminateMiningWorkers) {
            SS_LOG_WARN(kLogCategory, L"Worker telemetry and worker termination are not wired in BrowserMinerDetector; disabling those options");
            effectiveConfig.enableWorkerMonitoring = false;
            effectiveConfig.terminateMiningWorkers = false;
        }

        if (!effectiveConfig.IsValid()) {
            SS_LOG_ERROR(kLogCategory, L"Initialization rejected due to invalid configuration");
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        {
            std::unique_lock configLock(m_mutex);
            m_config = effectiveConfig;
        }

        {
            std::unique_lock whitelistLock(m_whitelistMutex);
            m_configWhitelistedDomains.clear();
            m_manualWhitelistedDomains.clear();
            for (const std::string& configuredDomain : effectiveConfig.whitelistedDomains) {
                const std::string normalized = NormalizeDomainValue(configuredDomain);
                if (!normalized.empty()) {
                    m_configWhitelistedDomains[normalized] = "Configuration";
                }
            }
        }

        {
            std::unique_lock domainsLock(m_domainsMutex);
            m_builtinBlockedDomains.clear();
            m_customBlockedDomains.clear();
        }

        if (effectiveConfig.blockKnownDomains) {
            LoadBuiltinBlacklist();
        }

        if (!effectiveConfig.domainBlacklistPath.empty() && !LoadCustomBlacklistInternal(effectiveConfig.domainBlacklistPath)) {
            SS_LOG_ERROR(kLogCategory, L"Failed to load configured blacklist from '%ls'",
                effectiveConfig.domainBlacklistPath.c_str());
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        size_t blockedDomainCount = 0;
        {
            std::shared_lock domainsLock(m_domainsMutex);
            blockedDomainCount = m_builtinBlockedDomains.size();
            for (const auto& domain : m_customBlockedDomains) {
                if (!m_builtinBlockedDomains.contains(domain)) {
                    ++blockedDomainCount;
                }
            }
            for (const auto& domain : m_manualBlockedDomains) {
                if (!m_builtinBlockedDomains.contains(domain) && !m_customBlockedDomains.contains(domain)) {
                    ++blockedDomainCount;
                }
            }
        }

        size_t whitelistedDomainCount = 0;
        {
            std::shared_lock whitelistLock(m_whitelistMutex);
            whitelistedDomainCount = m_configWhitelistedDomains.size();
            for (const auto& [domain, reason] : m_manualWhitelistedDomains) {
                (void)reason;
                if (!m_configWhitelistedDomains.contains(domain)) {
                    ++whitelistedDomainCount;
                }
            }
        }

        SS_LOG_INFO(kLogCategory, L"Browser miner detector initialized with %zu blocked domains and %zu whitelisted domains",
            blockedDomainCount, whitelistedDomainCount);
        return true;
    } catch (const std::exception& exception) {
        SS_LOG_ERROR(kLogCategory, L"Initialization failed: %ls",
            Utils::StringUtils::ToWide(exception.what()).c_str());
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void BrowserMinerDetectorImpl::Shutdown() {
    std::lock_guard lifecycleLock(m_lifecycleMutex);
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_initialized.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    const bool shutdownRequestedFromCallback = (g_browserMinerCallbackDepth != 0U);
    if (shutdownRequestedFromCallback) {
        SS_LOG_WARN(kLogCategory, L"Shutdown requested from a BrowserMinerDetector callback; callback completion wait will be deferred for the current callback thread");
    }

    {
        std::unique_lock operationLock(m_operationMutex);
        m_operationCv.wait(operationLock, [&]() {
            const bool noActiveOperations = m_activeOperations.load(std::memory_order_acquire) == 0U;
            const bool callbacksDrained = shutdownRequestedFromCallback ||
                m_callbacksInFlight.load(std::memory_order_acquire) == 0U;
            return noActiveOperations && callbacksDrained;
        });
    }

    {
        std::unique_lock lock(m_detectionsMutex);
        m_recentDetections.clear();
    }

    {
        std::unique_lock lock(m_domainsMutex);
        m_builtinBlockedDomains.clear();
        m_customBlockedDomains.clear();
        m_manualBlockedDomains.clear();
    }

    {
        std::unique_lock lock(m_whitelistMutex);
        m_configWhitelistedDomains.clear();
        m_manualWhitelistedDomains.clear();
    }

    {
        std::unique_lock lock(m_tabsMutex);
        m_monitoredTabs.clear();
    }

    {
        std::unique_lock lock(m_workersMutex);
        m_workers.clear();
    }

    {
        std::lock_guard lock(m_callbacksMutex);
        m_minerFoundCallbacks.clear();
        m_tabMiningCallbacks.clear();
        m_errorCallbacks.clear();
    }

    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
}

BrowserMinerDetectorConfiguration BrowserMinerDetectorImpl::SnapshotConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

void BrowserMinerDetectorImpl::StoreDetection(
    const BrowserMinerDetectionResult& result)
{
    std::unique_lock lock(m_detectionsMutex);
    m_recentDetections.push_back(result);
    while (m_recentDetections.size() > MAX_RECENT_DETECTIONS) {
        m_recentDetections.pop_front();
    }
}

BrowserMinerDetectionResult BrowserMinerDetectorImpl::AnalyzeScriptInternal(
    const std::string& scriptSource,
    const BrowserScriptInfo& scriptInfo)
{
    const auto startTime = Clock::now();
    BrowserMinerDetectionResult result;

    try {
        result.detectionId = GenerateDetectionId();
        result.detectionTime = std::chrono::system_clock::now();
        result.scriptInfo = SanitizeScriptInfo(scriptInfo, scriptSource.size(), ScriptType::JavaScript);
        if (!IsOperational()) {
            AppendEvidence(result.evidence, "Detector is not initialized");
            return result;
        }

        OperationGuard activeOperationGuard(*this);

        if (!IsOperational()) {
            AppendEvidence(result.evidence, "Detector stopped before analysis could begin");
            return result;
        }

        const BrowserMinerDetectorConfiguration config = SnapshotConfiguration();
        if (!config.enableJSScanning) {
            AppendEvidence(result.evidence, "JavaScript scanning disabled by configuration");
            return result;
        }

        m_statistics.scriptsScanned.fetch_add(1, std::memory_order_relaxed);

        if (scriptSource.size() > config.maxScriptScanSize) {
            AppendEvidence(result.evidence, "Script exceeds configured scan limit");
            SS_LOG_WARN(kLogCategory, L"Skipped oversized browser script (%zu bytes)", scriptSource.size());
            return result;
        }

        if (!result.scriptInfo.domain.empty() && IsDomainWhitelistedInternal(result.scriptInfo.domain)) {
            result.isWhitelisted = true;
            AppendEvidence(result.evidence, "Domain is explicitly whitelisted");
            return result;
        }

        std::vector<BrowserDetectionMethod> methods;
        auto addMethod = [&](BrowserDetectionMethod method, std::string_view evidence) {
            if (!ContainsMethod(methods, method)) {
                methods.push_back(method);
            }
            AppendEvidence(result.evidence, evidence);
        };

        std::vector<std::string> matchedSignatures;
        if (config.enableJSScanning && DetectJSMinerSignatures(scriptSource, matchedSignatures)) {
            result.matchedSignatures = std::move(matchedSignatures);
            addMethod(BrowserDetectionMethod::SignatureMatch, "Known browser-miner signature matched");
            IncrementCounter(m_statistics.byMethod, BrowserDetectionMethod::SignatureMatch);
        }

        result.minerFamily = IdentifyMinerFamily(scriptSource);
        if (result.minerFamily != BrowserMinerFamily::Unknown) {
            result.familyName = std::string(GetBrowserMinerFamilyName(result.minerFamily));
            addMethod(BrowserDetectionMethod::StringPattern, "Miner family indicators identified in script");
            IncrementCounter(m_statistics.byFamily, result.minerFamily);
        }

        if (!result.scriptInfo.domain.empty() && config.enableDomainBlocking && IsDomainBlockedInternal(result.scriptInfo.domain)) {
            addMethod(BrowserDetectionMethod::DomainBlacklist, "Domain matches browser-miner blacklist");
            m_statistics.domainsBlocked.fetch_add(1, std::memory_order_relaxed);
        }

        const auto& threatIntel = ThreatIntel::ThreatIntelManager::Instance();
        if (!result.scriptInfo.domain.empty() && threatIntel.IsInitialized()) {
            const auto lookup = threatIntel.LookupDomain(result.scriptInfo.domain);
            if (lookup.IsMalicious() && lookup.category == ThreatIntel::ThreatCategory::Cryptominer) {
                addMethod(BrowserDetectionMethod::ThreatIntel,
                    std::format("Threat intelligence score {} on domain", lookup.score));
                if (config.enableDomainBlocking) {
                    BlockDomainInternal(result.scriptInfo.domain);
                }
            } else if (lookup.IsMalicious()) {
                AppendEvidence(result.evidence,
                    std::format("Non-miner malicious threat-intel category {} observed on domain",
                        static_cast<uint32_t>(lookup.category)));
            }
        }

        result.poolAddresses = ExtractPoolAddresses(scriptSource);
        if (!result.poolAddresses.empty()) {
            addMethod(BrowserDetectionMethod::NetworkPool, "Mining pool endpoint found");
        }

        if (config.enableHeuristics && DetectObfuscation(scriptSource)) {
            addMethod(BrowserDetectionMethod::HeuristicAnalysis, "Obfuscation consistent with miner loaders");
        }

        if (auto walletAddress = ExtractWalletAddress(scriptSource)) {
            result.walletAddress = *walletAddress;
            AppendEvidence(result.evidence, "Cryptocurrency wallet embedded in script");
        }

        if (auto throttle = ExtractThrottle(scriptSource)) {
            result.throttlePercent = *throttle;
            AppendEvidence(result.evidence, std::format("Throttle configured to {}%", *throttle));
        }

        if (result.minerFamily == BrowserMinerFamily::Unknown && !methods.empty()) {
            result.minerFamily = BrowserMinerFamily::GenericJS;
            result.familyName = std::string(GetBrowserMinerFamilyName(result.minerFamily));
        }

        result.additionalMethods = methods;
        if (!methods.empty()) {
            result.detectionMethod = methods.front();
        }

        const bool authoritativeDetection =
            ContainsMethod(methods, BrowserDetectionMethod::SignatureMatch) ||
            ContainsMethod(methods, BrowserDetectionMethod::DomainBlacklist) ||
            ContainsMethod(methods, BrowserDetectionMethod::ThreatIntel) ||
            (ContainsMethod(methods, BrowserDetectionMethod::NetworkPool) &&
             ContainsMethod(methods, BrowserDetectionMethod::StringPattern));

        result.confidenceScore = CalculateConfidenceScore(
            methods,
            scriptSource.find("WebAssembly") != std::string::npos,
            !result.poolAddresses.empty());
        result.severity = DetermineSeverity(result.confidenceScore, result.minerFamily);
        result.isMinerDetected = authoritativeDetection ||
            result.confidenceScore >= (config.confidenceThreshold * 100.0);

        const auto tabCallbackInfo = UpdateTabState(result.scriptInfo, result, false);
        if (result.isMinerDetected) {
            if (!IsOperational()) {
                AppendEvidence(result.evidence, "Detector stopped before result publication");
                return result;
            }

            m_statistics.minersDetected.fetch_add(1, std::memory_order_relaxed);
            StoreDetection(result);
            const auto minerCallbacks = SnapshotMinerFoundCallbacks();
            const auto tabCallbacks = tabCallbackInfo.has_value()
                ? SnapshotTabMiningCallbacks()
                : std::vector<TabMiningCallback>{};
            const std::wstring familyName = Utils::StringUtils::ToWide(result.familyName);
            const std::wstring domain = Utils::StringUtils::ToWide(result.scriptInfo.domain);
            CallbackDispatchGuard callbackDispatchGuard(*this);
            activeOperationGuard.Release();
            if (tabCallbackInfo.has_value()) {
                DispatchCallbackList(tabCallbacks,
                    [&](const TabMiningCallback& callback) { callback(*tabCallbackInfo); },
                    L"Tab");
            }
            DispatchCallbackList(minerCallbacks,
                [&](const MinerFoundCallback& callback) { callback(result, result.scriptInfo); },
                L"Miner");
            SS_LOG_WARN(kLogCategory, L"Detected browser miner family '%ls' with %.1f%% confidence on domain '%ls'",
                familyName.c_str(), result.confidenceScore, domain.c_str());
        }
    } catch (const std::exception& exception) {
        const std::wstring message = Utils::StringUtils::ToWide(exception.what());
        SS_LOG_ERROR(kLogCategory, L"Script analysis failed: %ls", message.c_str());
        CallbackDispatchGuard callbackDispatchGuard(*this);
        DispatchCallbackList(SnapshotErrorCallbacks(),
            [&](const ErrorCallback& callback) { callback(exception.what(), -1); },
            L"Error");
    }

    result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startTime);
    return result;
}

BrowserMinerDetectionResult BrowserMinerDetectorImpl::AnalyzeWASMInternal(
    std::span<const uint8_t> wasmBinary,
    const BrowserScriptInfo& scriptInfo)
{
    const auto startTime = Clock::now();
    BrowserMinerDetectionResult result;

    try {
        result.detectionId = GenerateDetectionId();
        result.detectionTime = std::chrono::system_clock::now();
        result.scriptInfo = SanitizeScriptInfo(scriptInfo, wasmBinary.size(), ScriptType::WebAssembly);
        if (!IsOperational()) {
            AppendEvidence(result.evidence, "Detector is not initialized");
            return result;
        }

        OperationGuard activeOperationGuard(*this);

        if (!IsOperational()) {
            AppendEvidence(result.evidence, "Detector stopped before analysis could begin");
            return result;
        }

        const BrowserMinerDetectorConfiguration config = SnapshotConfiguration();
        m_statistics.wasmModulesScanned.fetch_add(1, std::memory_order_relaxed);

        if (wasmBinary.size() > config.maxWASMSize) {
            AppendEvidence(result.evidence, "WASM module exceeds configured scan limit");
            return result;
        }

        if (!result.scriptInfo.domain.empty() && IsDomainWhitelistedInternal(result.scriptInfo.domain)) {
            result.isWhitelisted = true;
            AppendEvidence(result.evidence, "Domain is explicitly whitelisted");
            return result;
        }

        if (!config.enableWASMScanning) {
            AppendEvidence(result.evidence, "WASM scanning disabled by configuration");
            return result;
        }

        result.wasmAnalysis = AnalyzeWASMBinary(wasmBinary);
        if (!result.wasmAnalysis->isValidWASM) {
            AppendEvidence(result.evidence, "Module is not valid WebAssembly");
            return result;
        }

        std::vector<BrowserDetectionMethod> methods;
        auto addMethod = [&](BrowserDetectionMethod method, std::string_view evidence) {
            if (!ContainsMethod(methods, method)) {
                methods.push_back(method);
            }
            AppendEvidence(result.evidence, evidence);
        };

        if (result.wasmAnalysis->isMiningModule) {
            addMethod(BrowserDetectionMethod::WASMAnalysis, "WASM instruction profile matches browser miner");
            result.algorithm = result.wasmAnalysis->algorithm;
            result.minerFamily = BrowserMinerFamily::GenericWASM;
            result.familyName = std::string(GetBrowserMinerFamilyName(result.minerFamily));
            IncrementCounter(m_statistics.byMethod, BrowserDetectionMethod::WASMAnalysis);
            IncrementCounter(m_statistics.byFamily, result.minerFamily);
        }

        if (!result.scriptInfo.domain.empty() && config.enableDomainBlocking && IsDomainBlockedInternal(result.scriptInfo.domain)) {
            addMethod(BrowserDetectionMethod::DomainBlacklist, "Domain matches browser-miner blacklist");
        }

        const auto& threatIntel = ThreatIntel::ThreatIntelManager::Instance();
        if (!result.scriptInfo.domain.empty() && threatIntel.IsInitialized()) {
            const auto lookup = threatIntel.LookupDomain(result.scriptInfo.domain);
            if (lookup.IsMalicious() && lookup.category == ThreatIntel::ThreatCategory::Cryptominer) {
                addMethod(BrowserDetectionMethod::ThreatIntel,
                    std::format("Threat intelligence score {} on domain", lookup.score));
                if (config.enableDomainBlocking) {
                    BlockDomainInternal(result.scriptInfo.domain);
                }
            } else if (lookup.IsMalicious()) {
                AppendEvidence(result.evidence,
                    std::format("Non-miner malicious threat-intel category {} observed on domain",
                        static_cast<uint32_t>(lookup.category)));
            }
        }

        result.additionalMethods = methods;
        if (!methods.empty()) {
            result.detectionMethod = methods.front();
        }

        const double weightedScore = CalculateConfidenceScore(methods, true, false);
        result.confidenceScore = std::max(result.wasmAnalysis->confidenceScore, weightedScore);
        result.severity = DetermineSeverity(result.confidenceScore, result.minerFamily);
        result.isMinerDetected = result.wasmAnalysis->isMiningModule ||
            ContainsMethod(methods, BrowserDetectionMethod::DomainBlacklist) ||
            ContainsMethod(methods, BrowserDetectionMethod::ThreatIntel) ||
            result.confidenceScore >= (config.confidenceThreshold * 100.0);

        const auto tabCallbackInfo = UpdateTabState(result.scriptInfo, result, true);
        if (result.isMinerDetected) {
            if (!IsOperational()) {
                AppendEvidence(result.evidence, "Detector stopped before result publication");
                return result;
            }

            m_statistics.minersDetected.fetch_add(1, std::memory_order_relaxed);
            StoreDetection(result);
            const auto minerCallbacks = SnapshotMinerFoundCallbacks();
            const auto tabCallbacks = tabCallbackInfo.has_value()
                ? SnapshotTabMiningCallbacks()
                : std::vector<TabMiningCallback>{};
            const std::wstring domain = Utils::StringUtils::ToWide(result.scriptInfo.domain);
            CallbackDispatchGuard callbackDispatchGuard(*this);
            activeOperationGuard.Release();
            if (tabCallbackInfo.has_value()) {
                DispatchCallbackList(tabCallbacks,
                    [&](const TabMiningCallback& callback) { callback(*tabCallbackInfo); },
                    L"Tab");
            }
            DispatchCallbackList(minerCallbacks,
                [&](const MinerFoundCallback& callback) { callback(result, result.scriptInfo); },
                L"Miner");
            SS_LOG_WARN(kLogCategory, L"Detected browser miner via WASM analysis with %.1f%% confidence on domain '%ls'",
                result.confidenceScore, domain.c_str());
        }
    } catch (const std::exception& exception) {
        const std::wstring message = Utils::StringUtils::ToWide(exception.what());
        SS_LOG_ERROR(kLogCategory, L"WASM analysis failed: %ls", message.c_str());
        CallbackDispatchGuard callbackDispatchGuard(*this);
        DispatchCallbackList(SnapshotErrorCallbacks(),
            [&](const ErrorCallback& callback) { callback(exception.what(), -1); },
            L"Error");
    }

    result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startTime);
    return result;
}

bool BrowserMinerDetectorImpl::DetectJSMinerSignatures(
    const std::string& script,
    std::vector<std::string>& matchedSigs) const
{
    const std::string lowerScript = LowerAsciiCopy(script);
    bool detected = false;

    for (std::string_view signature : MiningSignatures::JS_MINER_STRINGS) {
        if (lowerScript.find(signature) != std::string::npos) {
            matchedSigs.emplace_back(signature);
            detected = true;
        }
    }

    return detected;
}

BrowserMinerFamily BrowserMinerDetectorImpl::IdentifyMinerFamily(
    const std::string& script) const
{
    const std::string lowerScript = LowerAsciiCopy(script);

    if (lowerScript.find("authedmine") != std::string::npos) {
        return BrowserMinerFamily::Authedmine;
    }
    if (lowerScript.find("coinhive") != std::string::npos ||
        lowerScript.find("coin-hive") != std::string::npos) {
        return BrowserMinerFamily::Coinhive;
    }
    if (lowerScript.find("cryptoloot") != std::string::npos ||
        lowerScript.find("crypto-loot") != std::string::npos) {
        return BrowserMinerFamily::CryptoLoot;
    }
    if (lowerScript.find("coinimp") != std::string::npos ||
        lowerScript.find("coin-imp") != std::string::npos) {
        return BrowserMinerFamily::CoinIMP;
    }
    if (lowerScript.find("jsecoin") != std::string::npos) {
        return BrowserMinerFamily::JSECoin;
    }
    if (lowerScript.find("webminepool") != std::string::npos) {
        return BrowserMinerFamily::WebMinePool;
    }
    if (lowerScript.find("deepminer") != std::string::npos) {
        return BrowserMinerFamily::DeepMiner;
    }
    if (lowerScript.find("minemytraffic") != std::string::npos) {
        return BrowserMinerFamily::MineMyTraffic;
    }
    if (lowerScript.find("ppoi") != std::string::npos) {
        return BrowserMinerFamily::PPoi;
    }
    if (lowerScript.find("cryptonight") != std::string::npos ||
        lowerScript.find("randomx") != std::string::npos ||
        lowerScript.find("argon2") != std::string::npos) {
        return BrowserMinerFamily::GenericJS;
    }

    return BrowserMinerFamily::Unknown;
}

bool BrowserMinerDetectorImpl::DetectObfuscation(
    const std::string& script) const
{
    if (script.empty()) {
        return false;
    }

    const std::string lowerScript = LowerAsciiCopy(script);
    uint32_t score = 0;

    if (lowerScript.find("eval(") != std::string::npos) score += 10;
    if (lowerScript.find("unescape(") != std::string::npos) score += 10;
    if (lowerScript.find("fromcharcode(") != std::string::npos) score += 10;
    if (lowerScript.find("atob(") != std::string::npos) score += 8;
    if (lowerScript.find("function(") == std::string::npos && lowerScript.find("=>") == std::string::npos) score += 4;

    size_t encodedEscapes = 0;
    for (size_t index = 0; index + 3 < script.size(); ++index) {
        if (script[index] == '\\' && (script[index + 1] == 'x' || script[index + 1] == 'u')) {
            ++encodedEscapes;
        }
    }

    if (encodedEscapes > 32) {
        score += 12;
    }

    const size_t nonAlphaNumeric = std::count_if(script.begin(), script.end(), [](unsigned char value) {
        return std::isalnum(value) == 0 && std::isspace(value) == 0;
    });
    const double ratio = static_cast<double>(nonAlphaNumeric) / static_cast<double>(script.size());
    if (ratio > 0.35) {
        score += 10;
    }

    return score >= 20;
}

std::optional<std::string> BrowserMinerDetectorImpl::ExtractWalletAddress(
    const std::string& script) const
{
    static const std::regex moneroPattern(R"(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})",
        std::regex_constants::optimize);
    std::smatch match;
    if (std::regex_search(script, match, moneroPattern) && !match.empty()) {
        return match[0].str();
    }
    return std::nullopt;
}

std::optional<uint32_t> BrowserMinerDetectorImpl::ExtractThrottle(
    const std::string& script) const
{
    static const std::regex throttlePattern(
        R"((?:setThrottle|throttle)\s*[:=(]\s*(\d{1,3}))",
        std::regex_constants::icase | std::regex_constants::optimize);
    std::smatch match;
    if (std::regex_search(script, match, throttlePattern) && match.size() >= 2) {
        const uint32_t throttle = static_cast<uint32_t>(std::stoul(match[1].str()));
        if (throttle <= 100U) {
            return throttle;
        }
    }
    return std::nullopt;
}

std::vector<std::string> BrowserMinerDetectorImpl::ExtractPoolAddresses(
    const std::string& script) const
{
    std::vector<std::string> pools;
    std::unordered_set<std::string> seen;
    const std::string lowerScript = LowerAsciiCopy(script);

    for (std::string_view endpoint : MiningSignatures::POOL_ENDPOINTS) {
        if (lowerScript.find(endpoint) != std::string::npos && seen.emplace(endpoint).second) {
            pools.emplace_back(endpoint);
        }
    }

    static const std::regex poolPattern(
        R"(((?:wss?|stratum\+tcp)://[a-zA-Z0-9\-\._:\[\]]+))",
        std::regex_constants::icase | std::regex_constants::optimize);

    for (std::sregex_iterator iter(script.begin(), script.end(), poolPattern), end; iter != end; ++iter) {
        std::string pool = LowerAsciiCopy((*iter)[1].str());
        if (!pool.empty() && seen.emplace(pool).second) {
            pools.push_back(std::move(pool));
        }
    }

    return pools;
}

uint64_t BrowserMinerDetectorImpl::DecodeLEB128(
    const uint8_t*& ptr,
    const uint8_t* end) noexcept
{
    uint64_t value = 0;
    unsigned shift = 0;

    while (ptr < end && shift < 64U) {
        const uint8_t byte = *ptr++;
        value |= static_cast<uint64_t>(byte & 0x7FU) << shift;
        if ((byte & 0x80U) == 0U) {
            return value;
        }
        shift += 7U;
    }

    ptr = end;
    return std::numeric_limits<uint64_t>::max();
}

BrowserMinerDetectorImpl::WASMInstructionStats
BrowserMinerDetectorImpl::AnalyzeCodeSection(std::span<const uint8_t> sectionData) const
{
    WASMInstructionStats stats;
    const uint8_t* cursor = sectionData.data();
    const uint8_t* end = sectionData.data() + sectionData.size();

    const uint64_t functionCount = DecodeLEB128(cursor, end);
    if (functionCount == std::numeric_limits<uint64_t>::max()) {
        stats.structurallyValid = false;
        return stats;
    }

    stats.functionCount = static_cast<uint32_t>(
        std::min<uint64_t>(functionCount, std::numeric_limits<uint32_t>::max()));

    uint64_t parsedFunctionCount = 0;
    for (uint64_t functionIndex = 0; functionIndex < functionCount && cursor < end; ++functionIndex) {
        ++parsedFunctionCount;
        const uint64_t bodySize = DecodeLEB128(cursor, end);
        if (bodySize == std::numeric_limits<uint64_t>::max() ||
            bodySize > static_cast<uint64_t>(end - cursor)) {
            stats.structurallyValid = false;
            return stats;
        }

        const uint8_t* bodyCursor = cursor;
        const uint8_t* bodyEnd = cursor + static_cast<size_t>(bodySize);
        cursor = bodyEnd;

        const uint64_t localDeclCount = DecodeLEB128(bodyCursor, bodyEnd);
        if (localDeclCount == std::numeric_limits<uint64_t>::max()) {
            stats.structurallyValid = false;
            return stats;
        }

        for (uint64_t localIndex = 0; localIndex < localDeclCount; ++localIndex) {
            const uint64_t localCount = DecodeLEB128(bodyCursor, bodyEnd);
            if (localCount == std::numeric_limits<uint64_t>::max() || bodyCursor >= bodyEnd) {
                stats.structurallyValid = false;
                return stats;
            }
            ++bodyCursor;
        }

        std::vector<ControlFrame> frames;
        bool terminated = false;
        while (bodyCursor < bodyEnd) {
            const uint8_t opcode = *bodyCursor++;
            ++stats.totalInstructions;
            switch (opcode) {
                case kWasmOpcodeI32Xor:
                case kWasmOpcodeI64Xor:
                    ++stats.xorCount;
                    break;
                case kWasmOpcodeI32Mul:
                case kWasmOpcodeI64Mul:
                    ++stats.mulCount;
                    break;
                case kWasmOpcodeI32Rotl:
                case kWasmOpcodeI32Rotr:
                    ++stats.rotateCount;
                    break;
                case kWasmOpcodeLoop:
                    ++stats.loopCount;
                    break;
                default:
                    break;
            }

            if (!SkipWasmInstruction(opcode, bodyCursor, bodyEnd, frames, terminated)) {
                stats.structurallyValid = false;
                return stats;
            }
        }

        if (!terminated || !frames.empty() || bodyCursor != bodyEnd) {
            stats.structurallyValid = false;
            return stats;
        }
    }

    if (parsedFunctionCount != functionCount || cursor != end) {
        stats.structurallyValid = false;
        return stats;
    }

    stats.sequenceScore = std::min<uint32_t>(
        100U,
        std::min<uint32_t>(stats.xorCount, 32U) +
        std::min<uint32_t>(stats.mulCount, 32U) +
        std::min<uint32_t>(stats.rotateCount * 2U, 24U) +
        std::min<uint32_t>(stats.loopCount, 12U));
    return stats;
}

bool BrowserMinerDetectorImpl::IsValidWASM(
    std::span<const uint8_t> data) const
{
    if (data.size() < 8) {
        return false;
    }

    if (!std::equal(MiningSignatures::WASM_MAGIC.begin(),
                    MiningSignatures::WASM_MAGIC.end(),
                    data.begin()) ||
        !std::equal(std::begin(kWasmVersion1), std::end(kWasmVersion1), data.begin() + 4)) {
        return false;
    }

    const uint8_t* cursor = data.data() + 8;
    const uint8_t* end = data.data() + data.size();
    uint8_t lastSectionId = 0;

    while (cursor < end) {
        const uint8_t sectionId = *cursor++;
        const uint64_t sectionSize = DecodeLEB128(cursor, end);
        if (sectionSize == std::numeric_limits<uint64_t>::max() ||
            sectionSize > static_cast<uint64_t>(end - cursor)) {
            return false;
        }

        if (sectionId != 0U) {
            if (sectionId < lastSectionId) {
                return false;
            }
            lastSectionId = sectionId;
        }

        cursor += static_cast<size_t>(sectionSize);
    }

    return cursor == end;
}

bool BrowserMinerDetectorImpl::HasCryptoInstructions(
    std::span<const uint8_t> wasmBinary)
{
    if (!IsValidWASM(wasmBinary)) {
        return false;
    }

    const uint8_t* cursor = wasmBinary.data() + 8;
    const uint8_t* end = wasmBinary.data() + wasmBinary.size();
    WASMInstructionStats aggregate{};

    while (cursor < end) {
        const uint8_t sectionId = *cursor++;
        const uint64_t sectionSize = DecodeLEB128(cursor, end);
        if (sectionSize == std::numeric_limits<uint64_t>::max() ||
            sectionSize > static_cast<uint64_t>(end - cursor)) {
            return false;
        }

        if (sectionId == kWasmSectionCode) {
            const WASMInstructionStats stats = AnalyzeCodeSection(
                std::span<const uint8_t>(cursor, static_cast<size_t>(sectionSize)));
            if (!stats.structurallyValid) {
                return false;
            }
            aggregate.xorCount += stats.xorCount;
            aggregate.mulCount += stats.mulCount;
            aggregate.rotateCount += stats.rotateCount;
            aggregate.totalInstructions += stats.totalInstructions;
            aggregate.sequenceScore = std::min<uint32_t>(100U, aggregate.sequenceScore + stats.sequenceScore);
        }

        cursor += static_cast<size_t>(sectionSize);
    }

    return aggregate.sequenceScore >= 50U ||
           (aggregate.xorCount >= 32U && aggregate.mulCount >= 32U && aggregate.rotateCount >= 8U);
}

double BrowserMinerDetectorImpl::CalculateLoopDensity(
    std::span<const uint8_t> wasmBinary)
{
    if (!IsValidWASM(wasmBinary)) {
        return 0.0;
    }

    const uint8_t* cursor = wasmBinary.data() + 8;
    const uint8_t* end = wasmBinary.data() + wasmBinary.size();
    uint64_t totalInstructions = 0;
    uint64_t loopCount = 0;

    while (cursor < end) {
        const uint8_t sectionId = *cursor++;
        const uint64_t sectionSize = DecodeLEB128(cursor, end);
        if (sectionSize == std::numeric_limits<uint64_t>::max() ||
            sectionSize > static_cast<uint64_t>(end - cursor)) {
            return 0.0;
        }

        if (sectionId == kWasmSectionCode) {
            const WASMInstructionStats stats = AnalyzeCodeSection(
                std::span<const uint8_t>(cursor, static_cast<size_t>(sectionSize)));
            if (!stats.structurallyValid) {
                return 0.0;
            }
            totalInstructions += stats.totalInstructions;
            loopCount += stats.loopCount;
        }

        cursor += static_cast<size_t>(sectionSize);
    }

    if (totalInstructions == 0) {
        return 0.0;
    }

    return static_cast<double>(loopCount) / static_cast<double>(totalInstructions);
}

WASMAnalysisResult BrowserMinerDetectorImpl::AnalyzeWASMBinary(
    std::span<const uint8_t> wasmBinary)
{
    WASMAnalysisResult result;
    result.moduleSize = wasmBinary.size();
    result.isValidWASM = IsValidWASM(wasmBinary);
    if (!result.isValidWASM) {
        return result;
    }

    result.hasCryptoInstructions = HasCryptoInstructions(wasmBinary);
    result.loopDensityScore = CalculateLoopDensity(wasmBinary);

    const uint8_t* cursor = wasmBinary.data() + 8;
    const uint8_t* end = wasmBinary.data() + wasmBinary.size();
    WASMInstructionStats aggregateStats{};

    while (cursor < end) {
        const uint8_t sectionId = *cursor++;
        const uint64_t sectionSize = DecodeLEB128(cursor, end);
        if (sectionSize == std::numeric_limits<uint64_t>::max() ||
            sectionSize > static_cast<uint64_t>(end - cursor)) {
            return WASMAnalysisResult{};
        }

        const uint8_t* sectionData = cursor;
        const uint8_t* sectionEnd = cursor + static_cast<size_t>(sectionSize);

        if (sectionId == kWasmSectionMemory) {
            const uint8_t* memoryCursor = sectionData;
            const uint64_t memoryCount = DecodeLEB128(memoryCursor, sectionEnd);
            if (memoryCount > 0U && memoryCount != std::numeric_limits<uint64_t>::max()) {
                const uint64_t flags = DecodeLEB128(memoryCursor, sectionEnd);
                const uint64_t initialPages = DecodeLEB128(memoryCursor, sectionEnd);
                if (flags != std::numeric_limits<uint64_t>::max() &&
                    initialPages != std::numeric_limits<uint64_t>::max()) {
                    result.memoryPages = static_cast<uint32_t>(
                        std::min<uint64_t>(initialPages, std::numeric_limits<uint32_t>::max()));
                    result.hasLargeMemory = result.memoryPages >= kLargeWasmMemoryPages;
                }
            }
        } else if (sectionId == kWasmSectionCode) {
            const WASMInstructionStats stats = AnalyzeCodeSection(
                std::span<const uint8_t>(sectionData, static_cast<size_t>(sectionSize)));
            if (!stats.structurallyValid) {
                result.suspiciousPatterns.emplace_back("WASM code section contains unsupported or malformed instructions");
                return result;
            }
            aggregateStats.xorCount += stats.xorCount;
            aggregateStats.mulCount += stats.mulCount;
            aggregateStats.rotateCount += stats.rotateCount;
            aggregateStats.loopCount += stats.loopCount;
            aggregateStats.totalInstructions += stats.totalInstructions;
            aggregateStats.functionCount += stats.functionCount;
            aggregateStats.sequenceScore = std::min<uint32_t>(100U,
                aggregateStats.sequenceScore + stats.sequenceScore);
        }

        cursor = sectionEnd;
    }

    result.functionCount = aggregateStats.functionCount;

    uint32_t miningScore = 0;
    if (result.hasCryptoInstructions) {
        miningScore += 45U;
        result.suspiciousPatterns.emplace_back("Crypto instruction clusters detected in code section");
    }
    if (result.hasLargeMemory) {
        miningScore += 20U;
        result.suspiciousPatterns.emplace_back("WASM module requests unusually large linear memory");
    }
    if (result.loopDensityScore >= 0.08) {
        miningScore += 20U;
        result.suspiciousPatterns.emplace_back("Loop density exceeds expected browser workload baseline");
    }
    if (aggregateStats.sequenceScore >= 70U) {
        miningScore += 15U;
        result.suspiciousPatterns.emplace_back("Arithmetic sequence profile aligns with hashing workloads");
    }

    result.confidenceScore = std::min<double>(static_cast<double>(miningScore), 100.0);
    result.isMiningModule = miningScore >= 50U;

    if (result.isMiningModule) {
        result.algorithm = result.hasLargeMemory ? BrowserMiningAlgorithm::RandomX
                                                 : BrowserMiningAlgorithm::CryptoNight;
    }

    return result;
}

bool BrowserMinerDetectorImpl::IsDomainBlockedInternal(
    const std::string& domain) const
{
    const std::string normalized = NormalizeDomainValue(domain);
    if (normalized.empty()) {
        return false;
    }

    std::shared_lock lock(m_domainsMutex);
    const auto matches = [&](const auto& container) {
        return std::any_of(container.begin(), container.end(), [&](const std::string& entry) {
            return DomainMatches(normalized, entry);
        });
    };

    return matches(m_builtinBlockedDomains) || matches(m_customBlockedDomains) || matches(m_manualBlockedDomains);
}

bool BrowserMinerDetectorImpl::IsDomainWhitelistedInternal(
    const std::string& domain) const
{
    const std::string normalized = NormalizeDomainValue(domain);
    if (normalized.empty()) {
        return false;
    }

    std::shared_lock lock(m_whitelistMutex);
    const auto matches = [&](const auto& container) {
        return std::any_of(container.begin(), container.end(),
            [&](const auto& entry) { return DomainMatches(normalized, entry.first); });
    };
    return matches(m_configWhitelistedDomains) || matches(m_manualWhitelistedDomains);
}

void BrowserMinerDetectorImpl::BlockDomainInternal(
    const std::string& domain)
{
    const std::string normalized = NormalizeDomainValue(domain);
    if (normalized.empty()) {
        return;
    }

    std::unique_lock lock(m_domainsMutex);
    const size_t totalCount = m_builtinBlockedDomains.size() +
                              m_customBlockedDomains.size() +
                              m_manualBlockedDomains.size();
    if (totalCount >= BrowserMinerConstants::MAX_BLOCKED_DOMAINS) {
        SS_LOG_WARN(kLogCategory, L"Blocked-domain capacity reached; refusing to add '%hs'", normalized.c_str());
        return;
    }

    m_manualBlockedDomains.insert(normalized);
}

void BrowserMinerDetectorImpl::LoadBuiltinBlacklist() {
    std::unique_lock lock(m_domainsMutex);
    m_builtinBlockedDomains.clear();
    for (std::string_view domain : MiningSignatures::KNOWN_MINING_DOMAINS) {
        const std::string normalized = NormalizeDomainValue(domain);
        if (!normalized.empty()) {
            m_builtinBlockedDomains.insert(normalized);
        }
    }
}

bool BrowserMinerDetectorImpl::LoadCustomBlacklistInternal(
    const std::filesystem::path& path)
{
    Utils::FileUtils::Error error;
    auto loadedDomains = LoadBlacklistFileDomains(path, error);
    if (!loadedDomains.has_value()) {
        SS_LOG_ERROR(kLogCategory, L"Unable to read blacklist '%ls' (Win32=%lu)",
            path.c_str(), static_cast<unsigned long>(error.win32));
        return false;
    }

    std::unique_lock lock(m_domainsMutex);
    if (ComputeUniqueDomainCount(m_builtinBlockedDomains, *loadedDomains, m_manualBlockedDomains) >
        BrowserMinerConstants::MAX_BLOCKED_DOMAINS) {
        SS_LOG_ERROR(kLogCategory, L"Configured blacklist exceeds maximum supported domain capacity");
        return false;
    }

    m_customBlockedDomains = std::move(*loadedDomains);
    return true;
}

bool BrowserMinerDetectorImpl::IsTabMiningInternal(
    uint32_t browserPid,
    uint64_t tabId)
{
    std::shared_lock lock(m_tabsMutex);
    const auto it = m_monitoredTabs.find(TabKey{browserPid, tabId});
    return it != m_monitoredTabs.end() && it->second.isMining;
}

std::optional<TabMiningInfo> BrowserMinerDetectorImpl::GetTabMiningInfoInternal(
    uint32_t browserPid,
    uint64_t tabId) const
{
    std::shared_lock lock(m_tabsMutex);
    const auto it = m_monitoredTabs.find(TabKey{browserPid, tabId});
    if (it == m_monitoredTabs.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<TabMiningInfo> BrowserMinerDetectorImpl::UpdateTabState(
    const BrowserScriptInfo& scriptInfo,
    const BrowserMinerDetectionResult& result,
    bool hasWasmSignal)
{
    if (scriptInfo.browserPid == 0 || scriptInfo.tabId == 0) {
        return std::nullopt;
    }

    TabMiningInfo snapshot;
    bool invokeCallback = false;

    {
        std::unique_lock lock(m_tabsMutex);
        const TabKey key{scriptInfo.browserPid, scriptInfo.tabId};
        auto existing = m_monitoredTabs.find(key);
        if (existing == m_monitoredTabs.end()) {
            if (!result.isMinerDetected) {
                return std::nullopt;
            }

            if (m_monitoredTabs.size() >= BrowserMinerConstants::MAX_MONITORED_TABS) {
                SS_LOG_WARN(kLogCategory, L"Dropping tab mining state update because monitored-tab capacity was reached");
                return std::nullopt;
            }

            existing = m_monitoredTabs.emplace(key, TabMiningInfo{}).first;
        }

        TabMiningInfo& tabInfo = existing->second;
        const bool wasMining = tabInfo.isMining;

        tabInfo.browserPid = scriptInfo.browserPid;
        tabInfo.tabId = scriptInfo.tabId;
        tabInfo.domain = scriptInfo.domain;
        tabInfo.url = scriptInfo.sourceUrl;
        tabInfo.hasWASM = tabInfo.hasWASM || hasWasmSignal || scriptInfo.scriptType == ScriptType::WebAssembly;
        tabInfo.workerCount = static_cast<uint32_t>(result.relatedWorkers.size());
        tabInfo.isMining = result.isMinerDetected;
        tabInfo.highCpuDurationSecs = result.isMinerDetected
            ? std::max<uint32_t>(tabInfo.highCpuDurationSecs, BrowserMinerConstants::SUSTAINED_CPU_SECS)
            : 0U;

        snapshot = tabInfo;
        invokeCallback = result.isMinerDetected && !wasMining;
    }

    if (invokeCallback) {
        m_statistics.tabsFlagged.fetch_add(1, std::memory_order_relaxed);
        return snapshot;
    }

    return std::nullopt;
}

std::vector<MinerFoundCallback> BrowserMinerDetectorImpl::SnapshotMinerFoundCallbacks() const {
    std::lock_guard lock(m_callbacksMutex);
    return m_minerFoundCallbacks;
}

std::vector<TabMiningCallback> BrowserMinerDetectorImpl::SnapshotTabMiningCallbacks() const {
    std::lock_guard lock(m_callbacksMutex);
    return m_tabMiningCallbacks;
}

std::vector<ErrorCallback> BrowserMinerDetectorImpl::SnapshotErrorCallbacks() const {
    std::lock_guard lock(m_callbacksMutex);
    return m_errorCallbacks;
}

std::string BrowserMinerDetectorImpl::GenerateDetectionId() const {
    return GenerateRandomDetectionId();
}

double BrowserMinerDetectorImpl::CalculateConfidenceScore(
    const std::vector<BrowserDetectionMethod>& methods,
    bool hasWASM,
    bool hasPoolConnection) const
{
    double score = 0.0;
    for (BrowserDetectionMethod method : methods) {
        switch (method) {
            case BrowserDetectionMethod::SignatureMatch:
                score += 55.0;
                break;
            case BrowserDetectionMethod::StringPattern:
                score += 20.0;
                break;
            case BrowserDetectionMethod::WASMAnalysis:
                score += 50.0;
                break;
            case BrowserDetectionMethod::BehavioralCPU:
                score += 25.0;
                break;
            case BrowserDetectionMethod::NetworkPool:
                score += 35.0;
                break;
            case BrowserDetectionMethod::WorkerAbuse:
                score += 20.0;
                break;
            case BrowserDetectionMethod::DomainBlacklist:
                score += 40.0;
                break;
            case BrowserDetectionMethod::HeuristicAnalysis:
                score += 15.0;
                break;
            case BrowserDetectionMethod::ThreatIntel:
                score += 45.0;
                break;
            case BrowserDetectionMethod::Unknown:
            default:
                break;
        }
    }

    if (methods.size() >= 2) {
        score += 10.0;
    }
    if (methods.size() >= 3) {
        score += 10.0;
    }
    if (hasWASM && hasPoolConnection) {
        score += 20.0;
    }

    return std::min(score, 100.0);
}

ThreatSeverity BrowserMinerDetectorImpl::DetermineSeverity(
    double confidence,
    BrowserMinerFamily family) const
{
    if (family == BrowserMinerFamily::Coinhive ||
        family == BrowserMinerFamily::Authedmine ||
        family == BrowserMinerFamily::CryptoLoot ||
        family == BrowserMinerFamily::CoinIMP) {
        if (confidence >= 70.0) {
            return ThreatSeverity::Critical;
        }
        if (confidence >= 50.0) {
            return ThreatSeverity::High;
        }
    }

    if (confidence >= 90.0) return ThreatSeverity::Critical;
    if (confidence >= 70.0) return ThreatSeverity::High;
    if (confidence >= 45.0) return ThreatSeverity::Medium;
    if (confidence >= 25.0) return ThreatSeverity::Low;
    return ThreatSeverity::None;
}

std::atomic<bool> BrowserMinerDetector::s_instanceCreated{false};

BrowserMinerDetector& BrowserMinerDetector::Instance() {
    static BrowserMinerDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool BrowserMinerDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

BrowserMinerDetector::BrowserMinerDetector()
    : m_impl(std::make_shared<BrowserMinerDetectorImpl>()) {}

std::shared_ptr<BrowserMinerDetectorImpl> BrowserMinerDetector::GetImplSnapshot() const noexcept {
    std::lock_guard lock(m_implMutex);
    return m_impl;
}

BrowserMinerDetector::~BrowserMinerDetector() {
    std::shared_ptr<BrowserMinerDetectorImpl> impl;
    {
        std::lock_guard lock(m_implMutex);
        impl = std::move(m_impl);
    }

    if (impl) {
        impl->Shutdown();
    }
}

bool BrowserMinerDetector::Initialize(const BrowserMinerDetectorConfiguration& config) {
    const auto impl = GetImplSnapshot();
    return impl != nullptr && impl->Initialize(config);
}

void BrowserMinerDetector::Shutdown() {
    const auto impl = GetImplSnapshot();
    if (impl) {
        impl->Shutdown();
    }
}

bool BrowserMinerDetector::IsInitialized() const noexcept {
    const auto impl = GetImplSnapshot();
    return impl != nullptr && impl->m_initialized.load(std::memory_order_acquire);
}

ModuleStatus BrowserMinerDetector::GetStatus() const noexcept {
    const auto impl = GetImplSnapshot();
    return impl != nullptr
        ? impl->m_status.load(std::memory_order_acquire)
        : ModuleStatus::Uninitialized;
}

bool BrowserMinerDetector::UpdateConfiguration(const BrowserMinerDetectorConfiguration& config) {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        SS_LOG_ERROR(kLogCategory, L"Configuration update rejected because the detector is unavailable");
        return false;
    }

    BrowserMinerDetectorConfiguration effectiveConfig = config;
    if (effectiveConfig.enableWorkerMonitoring || effectiveConfig.terminateMiningWorkers) {
        SS_LOG_WARN(kLogCategory, L"Worker telemetry and worker termination are not wired in BrowserMinerDetector; disabling those options");
        effectiveConfig.enableWorkerMonitoring = false;
        effectiveConfig.terminateMiningWorkers = false;
    }

    if (!effectiveConfig.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Configuration update rejected due to invalid detector values");
        return false;
    }

    std::unordered_map<std::string, std::string> newWhitelistedDomains;
    for (const std::string& domain : effectiveConfig.whitelistedDomains) {
        const std::string normalized = NormalizeDomainValue(domain);
        if (!normalized.empty()) {
            newWhitelistedDomains[normalized] = "Configuration";
        }
    }

    std::unordered_set<std::string> newBuiltinBlockedDomains;
    if (effectiveConfig.blockKnownDomains) {
        for (std::string_view domain : MiningSignatures::KNOWN_MINING_DOMAINS) {
            const std::string normalized = NormalizeDomainValue(domain);
            if (!normalized.empty()) {
                newBuiltinBlockedDomains.insert(normalized);
            }
        }
    }

    std::unordered_set<std::string> newCustomBlockedDomains;
    if (!effectiveConfig.domainBlacklistPath.empty()) {
        Utils::FileUtils::Error error;
        auto loadedDomains = LoadBlacklistFileDomains(effectiveConfig.domainBlacklistPath, error);
        if (!loadedDomains.has_value()) {
            SS_LOG_ERROR(kLogCategory, L"Configuration update could not load blacklist '%ls' (Win32=%lu)",
                effectiveConfig.domainBlacklistPath.c_str(), static_cast<unsigned long>(error.win32));
            return false;
        }
        newCustomBlockedDomains = std::move(*loadedDomains);
    }

    {
        std::shared_lock domainsLock(impl->m_domainsMutex);
        if (ComputeUniqueDomainCount(newBuiltinBlockedDomains, newCustomBlockedDomains,
                impl->m_manualBlockedDomains) > BrowserMinerConstants::MAX_BLOCKED_DOMAINS) {
            SS_LOG_ERROR(kLogCategory, L"Configuration update would exceed maximum blocked-domain capacity");
            return false;
        }
    }

    {
        std::unique_lock configLock(impl->m_mutex);
        std::unique_lock whitelistLock(impl->m_whitelistMutex);
        std::unique_lock domainsLock(impl->m_domainsMutex);
        impl->m_config = effectiveConfig;
        impl->m_configWhitelistedDomains = std::move(newWhitelistedDomains);
        impl->m_builtinBlockedDomains = std::move(newBuiltinBlockedDomains);
        impl->m_customBlockedDomains = std::move(newCustomBlockedDomains);
    }

    return true;
}

BrowserMinerDetectorConfiguration BrowserMinerDetector::GetConfiguration() const {
    const auto impl = GetImplSnapshot();
    return impl != nullptr ? impl->SnapshotConfiguration() : BrowserMinerDetectorConfiguration{};
}

BrowserMinerDetectionResult BrowserMinerDetector::AnalyzeScript(const std::string& scriptSource) {
    BrowserScriptInfo info;
    info.scriptSize = scriptSource.size();
    info.scriptType = ScriptType::JavaScript;
    return AnalyzeScript(scriptSource, info);
}

BrowserMinerDetectionResult BrowserMinerDetector::AnalyzeScript(
    const std::string& scriptSource,
    const BrowserScriptInfo& scriptInfo)
{
    const auto impl = GetImplSnapshot();
    return impl != nullptr
        ? impl->AnalyzeScriptInternal(scriptSource, scriptInfo)
        : BrowserMinerDetectionResult{};
}

BrowserMinerDetectionResult BrowserMinerDetector::AnalyzeWASM(std::span<const uint8_t> wasmBinary) {
    BrowserScriptInfo info;
    info.scriptSize = wasmBinary.size();
    info.scriptType = ScriptType::WebAssembly;
    return AnalyzeWASM(wasmBinary, info);
}

BrowserMinerDetectionResult BrowserMinerDetector::AnalyzeWASM(
    std::span<const uint8_t> wasmBinary,
    const BrowserScriptInfo& scriptInfo)
{
    const auto impl = GetImplSnapshot();
    return impl != nullptr
        ? impl->AnalyzeWASMInternal(wasmBinary, scriptInfo)
        : BrowserMinerDetectionResult{};
}

bool BrowserMinerDetector::QuickSignatureCheck(const std::string& content) const {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return false;
    }

    std::vector<std::string> matches;
    return impl->DetectJSMinerSignatures(content, matches);
}

bool BrowserMinerDetector::IsTabMining(uint32_t browserPid, uint64_t tabId) {
    const auto impl = GetImplSnapshot();
    return impl != nullptr && impl->IsTabMiningInternal(browserPid, tabId);
}

std::optional<TabMiningInfo> BrowserMinerDetector::GetTabMiningInfo(
    uint32_t browserPid,
    uint64_t tabId) const
{
    const auto impl = GetImplSnapshot();
    return impl != nullptr ? impl->GetTabMiningInfoInternal(browserPid, tabId) : std::nullopt;
}

std::vector<TabMiningInfo> BrowserMinerDetector::GetMiningTabs() const {
    std::vector<TabMiningInfo> tabs;
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return tabs;
    }

    std::shared_lock lock(impl->m_tabsMutex);
    for (const auto& [key, info] : impl->m_monitoredTabs) {
        (void)key;
        if (info.isMining) {
            tabs.push_back(info);
        }
    }
    return tabs;
}

void BrowserMinerDetector::StartTabMonitoring(uint32_t browserPid, uint64_t tabId) {
    const auto impl = GetImplSnapshot();
    if (!impl || browserPid == 0 || tabId == 0) {
        return;
    }

    std::unique_lock lock(impl->m_tabsMutex);
    if (impl->m_monitoredTabs.size() >= BrowserMinerConstants::MAX_MONITORED_TABS &&
        !impl->m_monitoredTabs.contains(TabKey{browserPid, tabId})) {
        SS_LOG_WARN(kLogCategory, L"Refusing to monitor additional tab because capacity was reached");
        return;
    }

    TabMiningInfo& info = impl->m_monitoredTabs[TabKey{browserPid, tabId}];
    info.browserPid = browserPid;
    info.tabId = tabId;
}

void BrowserMinerDetector::StopTabMonitoring(uint32_t browserPid, uint64_t tabId) {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return;
    }

    const TabKey key{browserPid, tabId};
    {
        std::unique_lock lock(impl->m_tabsMutex);
        impl->m_monitoredTabs.erase(key);
    }
    {
        std::unique_lock lock(impl->m_workersMutex);
        impl->m_workers.erase(key);
    }
}

std::vector<WebWorkerInfo> BrowserMinerDetector::GetWorkers(
    uint32_t browserPid,
    uint64_t tabId) const
{
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return {};
    }

    std::shared_lock lock(impl->m_workersMutex);
    const auto it = impl->m_workers.find(TabKey{browserPid, tabId});
    return it != impl->m_workers.end() ? it->second : std::vector<WebWorkerInfo>{};
}

size_t BrowserMinerDetector::TerminateMiningWorkers(uint32_t browserPid, uint64_t tabId) {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return 0;
    }

    if (browserPid == 0 || tabId == 0) {
        SS_LOG_WARN(kLogCategory, L"Worker termination request rejected because browserPid/tabId was invalid");
        return 0;
    }

    const std::string message =
        "Browser worker termination is unavailable because PhantomHome has no browser-side worker enforcement wiring";
    SS_LOG_WARN(kLogCategory, L"%hs", message.c_str());
    BrowserMinerDetectorImpl::CallbackDispatchGuard callbackDispatchGuard(*impl);
    DispatchCallbackList(impl->SnapshotErrorCallbacks(),
        [&](const ErrorCallback& callback) { callback(message, ERROR_NOT_SUPPORTED); },
        L"Error");
    return 0;
}

bool BrowserMinerDetector::IsDomainBlocked(const std::string& domain) const {
    const auto impl = GetImplSnapshot();
    return impl != nullptr && impl->IsDomainBlockedInternal(domain);
}

void BrowserMinerDetector::BlockDomain(const std::string& domain) {
    const auto impl = GetImplSnapshot();
    if (impl) {
        impl->BlockDomainInternal(domain);
    }
}

void BrowserMinerDetector::UnblockDomain(const std::string& domain) {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return;
    }

    const std::string normalized = NormalizeDomainValue(domain);
    if (normalized.empty()) {
        return;
    }

    std::unique_lock lock(impl->m_domainsMutex);
    impl->m_manualBlockedDomains.erase(normalized);
}

bool BrowserMinerDetector::LoadDomainBlacklist(const std::filesystem::path& path) {
    const auto impl = GetImplSnapshot();
    return impl != nullptr && impl->LoadCustomBlacklistInternal(path);
}

size_t BrowserMinerDetector::GetBlockedDomainCount() const noexcept {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return 0;
    }

    std::shared_lock lock(impl->m_domainsMutex);
    size_t total = impl->m_builtinBlockedDomains.size();
    for (const auto& domain : impl->m_customBlockedDomains) {
        if (!impl->m_builtinBlockedDomains.contains(domain)) {
            ++total;
        }
    }
    for (const auto& domain : impl->m_manualBlockedDomains) {
        if (!impl->m_builtinBlockedDomains.contains(domain) &&
            !impl->m_customBlockedDomains.contains(domain)) {
            ++total;
        }
    }
    return total;
}

void BrowserMinerDetector::WhitelistDomain(const std::string& domain, const std::string& reason) {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return;
    }

    const std::string normalized = NormalizeDomainValue(domain);
    if (normalized.empty()) {
        return;
    }

    std::unique_lock lock(impl->m_whitelistMutex);
    impl->m_manualWhitelistedDomains[normalized] = reason.empty() ? "Manual" : reason;
}

bool BrowserMinerDetector::IsDomainWhitelisted(const std::string& domain) const {
    const auto impl = GetImplSnapshot();
    return impl != nullptr && impl->IsDomainWhitelistedInternal(domain);
}

void BrowserMinerDetector::RegisterMinerFoundCallback(MinerFoundCallback callback) {
    const auto impl = GetImplSnapshot();
    if (!impl || !callback) {
        return;
    }

    std::lock_guard lock(impl->m_callbacksMutex);
    impl->m_minerFoundCallbacks.push_back(std::move(callback));
}

void BrowserMinerDetector::RegisterTabMiningCallback(TabMiningCallback callback) {
    const auto impl = GetImplSnapshot();
    if (!impl || !callback) {
        return;
    }

    std::lock_guard lock(impl->m_callbacksMutex);
    impl->m_tabMiningCallbacks.push_back(std::move(callback));
}

void BrowserMinerDetector::RegisterErrorCallback(ErrorCallback callback) {
    const auto impl = GetImplSnapshot();
    if (!impl || !callback) {
        return;
    }

    std::lock_guard lock(impl->m_callbacksMutex);
    impl->m_errorCallbacks.push_back(std::move(callback));
}

void BrowserMinerDetector::UnregisterCallbacks() {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return;
    }

    std::lock_guard lock(impl->m_callbacksMutex);
    impl->m_minerFoundCallbacks.clear();
    impl->m_tabMiningCallbacks.clear();
    impl->m_errorCallbacks.clear();
}

BrowserMinerStatistics BrowserMinerDetector::GetStatistics() const {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return BrowserMinerStatistics{};
    }

    std::shared_lock lock(impl->m_mutex);
    return impl->m_statistics;
}

void BrowserMinerDetector::ResetStatistics() {
    const auto impl = GetImplSnapshot();
    if (impl) {
        std::unique_lock lock(impl->m_mutex);
        impl->m_statistics.Reset();
    }
}

std::vector<BrowserMinerDetectionResult> BrowserMinerDetector::GetRecentDetections(size_t maxCount) const {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return {};
    }

    std::vector<BrowserMinerDetectionResult> detections;
    std::shared_lock lock(impl->m_detectionsMutex);
    const size_t count = std::min(maxCount, impl->m_recentDetections.size());
    detections.reserve(count);

    auto iter = impl->m_recentDetections.rbegin();
    for (size_t index = 0; index < count && iter != impl->m_recentDetections.rend(); ++index, ++iter) {
        detections.push_back(*iter);
    }

    return detections;
}

bool BrowserMinerDetector::SelfTest() {
    const auto impl = GetImplSnapshot();
    if (!impl) {
        return false;
    }

    const bool wasInitialized = IsInitialized();
    if (!wasInitialized && !Initialize()) {
        return false;
    }

    const std::string selfTestDomain = "selftest-browser-miner.invalid";
    bool blockedDomainAdded = false;

    try {
        const std::string script =
            "var miner = new CoinHive.Anonymous('site'); miner.setThrottle(25); miner.start();";
        std::vector<std::string> signatures;
        const bool matchedSignatures = impl->DetectJSMinerSignatures(script, signatures);
        const BrowserMinerFamily family = impl->IdentifyMinerFamily(script);
        const auto throttle = impl->ExtractThrottle(script);
        if (!matchedSignatures || family != BrowserMinerFamily::Coinhive || !throttle.has_value() || *throttle != 25U) {
            SS_LOG_ERROR(kLogCategory, L"Self-test failed during JavaScript miner detection");
            if (!wasInitialized) {
                Shutdown();
            }
            return false;
        }

        const std::array<uint8_t, 8> wasmHeader = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
        if (!impl->IsValidWASM(wasmHeader)) {
            SS_LOG_ERROR(kLogCategory, L"Self-test failed during WASM header validation");
            if (!wasInitialized) {
                Shutdown();
            }
            return false;
        }

        BlockDomain(selfTestDomain);
        blockedDomainAdded = true;
        const bool blocked = IsDomainBlocked(selfTestDomain);
        UnblockDomain(selfTestDomain);
        blockedDomainAdded = false;
        if (!blocked || IsDomainBlocked(selfTestDomain)) {
            SS_LOG_ERROR(kLogCategory, L"Self-test failed during domain blacklist round-trip");
            if (!wasInitialized) {
                Shutdown();
            }
            return false;
        }
    } catch (const std::exception& exception) {
        SS_LOG_ERROR(kLogCategory, L"Self-test raised exception: %ls",
            Utils::StringUtils::ToWide(exception.what()).c_str());
        if (blockedDomainAdded) {
            UnblockDomain(selfTestDomain);
        }
        if (!wasInitialized) {
            Shutdown();
        }
        return false;
    }

    if (!wasInitialized) {
        Shutdown();
    }

    return true;
}

std::string BrowserMinerDetector::GetVersionString() {
    return std::format("{}.{}.{}",
        BrowserMinerConstants::VERSION_MAJOR,
        BrowserMinerConstants::VERSION_MINOR,
        BrowserMinerConstants::VERSION_PATCH);
}

BrowserMinerStatistics::BrowserMinerStatistics(const BrowserMinerStatistics& other) noexcept {
    *this = other;
}

BrowserMinerStatistics& BrowserMinerStatistics::operator=(const BrowserMinerStatistics& other) noexcept {
    if (this == &other) {
        return *this;
    }

    scriptsScanned.store(other.scriptsScanned.load(std::memory_order_relaxed), std::memory_order_relaxed);
    wasmModulesScanned.store(other.wasmModulesScanned.load(std::memory_order_relaxed), std::memory_order_relaxed);
    minersDetected.store(other.minersDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    minersBlocked.store(other.minersBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    domainsBlocked.store(other.domainsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    workersTerminated.store(other.workersTerminated.load(std::memory_order_relaxed), std::memory_order_relaxed);
    tabsFlagged.store(other.tabsFlagged.load(std::memory_order_relaxed), std::memory_order_relaxed);

    for (size_t index = 0; index < byFamily.size(); ++index) {
        byFamily[index].store(other.byFamily[index].load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
    for (size_t index = 0; index < byMethod.size(); ++index) {
        byMethod[index].store(other.byMethod[index].load(std::memory_order_relaxed), std::memory_order_relaxed);
    }

    startTime = other.startTime;
    return *this;
}

void BrowserMinerStatistics::Reset() noexcept {
    scriptsScanned.store(0, std::memory_order_relaxed);
    wasmModulesScanned.store(0, std::memory_order_relaxed);
    minersDetected.store(0, std::memory_order_relaxed);
    minersBlocked.store(0, std::memory_order_relaxed);
    domainsBlocked.store(0, std::memory_order_relaxed);
    workersTerminated.store(0, std::memory_order_relaxed);
    tabsFlagged.store(0, std::memory_order_relaxed);

    for (auto& counter : byFamily) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byMethod) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

std::string BrowserMinerStatistics::ToJson() const {
    nlohmann::json json = {
        {"scriptsScanned", scriptsScanned.load(std::memory_order_relaxed)},
        {"wasmModulesScanned", wasmModulesScanned.load(std::memory_order_relaxed)},
        {"minersDetected", minersDetected.load(std::memory_order_relaxed)},
        {"minersBlocked", minersBlocked.load(std::memory_order_relaxed)},
        {"domainsBlocked", domainsBlocked.load(std::memory_order_relaxed)},
        {"workersTerminated", workersTerminated.load(std::memory_order_relaxed)},
        {"tabsFlagged", tabsFlagged.load(std::memory_order_relaxed)}
    };
    return json.dump(2);
}

bool BrowserMinerDetectorConfiguration::IsValid() const noexcept {
    return maxScriptScanSize > 0 &&
           maxScriptScanSize <= 100ULL * 1024ULL * 1024ULL &&
           maxWASMSize > 0 &&
           maxWASMSize <= 200ULL * 1024ULL * 1024ULL &&
           tabCpuThreshold >= 0.0 && tabCpuThreshold <= 100.0 &&
           confidenceThreshold >= 0.0 && confidenceThreshold <= 1.0;
}

std::string BrowserScriptInfo::ToJson() const {
    nlohmann::json json = {
        {"browserPid", browserPid},
        {"tabId", tabId},
        {"frameId", frameId},
        {"sourceUrl", sourceUrl},
        {"domain", domain},
        {"scriptType", static_cast<int>(scriptType)},
        {"scriptSize", scriptSize},
        {"isInline", isInline},
        {"isFromExtension", isFromExtension}
    };
    return json.dump(2);
}

std::string WebWorkerInfo::ToJson() const {
    nlohmann::json json = {
        {"workerId", workerId},
        {"parentTabId", parentTabId},
        {"workerType", static_cast<int>(workerType)},
        {"scriptUrl", scriptUrl},
        {"workerName", workerName},
        {"cpuUsage", cpuUsage},
        {"memoryUsage", memoryUsage},
        {"isMiningSpected", isMiningSpected}
    };
    return json.dump(2);
}

std::string WASMAnalysisResult::ToJson() const {
    nlohmann::json json = {
        {"isValidWASM", isValidWASM},
        {"moduleSize", moduleSize},
        {"isMiningModule", isMiningModule},
        {"algorithm", static_cast<int>(algorithm)},
        {"hasCryptoInstructions", hasCryptoInstructions},
        {"hasLargeMemory", hasLargeMemory},
        {"memoryPages", memoryPages},
        {"functionCount", functionCount},
        {"loopDensityScore", loopDensityScore},
        {"confidenceScore", confidenceScore},
        {"suspiciousPatterns", suspiciousPatterns}
    };
    return json.dump(2);
}

std::string BrowserMinerDetectionResult::ToJson() const {
    nlohmann::json json = {
        {"detectionId", detectionId},
        {"isMinerDetected", isMinerDetected},
        {"minerFamily", static_cast<int>(minerFamily)},
        {"familyName", familyName},
        {"algorithm", static_cast<int>(algorithm)},
        {"detectionMethod", static_cast<int>(detectionMethod)},
        {"additionalMethods", nlohmann::json::array()},
        {"severity", static_cast<int>(severity)},
        {"confidenceScore", confidenceScore},
        {"poolAddresses", poolAddresses},
        {"walletAddress", walletAddress},
        {"evidence", evidence},
        {"matchedSignatures", matchedSignatures},
        {"isWhitelisted", isWhitelisted},
        {"scriptInfo", nlohmann::json::parse(scriptInfo.ToJson())}
    };

    for (BrowserDetectionMethod method : additionalMethods) {
        json["additionalMethods"].push_back(static_cast<int>(method));
    }
    if (throttlePercent.has_value()) {
        json["throttlePercent"] = *throttlePercent;
    }
    if (wasmAnalysis.has_value()) {
        json["wasmAnalysis"] = nlohmann::json::parse(wasmAnalysis->ToJson());
    }
    if (!relatedWorkers.empty()) {
        json["relatedWorkers"] = nlohmann::json::array();
        for (const auto& worker : relatedWorkers) {
            json["relatedWorkers"].push_back(nlohmann::json::parse(worker.ToJson()));
        }
    }

    return json.dump(2);
}

std::string TabMiningInfo::ToJson() const {
    nlohmann::json json = {
        {"tabId", tabId},
        {"browserPid", browserPid},
        {"url", url},
        {"domain", domain},
        {"isMining", isMining},
        {"cpuUsage", cpuUsage},
        {"avgCpuUsage", avgCpuUsage},
        {"peakCpuUsage", peakCpuUsage},
        {"highCpuDurationSecs", highCpuDurationSecs},
        {"workerCount", workerCount},
        {"hasWASM", hasWASM},
        {"isBackgroundTab", isBackgroundTab}
    };
    return json.dump(2);
}

std::string_view GetScriptTypeName(ScriptType type) noexcept {
    switch (type) {
        case ScriptType::Unknown: return "Unknown";
        case ScriptType::JavaScript: return "JavaScript";
        case ScriptType::MinifiedJS: return "Minified JavaScript";
        case ScriptType::ObfuscatedJS: return "Obfuscated JavaScript";
        case ScriptType::WebAssembly: return "WebAssembly";
        case ScriptType::AsmJS: return "asm.js";
        case ScriptType::TypeScript: return "TypeScript";
        default: return "Unknown";
    }
}

std::string_view GetBrowserMinerFamilyName(BrowserMinerFamily family) noexcept {
    switch (family) {
        case BrowserMinerFamily::Unknown: return "Unknown";
        case BrowserMinerFamily::Coinhive: return "Coinhive";
        case BrowserMinerFamily::CryptoLoot: return "CryptoLoot";
        case BrowserMinerFamily::CoinIMP: return "CoinIMP";
        case BrowserMinerFamily::JSECoin: return "JSECoin";
        case BrowserMinerFamily::WebMinePool: return "WebMinePool";
        case BrowserMinerFamily::Authedmine: return "Authedmine";
        case BrowserMinerFamily::DeepMiner: return "DeepMiner";
        case BrowserMinerFamily::MineMyTraffic: return "MineMyTraffic";
        case BrowserMinerFamily::PPoi: return "PPoi";
        case BrowserMinerFamily::GenericWASM: return "Generic WASM";
        case BrowserMinerFamily::GenericJS: return "Generic JavaScript";
        case BrowserMinerFamily::Custom: return "Custom";
        default: return "Unknown";
    }
}

std::string_view GetBrowserMiningAlgorithmName(BrowserMiningAlgorithm algo) noexcept {
    switch (algo) {
        case BrowserMiningAlgorithm::Unknown: return "Unknown";
        case BrowserMiningAlgorithm::CryptoNight: return "CryptoNight";
        case BrowserMiningAlgorithm::RandomX: return "RandomX";
        case BrowserMiningAlgorithm::CryptoNightR: return "CryptoNight-R";
        case BrowserMiningAlgorithm::CryptoNightV7: return "CryptoNight v7";
        case BrowserMiningAlgorithm::CryptoNightLite: return "CryptoNight Lite";
        case BrowserMiningAlgorithm::Argon2: return "Argon2";
        default: return "Unknown";
    }
}

std::string_view GetBrowserDetectionMethodName(BrowserDetectionMethod method) noexcept {
    switch (method) {
        case BrowserDetectionMethod::Unknown: return "Unknown";
        case BrowserDetectionMethod::SignatureMatch: return "Signature Match";
        case BrowserDetectionMethod::StringPattern: return "String Pattern";
        case BrowserDetectionMethod::WASMAnalysis: return "WASM Analysis";
        case BrowserDetectionMethod::BehavioralCPU: return "Behavioral CPU";
        case BrowserDetectionMethod::NetworkPool: return "Network Pool";
        case BrowserDetectionMethod::WorkerAbuse: return "Worker Abuse";
        case BrowserDetectionMethod::DomainBlacklist: return "Domain Blacklist";
        case BrowserDetectionMethod::HeuristicAnalysis: return "Heuristic Analysis";
        case BrowserDetectionMethod::ThreatIntel: return "Threat Intel";
        default: return "Unknown";
    }
}

std::string_view GetWebWorkerTypeName(WebWorkerType type) noexcept {
    switch (type) {
        case WebWorkerType::Unknown: return "Unknown";
        case WebWorkerType::Dedicated: return "Dedicated Worker";
        case WebWorkerType::Shared: return "Shared Worker";
        case WebWorkerType::Service: return "Service Worker";
        default: return "Unknown";
    }
}

bool IsKnownMiningDomain(std::string_view domain) {
    const std::string normalized = NormalizeDomainValue(domain);
    if (normalized.empty()) {
        return false;
    }

    return std::any_of(MiningSignatures::KNOWN_MINING_DOMAINS.begin(),
        MiningSignatures::KNOWN_MINING_DOMAINS.end(), [&](std::string_view knownDomain) {
            return DomainMatches(normalized, NormalizeDomainValue(knownDomain));
        });
}

std::string ExtractDomain(std::string_view url) {
    return NormalizeDomainValue(url);
}

}  // namespace CryptoMiners
}  // namespace ShadowStrike
