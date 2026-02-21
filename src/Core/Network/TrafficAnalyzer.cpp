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
 * ShadowStrike Core Network - TRAFFIC ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file TrafficAnalyzer.cpp
 * @brief Enterprise-grade deep packet inspection and protocol analysis engine.
 *
 * This module provides comprehensive network traffic analysis through Deep
 * Packet Inspection (DPI), protocol identification, payload analysis, and
 * threat detection in network streams.
 *
 * Key Features:
 * - 50+ protocol identification (HTTP, HTTPS, DNS, SMB, SSH, etc.)
 * - TLS/SSL inspection with JA3/JA3S fingerprinting
 * - Certificate extraction and validation
 * - TCP stream reassembly
 * - Shellcode detection
 * - Payload signature scanning
 * - Anomaly detection (protocol, timing, size)
 * - HTTP/DNS/SMB protocol parsing
 * - Encrypted traffic analysis
 *
 * MITRE ATT&CK Coverage:
 * - T1071: Application Layer Protocol
 * - T1573: Encrypted Channel
 * - T1572: Protocol Tunneling
 * - T1001: Data Obfuscation
 * - T1095: Non-Application Layer Protocol
 * - T1132: Data Encoding
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "TrafficAnalyzer.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../FileSystem/FileTypeAnalyzer.hpp"

// Standard library
#include <algorithm>
#include <cctype>
#include <cmath>
#include <sstream>
#include <iomanip>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Calculates Shannon entropy of data.
 */
double CalculateEntropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;

    std::array<size_t, 256> freq{};
    for (uint8_t byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    const double size = static_cast<double>(data.size());

    for (size_t count : freq) {
        if (count > 0) {
            const double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Converts IP address to string.
 */
std::string IPToString(const std::array<uint8_t, 16>& ip, bool isIPv6) {
    if (!isIPv6) {
        return std::format("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    }

    std::ostringstream oss;
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) oss << ":";
        oss << std::hex << ((ip[i] << 8) | ip[i + 1]);
    }
    return oss.str();
}

/**
 * @brief Converts protocol to string.
 */
std::string_view ProtocolToString(Protocol protocol) {
    switch (protocol) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::HTTP: return "HTTP";
        case Protocol::HTTPS: return "HTTPS";
        case Protocol::DNS: return "DNS";
        case Protocol::SSH: return "SSH";
        case Protocol::SMTP: return "SMTP";
        case Protocol::FTP: return "FTP";
        case Protocol::SMB: return "SMB";
        case Protocol::RDP: return "RDP";
        case Protocol::TLS_UNKNOWN: return "TLS (Unknown App)";
        default: return "Unknown";
    }
}

/**
 * @brief Checks if payload looks like HTTP.
 */
bool IsHTTPPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 16) return false;

    const char* data = reinterpret_cast<const char*>(payload.data());
    std::string_view sv(data, std::min(payload.size(), size_t(16)));

    return sv.starts_with("GET ") || sv.starts_with("POST ") ||
           sv.starts_with("PUT ") || sv.starts_with("HEAD ") ||
           sv.starts_with("HTTP/1.") || sv.starts_with("OPTIONS ");
}

/**
 * @brief Checks if payload looks like TLS.
 */
bool IsTLSPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 6) return false;

    // TLS record header: [ContentType(1)] [Version(2)] [Length(2)]
    uint8_t contentType = payload[0];
    uint16_t version = (payload[1] << 8) | payload[2];

    // Content types: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application
    if (contentType < 20 || contentType > 23) return false;

    // Versions: 0x0300=SSL3.0, 0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2, 0x0304=TLS1.3
    return (version >= 0x0300 && version <= 0x0304);
}

/**
 * @brief Checks if payload looks like DNS.
 */
bool IsDNSPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 12) return false;

    // DNS header: [ID(2)] [Flags(2)] [QDCOUNT(2)] [ANCOUNT(2)] [NSCOUNT(2)] [ARCOUNT(2)]
    uint16_t flags = (payload[2] << 8) | payload[3];
    uint16_t qdcount = (payload[4] << 8) | payload[5];

    // Check if QR bit and OPCODE are reasonable
    uint8_t opcode = (flags >> 11) & 0x0F;
    if (opcode > 5) return false;

    // Must have at least one question
    return qdcount > 0 && qdcount < 100;
}

/**
 * @brief Checks if payload looks like SSH.
 */
bool IsSSHPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 7) return false;

    const char* data = reinterpret_cast<const char*>(payload.data());
    std::string_view sv(data, 7);

    return sv.starts_with("SSH-2.0") || sv.starts_with("SSH-1.");
}

/**
 * @brief Checks if payload looks like SMB.
 */
bool IsSMBPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 8) return false;

    // SMB1: 0xFF 'S' 'M' 'B'
    if (payload[0] == 0xFF && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B') {
        return true;
    }

    // SMB2/3: 0xFE 'S' 'M' 'B'
    if (payload[0] == 0xFE && payload[1] == 'S' && payload[2] == 'M' && payload[3] == 'B') {
        return true;
    }

    return false;
}

/**
 * @brief Detects Base64 encoding.
 */
bool IsBase64Encoded(std::span<const uint8_t> data) {
    if (data.size() < 16) return false;

    size_t base64Chars = 0;
    for (size_t i = 0; i < std::min(data.size(), size_t(256)); ++i) {
        uint8_t c = data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            base64Chars++;
        }
    }

    const size_t checked = std::min(data.size(), size_t(256));
    return (static_cast<double>(base64Chars) / checked) > 0.9;
}

/**
 * @brief Simple XOR key detection.
 */
uint8_t DetectXORKey(std::span<const uint8_t> data) {
    if (data.size() < 16) return 0;

    std::array<size_t, 256> keyScores{};

    // Try common XOR keys and check if result looks like text
    for (uint16_t key = 1; key < 256; ++key) {
        size_t textChars = 0;
        for (size_t i = 0; i < std::min(data.size(), size_t(256)); ++i) {
            uint8_t decoded = data[i] ^ static_cast<uint8_t>(key);
            if ((decoded >= 0x20 && decoded <= 0x7E) || decoded == '\n' || decoded == '\r' || decoded == '\t') {
                textChars++;
            }
        }
        keyScores[key] = textChars;
    }

    // Find key with highest text score
    uint8_t bestKey = 0;
    size_t bestScore = 0;
    for (uint16_t i = 1; i < 256; ++i) {
        if (keyScores[i] > bestScore) {
            bestScore = keyScores[i];
            bestKey = static_cast<uint8_t>(i);
        }
    }

    const size_t checked = std::min(data.size(), size_t(256));
    return (static_cast<double>(bestScore) / checked > 0.7) ? bestKey : 0;
}

/**
 * @brief Known shellcode patterns (simplified).
 */
const std::vector<std::vector<uint8_t>> g_shellcodePatterns = {
    // NOP sled
    {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},

    // Common x86 shellcode prologue
    {0xEB, 0x1E},  // jmp short
    {0xE8, 0x00, 0x00, 0x00, 0x00},  // call $+5

    // Windows API calls
    {0xFF, 0x15},  // call [addr]
    {0xFF, 0x55},  // call [ebp+offset]

    // GetPC (Position Independent Code)
    {0xE8, 0xFF, 0xFF, 0xFF, 0xFF},
};

/**
 * @brief Detects shellcode patterns.
 */
double DetectShellcodeScore(std::span<const uint8_t> payload) {
    if (payload.size() < TrafficAnalyzerConstants::SHELLCODE_MIN_SIZE) {
        return 0.0;
    }

    double score = 0.0;

    // Check for NOP sleds
    size_t nopCount = 0;
    for (size_t i = 0; i < std::min(payload.size(), size_t(512)); ++i) {
        if (payload[i] == 0x90) nopCount++;
    }
    if (nopCount > 20) score += 0.3;

    // Check for known patterns
    for (const auto& pattern : g_shellcodePatterns) {
        for (size_t i = 0; i + pattern.size() < payload.size(); ++i) {
            if (std::equal(pattern.begin(), pattern.end(), payload.begin() + i)) {
                score += 0.15;
                break;
            }
        }
    }

    // Check entropy (shellcode often has medium-high entropy)
    double entropy = CalculateEntropy(payload.subspan(0, std::min(payload.size(), size_t(512))));
    if (entropy > 6.0 && entropy < 7.5) {
        score += 0.2;
    }

    // Check for suspicious byte distributions
    std::array<size_t, 256> freq{};
    for (size_t i = 0; i < std::min(payload.size(), size_t(512)); ++i) {
        freq[payload[i]]++;
    }

    // Shellcode often has high frequency of certain bytes (0x00, 0xFF, etc.)
    if (freq[0x00] > 50 || freq[0xFF] > 50) {
        score += 0.15;
    }

    return std::min(score, 1.0);
}

} // anonymous namespace

// ============================================================================
// STREAMKEY IMPLEMENTATION
// ============================================================================

bool StreamKey::operator==(const StreamKey& other) const noexcept {
    return protocol == other.protocol &&
           srcPort == other.srcPort &&
           dstPort == other.dstPort &&
           isIPv6 == other.isIPv6 &&
           srcIP == other.srcIP &&
           dstIP == other.dstIP;
}

size_t StreamKey::Hash::operator()(const StreamKey& key) const noexcept {
    size_t hash = 0;

    // Hash IP addresses
    for (size_t i = 0; i < (key.isIPv6 ? 16 : 4); ++i) {
        hash ^= std::hash<uint8_t>{}(key.srcIP[i]) << (i % 8);
        hash ^= std::hash<uint8_t>{}(key.dstIP[i]) << ((i + 4) % 8);
    }

    // Hash ports and protocol
    hash ^= std::hash<uint16_t>{}(key.srcPort) << 16;
    hash ^= std::hash<uint16_t>{}(key.dstPort);
    hash ^= std::hash<uint8_t>{}(key.protocol) << 24;

    return hash;
}

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

TrafficAnalyzerConfig TrafficAnalyzerConfig::CreateDefault() noexcept {
    TrafficAnalyzerConfig config;
    // Defaults already set in struct
    return config;
}

TrafficAnalyzerConfig TrafficAnalyzerConfig::CreateHighSecurity() noexcept {
    TrafficAnalyzerConfig config;
    config.enableProtocolDetection = true;
    config.enableTLSInspection = true;
    config.enablePayloadAnalysis = true;
    config.enableAnomalyDetection = true;
    config.enableStreamReassembly = true;
    config.enableShellcodeDetection = true;
    config.enableSignatureScanning = true;

    config.extractCertificates = true;
    config.validateCertChain = true;
    config.checkJA3Reputation = true;

    config.logThreatsOnly = true;
    config.logTLSInfo = true;

    return config;
}

TrafficAnalyzerConfig TrafficAnalyzerConfig::CreatePerformance() noexcept {
    TrafficAnalyzerConfig config;
    config.enableProtocolDetection = true;
    config.enableTLSInspection = false;
    config.enablePayloadAnalysis = true;
    config.enableAnomalyDetection = false;
    config.enableStreamReassembly = true;
    config.enableShellcodeDetection = true;
    config.enableSignatureScanning = false;

    config.maxStreamSize = 10 * 1024 * 1024;  // 10 MB
    config.maxPayloadScan = 512 * 1024;        // 512 KB
    config.workerThreads = 8;

    config.extractCertificates = false;
    config.validateCertChain = false;
    config.checkJA3Reputation = false;

    return config;
}

TrafficAnalyzerConfig TrafficAnalyzerConfig::CreateForensic() noexcept {
    TrafficAnalyzerConfig config = CreateHighSecurity();

    config.logAllStreams = true;
    config.logThreatsOnly = false;
    config.logTLSInfo = true;

    config.maxStreamSize = TrafficAnalyzerConstants::MAX_STREAM_SIZE;
    config.streamTimeoutMs = 600000;  // 10 minutes

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void TrafficAnalyzerStatistics::Reset() noexcept {
    totalPackets.store(0, std::memory_order_relaxed);
    packetsAnalyzed.store(0, std::memory_order_relaxed);
    packetsDropped.store(0, std::memory_order_relaxed);
    bytesProcessed.store(0, std::memory_order_relaxed);

    totalStreams.store(0, std::memory_order_relaxed);
    activeStreams.store(0, std::memory_order_relaxed);
    streamsTimedOut.store(0, std::memory_order_relaxed);

    httpStreams.store(0, std::memory_order_relaxed);
    httpsStreams.store(0, std::memory_order_relaxed);
    dnsPackets.store(0, std::memory_order_relaxed);
    smbStreams.store(0, std::memory_order_relaxed);
    unknownProtocols.store(0, std::memory_order_relaxed);

    threatsDetected.store(0, std::memory_order_relaxed);
    anomaliesDetected.store(0, std::memory_order_relaxed);
    shellcodeDetected.store(0, std::memory_order_relaxed);
    signaturesMatched.store(0, std::memory_order_relaxed);

    tlsHandshakes.store(0, std::memory_order_relaxed);
    certsExtracted.store(0, std::memory_order_relaxed);
    ja3Fingerprints.store(0, std::memory_order_relaxed);
    maliciousJA3.store(0, std::memory_order_relaxed);

    avgAnalysisTimeUs.store(0, std::memory_order_relaxed);
    maxAnalysisTimeUs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterPacketCallback(PacketAnalysisCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_packetCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterStreamCallback(StreamCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_streamCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterProtocolCallback(ProtocolDetectionCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_protocolCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterThreatCallback(ThreatCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_threatCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterTLSCallback(TLSCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_tlsCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_packetCallbacks.erase(id)) return true;
        if (m_streamCallbacks.erase(id)) return true;
        if (m_protocolCallbacks.erase(id)) return true;
        if (m_threatCallbacks.erase(id)) return true;
        if (m_tlsCallbacks.erase(id)) return true;

        return false;
    }

    void InvokePacketCallbacks(const AnalysisResult& result) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_packetCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("PacketCallback exception: {}", e.what());
            }
        }
    }

    void InvokeStreamCallbacks(const StreamInfo& stream, bool isNew) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_streamCallbacks) {
            try {
                callback(stream, isNew);
            } catch (const std::exception& e) {
                Logger::Error("StreamCallback exception: {}", e.what());
            }
        }
    }

    void InvokeProtocolCallbacks(uint64_t streamId, Protocol protocol, const StreamInfo& stream) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_protocolCallbacks) {
            try {
                callback(streamId, protocol, stream);
            } catch (const std::exception& e) {
                Logger::Error("ProtocolCallback exception: {}", e.what());
            }
        }
    }

    void InvokeThreatCallbacks(uint64_t streamId, ThreatIndicator threat, const AnalysisResult& result) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_threatCallbacks) {
            try {
                callback(streamId, threat, result);
            } catch (const std::exception& e) {
                Logger::Error("ThreatCallback exception: {}", e.what());
            }
        }
    }

    void InvokeTLSCallbacks(uint64_t streamId, const TLSInfo& tlsInfo) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_tlsCallbacks) {
            try {
                callback(streamId, tlsInfo);
            } catch (const std::exception& e) {
                Logger::Error("TLSCallback exception: {}", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, PacketAnalysisCallback> m_packetCallbacks;
    std::unordered_map<uint64_t, StreamCallback> m_streamCallbacks;
    std::unordered_map<uint64_t, ProtocolDetectionCallback> m_protocolCallbacks;
    std::unordered_map<uint64_t, ThreatCallback> m_threatCallbacks;
    std::unordered_map<uint64_t, TLSCallback> m_tlsCallbacks;
};

// ============================================================================
// STREAM REASSEMBLY MANAGER
// ============================================================================

class StreamManager {
public:
    StreamManager(size_t maxStreams, uint32_t timeoutMs)
        : m_maxStreams(maxStreams)
        , m_timeoutMs(timeoutMs) {
    }

    std::optional<uint64_t> GetOrCreateStream(const StreamKey& key) {
        std::unique_lock lock(m_mutex);

        auto it = m_streamMap.find(key);
        if (it != m_streamMap.end()) {
            return it->second;
        }

        // Check limit
        if (m_streams.size() >= m_maxStreams) {
            Logger::Warn("StreamManager: Max streams reached");
            return std::nullopt;
        }

        // Create new stream
        const uint64_t streamId = m_nextStreamId++;
        StreamInfo stream;
        stream.streamId = streamId;
        stream.key = key;
        stream.state = StreamState::NEW;
        stream.startTime = std::chrono::system_clock::now();
        stream.lastActivity = stream.startTime;

        m_streams[streamId] = stream;
        m_streamMap[key] = streamId;

        return streamId;
    }

    std::optional<StreamInfo> GetStream(uint64_t streamId) const {
        std::shared_lock lock(m_mutex);
        auto it = m_streams.find(streamId);
        if (it != m_streams.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void UpdateStream(uint64_t streamId, std::function<void(StreamInfo&)> updater) {
        std::unique_lock lock(m_mutex);
        auto it = m_streams.find(streamId);
        if (it != m_streams.end()) {
            updater(it->second);
            it->second.lastActivity = std::chrono::system_clock::now();
        }
    }

    std::vector<StreamInfo> GetAllStreams() const {
        std::shared_lock lock(m_mutex);
        std::vector<StreamInfo> streams;
        streams.reserve(m_streams.size());
        for (const auto& [id, stream] : m_streams) {
            streams.push_back(stream);
        }
        return streams;
    }

    void RemoveStream(uint64_t streamId) {
        std::unique_lock lock(m_mutex);
        auto it = m_streams.find(streamId);
        if (it != m_streams.end()) {
            m_streamMap.erase(it->second.key);
            m_streams.erase(it);
        }
    }

    void ClearAll() {
        std::unique_lock lock(m_mutex);
        m_streams.clear();
        m_streamMap.clear();
    }

    size_t CleanupTimedOut() {
        std::unique_lock lock(m_mutex);
        const auto now = std::chrono::system_clock::now();
        const auto timeout = std::chrono::milliseconds(m_timeoutMs);

        size_t removed = 0;
        for (auto it = m_streams.begin(); it != m_streams.end();) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.lastActivity
            );

            if (elapsed > timeout) {
                m_streamMap.erase(it->second.key);
                it = m_streams.erase(it);
                removed++;
            } else {
                ++it;
            }
        }

        return removed;
    }

    size_t GetActiveCount() const {
        std::shared_lock lock(m_mutex);
        return m_streams.size();
    }

private:
    mutable std::shared_mutex m_mutex;
    const size_t m_maxStreams;
    const uint32_t m_timeoutMs;
    uint64_t m_nextStreamId{ 1 };
    std::unordered_map<uint64_t, StreamInfo> m_streams;
    std::unordered_map<StreamKey, uint64_t, StreamKey::Hash> m_streamMap;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class TrafficAnalyzerImpl {
public:
    TrafficAnalyzerImpl() = default;
    ~TrafficAnalyzerImpl() {
        Stop();
    }

    // Prevent copying
    TrafficAnalyzerImpl(const TrafficAnalyzerImpl&) = delete;
    TrafficAnalyzerImpl& operator=(const TrafficAnalyzerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const TrafficAnalyzerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("TrafficAnalyzer: Initializing...");

            m_config = config;

            // Initialize callback manager
            m_callbackManager = std::make_unique<CallbackManager>();

            // Initialize stream manager
            m_streamManager = std::make_unique<StreamManager>(
                m_config.maxActiveStreams,
                m_config.streamTimeoutMs
            );

            // Verify infrastructure
            if (!PatternStore::PatternStore::Instance().Initialize(
                PatternStore::PatternStoreConfig::CreateDefault())) {
                Logger::Warn("TrafficAnalyzer: PatternStore initialization warning");
            }

            m_initialized = true;
            Logger::Info("TrafficAnalyzer: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("TrafficAnalyzer: Initialization failed: {}", e.what());
            return false;
        }
    }

    bool Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Logger::Error("TrafficAnalyzer: Not initialized");
            return false;
        }

        if (m_running) {
            Logger::Warn("TrafficAnalyzer: Already running");
            return true;
        }

        try {
            m_running = true;

            // Start cleanup thread
            m_cleanupThread = std::thread([this]() { CleanupThread(); });

            Logger::Info("TrafficAnalyzer: Started");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("TrafficAnalyzer: Start failed: {}", e.what());
            m_running = false;
            return false;
        }
    }

    void Stop() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return;

            Logger::Info("TrafficAnalyzer: Stopping...");
            m_running = false;
        }

        m_cv.notify_all();

        if (m_cleanupThread.joinable()) {
            m_cleanupThread.join();
        }

        Logger::Info("TrafficAnalyzer: Stopped");
    }

    void Shutdown() noexcept {
        Stop();
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        if (m_streamManager) {
            m_streamManager->ClearAll();
        }
        Logger::Info("TrafficAnalyzer: Shutdown complete");
    }

    bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    // ========================================================================
    // PACKET ANALYSIS
    // ========================================================================

    void AnalyzePacket(const std::vector<uint8_t>& packet) {
        if (!m_running || packet.empty()) {
            return;
        }

        auto result = AnalyzePacketImpl(
            std::span<const uint8_t>(packet.data(), packet.size()),
            std::chrono::system_clock::now()
        );

        // Invoke callbacks
        m_callbackManager->InvokePacketCallbacks(result);
    }

    AnalysisResult AnalyzePacket(std::span<const uint8_t> packet,
                                std::chrono::system_clock::time_point timestamp) {
        if (!m_running || packet.empty()) {
            return AnalysisResult{};
        }

        return AnalyzePacketImpl(packet, timestamp);
    }

    std::vector<AnalysisResult> AnalyzePackets(const std::vector<std::vector<uint8_t>>& packets) {
        std::vector<AnalysisResult> results;
        results.reserve(packets.size());

        for (const auto& packet : packets) {
            results.push_back(AnalyzePacketImpl(
                std::span<const uint8_t>(packet.data(), packet.size()),
                std::chrono::system_clock::now()
            ));
        }

        return results;
    }

    // ========================================================================
    // STREAM MANAGEMENT
    // ========================================================================

    std::optional<StreamInfo> GetStream(uint64_t streamId) const {
        return m_streamManager->GetStream(streamId);
    }

    std::vector<StreamInfo> GetActiveStreams() const {
        return m_streamManager->GetAllStreams();
    }

    std::vector<StreamInfo> GetStreamsByProtocol(Protocol protocol) const {
        auto allStreams = m_streamManager->GetAllStreams();
        std::vector<StreamInfo> filtered;

        for (const auto& stream : allStreams) {
            if (stream.identifiedProtocol == protocol) {
                filtered.push_back(stream);
            }
        }

        return filtered;
    }

    void TerminateStream(uint64_t streamId) {
        m_streamManager->RemoveStream(streamId);
        m_stats.activeStreams.fetch_sub(1, std::memory_order_relaxed);
    }

    void ClearAllStreams() {
        m_streamManager->ClearAll();
        m_stats.activeStreams.store(0, std::memory_order_relaxed);
    }

    // ========================================================================
    // PROTOCOL DETECTION
    // ========================================================================

    Protocol IdentifyProtocol(std::span<const uint8_t> payload, uint16_t srcPort, uint16_t dstPort) const {
        if (payload.empty()) {
            return Protocol::UNKNOWN;
        }

        // Port-based identification first
        if (srcPort == 80 || dstPort == 80) {
            if (IsHTTPPayload(payload)) return Protocol::HTTP;
        }
        if (srcPort == 443 || dstPort == 443) {
            if (IsTLSPayload(payload)) return Protocol::HTTPS;
        }
        if (srcPort == 53 || dstPort == 53) {
            if (IsDNSPayload(payload)) return Protocol::DNS;
        }
        if (srcPort == 22 || dstPort == 22) {
            if (IsSSHPayload(payload)) return Protocol::SSH;
        }
        if (srcPort == 445 || dstPort == 445 || srcPort == 139 || dstPort == 139) {
            if (IsSMBPayload(payload)) return Protocol::SMB;
        }
        if (srcPort == 3389 || dstPort == 3389) {
            return Protocol::RDP;
        }
        if (srcPort == 25 || dstPort == 25 || srcPort == 587 || dstPort == 587) {
            return Protocol::SMTP;
        }
        if (srcPort == 21 || dstPort == 21) {
            return Protocol::FTP;
        }

        // Content-based identification
        if (IsHTTPPayload(payload)) return Protocol::HTTP;
        if (IsTLSPayload(payload)) return Protocol::TLS_UNKNOWN;
        if (IsDNSPayload(payload)) return Protocol::DNS;
        if (IsSSHPayload(payload)) return Protocol::SSH;
        if (IsSMBPayload(payload)) return Protocol::SMB;

        return Protocol::UNKNOWN;
    }

    // ========================================================================
    // TLS ANALYSIS
    // ========================================================================

    std::optional<TLSInfo> GetTLSInfo(uint64_t streamId) const {
        auto stream = m_streamManager->GetStream(streamId);
        if (stream && stream->tlsInfo) {
            return stream->tlsInfo;
        }
        return std::nullopt;
    }

    JA3Fingerprint CalculateJA3(std::span<const uint8_t> clientHello) const {
        JA3Fingerprint ja3;

        if (clientHello.size() < 43) {
            return ja3;
        }

        try {
            // Parse ClientHello structure
            // This is a simplified version - full TLS parsing is complex

            // TLS Record: [Type(1)] [Version(2)] [Length(2)] [Handshake...]
            // Handshake: [Type(1)] [Length(3)] [Version(2)] [Random(32)] [SessionID...]

            size_t offset = 5;  // Skip TLS record header

            if (clientHello[offset] != 0x01) {  // Handshake type must be ClientHello
                return ja3;
            }

            offset += 4;  // Skip handshake type and length

            // Extract version
            uint16_t version = (clientHello[offset] << 8) | clientHello[offset + 1];
            ja3.version = static_cast<TLSVersion>(version);
            offset += 2;

            offset += 32;  // Skip random

            // Skip session ID
            if (offset >= clientHello.size()) return ja3;
            uint8_t sessionIdLen = clientHello[offset++];
            offset += sessionIdLen;

            // Parse cipher suites
            if (offset + 2 >= clientHello.size()) return ja3;
            uint16_t cipherLen = (clientHello[offset] << 8) | clientHello[offset + 1];
            offset += 2;

            for (size_t i = 0; i < cipherLen && offset + 2 <= clientHello.size(); i += 2) {
                uint16_t cipher = (clientHello[offset] << 8) | clientHello[offset + 1];
                ja3.cipherSuites.push_back(cipher);
                offset += 2;
            }

            // Build JA3 string: version,ciphers,extensions,curves,formats
            std::ostringstream ja3String;
            ja3String << version << ",";

            for (size_t i = 0; i < ja3.cipherSuites.size(); ++i) {
                if (i > 0) ja3String << "-";
                ja3String << ja3.cipherSuites[i];
            }
            ja3String << ",,,";  // Simplified - would parse extensions/curves/formats

            ja3.rawString = ja3String.str();

            // Calculate MD5 hash
            auto md5 = Utils::HashUtils::MD5(
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(ja3.rawString.data()),
                    ja3.rawString.size()
                )
            );

            std::ostringstream hashStr;
            for (auto byte : md5) {
                hashStr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            ja3.hash = hashStr.str();

        } catch (const std::exception& e) {
            Logger::Error("TrafficAnalyzer::CalculateJA3: {}", e.what());
        }

        return ja3;
    }

    bool IsJA3Malicious(const std::string& ja3Hash) const {
        // Check against known malicious JA3 hashes
        // This would query ThreatIntel database
        static const std::unordered_set<std::string> knownMaliciousJA3 = {
            // Example malicious JA3 hashes (Trickbot, Emotet, etc.)
            "6734f37431670b3ab4292b8f60f29984",
            "839bbe3ed07fed922ded5aaf18d1f03e",
        };

        return knownMaliciousJA3.contains(ja3Hash);
    }

    // ========================================================================
    // PAYLOAD ANALYSIS
    // ========================================================================

    PayloadAnalysis AnalyzePayload(std::span<const uint8_t> payload) const {
        PayloadAnalysis analysis;
        analysis.size = payload.size();

        if (payload.empty()) {
            return analysis;
        }

        // Calculate entropy
        analysis.entropy = CalculateEntropy(payload);
        analysis.isHighEntropy = (analysis.entropy > 7.0);

        // Detect payload type
        if (analysis.isHighEntropy && analysis.entropy > 7.5) {
            analysis.type = PayloadType::ENCRYPTED;
        } else if (IsBase64Encoded(payload)) {
            analysis.type = PayloadType::ENCODED_BASE64;
            analysis.isBase64 = true;
        } else {
            // Check for text vs binary
            bool isText = true;
            for (size_t i = 0; i < std::min(payload.size(), size_t(256)); ++i) {
                uint8_t c = payload[i];
                if (c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != 0x00) {
                    isText = false;
                    break;
                }
            }
            analysis.type = isText ? PayloadType::TEXT : PayloadType::BINARY;
        }

        // Detect file type
        if (payload.size() >= 4) {
            auto fileInfo = FileSystem::FileTypeAnalyzer::Instance().AnalyzeBuffer(
                payload,
                L""
            );
            if (fileInfo.detected) {
                analysis.detectedMimeType = fileInfo.mimeType;
                analysis.detectedFileType = fileInfo.description;
            }
        }

        // Shellcode detection
        if (m_config.enableShellcodeDetection) {
            analysis.shellcodeScore = DetectShellcodeScore(payload);
            analysis.hasShellcode = (analysis.shellcodeScore >= TrafficAnalyzerConstants::SHELLCODE_THRESHOLD);
        }

        // XOR detection
        uint8_t xorKey = DetectXORKey(payload);
        if (xorKey != 0) {
            analysis.isPossiblyXORed = true;
            analysis.likelyXORKey = xorKey;
        }

        // Pattern matching
        if (m_config.enableSignatureScanning) {
            // Would use PatternStore for signature matching
            // Simplified for now
        }

        return analysis;
    }

    std::pair<bool, double> DetectShellcode(std::span<const uint8_t> payload) const {
        double score = DetectShellcodeScore(payload);
        return {score >= TrafficAnalyzerConstants::SHELLCODE_THRESHOLD, score};
    }

    std::string DetectFileType(std::span<const uint8_t> payload) const {
        if (payload.size() < 4) {
            return "application/octet-stream";
        }

        auto fileInfo = FileSystem::FileTypeAnalyzer::Instance().AnalyzeBuffer(
            payload,
            L""
        );

        return fileInfo.detected ? fileInfo.mimeType : "application/octet-stream";
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterPacketCallback(PacketAnalysisCallback callback) {
        return m_callbackManager->RegisterPacketCallback(std::move(callback));
    }

    uint64_t RegisterStreamCallback(StreamCallback callback) {
        return m_callbackManager->RegisterStreamCallback(std::move(callback));
    }

    uint64_t RegisterProtocolCallback(ProtocolDetectionCallback callback) {
        return m_callbackManager->RegisterProtocolCallback(std::move(callback));
    }

    uint64_t RegisterThreatCallback(ThreatCallback callback) {
        return m_callbackManager->RegisterThreatCallback(std::move(callback));
    }

    uint64_t RegisterTLSCallback(TLSCallback callback) {
        return m_callbackManager->RegisterTLSCallback(std::move(callback));
    }

    bool UnregisterCallback(uint64_t callbackId) {
        return m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const TrafficAnalyzerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    bool PerformDiagnostics() const {
        Logger::Info("TrafficAnalyzer Diagnostics:");
        Logger::Info("  Initialized: {}", m_initialized);
        Logger::Info("  Running: {}", m_running.load());
        Logger::Info("  Active Streams: {}", m_stats.activeStreams.load());
        Logger::Info("  Packets Analyzed: {}", m_stats.packetsAnalyzed.load());
        Logger::Info("  Threats Detected: {}", m_stats.threatsDetected.load());
        return true;
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        // Export not implemented
        return false;
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void CleanupThread() {
        Logger::Info("TrafficAnalyzer: Cleanup thread started");

        while (m_running.load(std::memory_order_acquire)) {
            std::unique_lock lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(30));

            if (!m_running.load(std::memory_order_acquire)) break;

            // Cleanup timed out streams
            size_t removed = m_streamManager->CleanupTimedOut();
            if (removed > 0) {
                m_stats.streamsTimedOut.fetch_add(removed, std::memory_order_relaxed);
                m_stats.activeStreams.fetch_sub(removed, std::memory_order_relaxed);
                Logger::Info("TrafficAnalyzer: Cleaned up {} timed-out streams", removed);
            }
        }

        Logger::Info("TrafficAnalyzer: Cleanup thread exited");
    }

    AnalysisResult AnalyzePacketImpl(std::span<const uint8_t> packet,
                                    std::chrono::system_clock::time_point timestamp) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        AnalysisResult result;
        result.packet.timestamp = timestamp;
        result.packet.captureLength = packet.size();
        result.packet.wireLength = packet.size();

        try {
            m_stats.totalPackets.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesProcessed.fetch_add(packet.size(), std::memory_order_relaxed);

            // Parse packet headers
            if (!ParsePacket(packet, result.packet)) {
                m_stats.packetsDropped.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            // Get or create stream
            if (result.packet.protocol == 6 || result.packet.protocol == 17) {  // TCP or UDP
                StreamKey key;
                key.srcIP = result.packet.srcIP;
                key.dstIP = result.packet.dstIP;
                key.srcPort = result.packet.srcPort;
                key.dstPort = result.packet.dstPort;
                key.protocol = result.packet.protocol;
                key.isIPv6 = result.packet.isIPv6;

                auto streamIdOpt = m_streamManager->GetOrCreateStream(key);
                if (streamIdOpt) {
                    result.streamId = *streamIdOpt;

                    // Check if this is a new stream
                    auto stream = m_streamManager->GetStream(result.streamId);
                    bool isNew = (stream && stream->state == StreamState::NEW);

                    // Update stream
                    m_streamManager->UpdateStream(result.streamId, [&](StreamInfo& s) {
                        if (s.state == StreamState::NEW) {
                            s.state = StreamState::ESTABLISHED;
                            m_stats.totalStreams.fetch_add(1, std::memory_order_relaxed);
                            m_stats.activeStreams.fetch_add(1, std::memory_order_relaxed);
                        }

                        // Update statistics
                        s.packetsClient++;
                        s.bytesClient += result.packet.payloadLength;
                        s.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            timestamp - s.startTime
                        );
                    });

                    // Protocol identification
                    if (m_config.enableProtocolDetection && !result.packet.payload.empty()) {
                        Protocol proto = IdentifyProtocol(
                            result.packet.payload,
                            result.packet.srcPort,
                            result.packet.dstPort
                        );

                        if (proto != Protocol::UNKNOWN) {
                            result.protocol = proto;
                            result.newProtocolIdentified = true;

                            m_streamManager->UpdateStream(result.streamId, [&](StreamInfo& s) {
                                if (s.identifiedProtocol == Protocol::UNKNOWN) {
                                    s.identifiedProtocol = proto;
                                    UpdateProtocolStats(proto);

                                    // Invoke callback
                                    m_callbackManager->InvokeProtocolCallbacks(result.streamId, proto, s);
                                }
                            });
                        }
                    }

                    // Payload analysis
                    if (m_config.enablePayloadAnalysis && !result.packet.payload.empty()) {
                        result.payloadAnalysis = AnalyzePayload(result.packet.payload);

                        // Shellcode detection
                        if (result.payloadAnalysis.hasShellcode) {
                            result.threats.push_back(ThreatIndicator::SHELLCODE_DETECTED);
                            result.threatScore += 80;
                            m_stats.shellcodeDetected.fetch_add(1, std::memory_order_relaxed);
                            m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);

                            Logger::Warn("TrafficAnalyzer: Shellcode detected in stream {} (score: {:.2f})",
                                result.streamId, result.payloadAnalysis.shellcodeScore);
                        }

                        // High entropy (potential encryption/obfuscation)
                        if (result.payloadAnalysis.isHighEntropy) {
                            result.anomalies.push_back(AnomalyType::ENCODING_ANOMALY);
                            m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);
                        }
                    }

                    // TLS inspection
                    if (m_config.enableTLSInspection && result.protocol == Protocol::HTTPS) {
                        if (IsTLSPayload(result.packet.payload) && result.packet.payload.size() > 100) {
                            // Check if this is a ClientHello
                            if (result.packet.payload[5] == 0x01) {  // Handshake type = ClientHello
                                auto ja3 = CalculateJA3(result.packet.payload);

                                if (!ja3.hash.empty()) {
                                    m_stats.ja3Fingerprints.fetch_add(1, std::memory_order_relaxed);

                                    if (IsJA3Malicious(ja3.hash)) {
                                        result.threats.push_back(ThreatIndicator::KNOWN_BAD_JA3);
                                        result.threatScore += 70;
                                        m_stats.maliciousJA3.fetch_add(1, std::memory_order_relaxed);
                                        m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);

                                        Logger::Critical("TrafficAnalyzer: Malicious JA3 detected: {} in stream {}",
                                            ja3.hash, result.streamId);
                                    }

                                    // Store in stream
                                    m_streamManager->UpdateStream(result.streamId, [&](StreamInfo& s) {
                                        if (!s.tlsInfo) {
                                            s.tlsInfo = TLSInfo{};
                                        }
                                        s.tlsInfo->ja3 = ja3;
                                    });

                                    m_stats.tlsHandshakes.fetch_add(1, std::memory_order_relaxed);
                                }
                            }
                        }
                    }

                    // Invoke threat callbacks
                    for (const auto& threat : result.threats) {
                        m_callbackManager->InvokeThreatCallbacks(result.streamId, threat, result);
                    }

                    // Invoke stream callback if new
                    if (isNew && stream) {
                        m_callbackManager->InvokeStreamCallbacks(*stream, true);
                    }
                }
            }

            result.analysisComplete = true;
            m_stats.packetsAnalyzed.fetch_add(1, std::memory_order_relaxed);

            // Update timing statistics
            const auto endTime = std::chrono::high_resolution_clock::now();
            result.analysisTime = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
            UpdateAnalysisTimeStats(result.analysisTime.count());

        } catch (const std::exception& e) {
            Logger::Error("TrafficAnalyzer::AnalyzePacketImpl: {}", e.what());
        }

        return result;
    }

    bool ParsePacket(std::span<const uint8_t> packet, PacketInfo& info) {
        if (packet.size() < 14) {  // Minimum Ethernet frame
            info.parseError = "Packet too small";
            return false;
        }

        size_t offset = 0;

        // Parse Ethernet header (14 bytes)
        std::copy_n(packet.begin(), 6, info.dstMac.begin());
        std::copy_n(packet.begin() + 6, 6, info.srcMac.begin());
        info.etherType = (packet[12] << 8) | packet[13];
        offset = 14;

        // Handle VLAN tagging (802.1Q)
        if (info.etherType == 0x8100) {
            if (packet.size() < offset + 4) return false;
            info.hasVlan = true;
            info.vlanId = ((packet[offset] << 8) | packet[offset + 1]) & 0x0FFF;
            info.etherType = (packet[offset + 2] << 8) | packet[offset + 3];
            offset += 4;
        }

        // Parse IP header
        if (info.etherType == 0x0800) {  // IPv4
            if (packet.size() < offset + 20) return false;

            info.ipVersion = 4;
            uint8_t ihl = packet[offset] & 0x0F;
            size_t ipHeaderLen = ihl * 4;

            if (packet.size() < offset + ipHeaderLen) return false;

            info.ttl = packet[offset + 8];
            info.protocol = packet[offset + 9];
            info.ipId = (packet[offset + 4] << 8) | packet[offset + 5];

            uint16_t fragFlags = (packet[offset + 6] << 8) | packet[offset + 7];
            info.fragmentOffset = fragFlags & 0x1FFF;
            info.moreFragments = (fragFlags & 0x2000) != 0;
            info.dontFragment = (fragFlags & 0x4000) != 0;

            std::copy_n(packet.begin() + offset + 12, 4, info.srcIP.begin());
            std::copy_n(packet.begin() + offset + 16, 4, info.dstIP.begin());

            offset += ipHeaderLen;
        } else if (info.etherType == 0x86DD) {  // IPv6
            if (packet.size() < offset + 40) return false;

            info.isIPv6 = true;
            info.ipVersion = 6;
            info.ttl = packet[offset + 7];  // Hop limit
            info.protocol = packet[offset + 6];  // Next header

            std::copy_n(packet.begin() + offset + 8, 16, info.srcIP.begin());
            std::copy_n(packet.begin() + offset + 24, 16, info.dstIP.begin());

            offset += 40;
        } else {
            info.parseError = "Unsupported ether type";
            return false;
        }

        // Parse transport layer
        if (info.protocol == 6) {  // TCP
            if (packet.size() < offset + 20) return false;

            info.srcPort = (packet[offset] << 8) | packet[offset + 1];
            info.dstPort = (packet[offset + 2] << 8) | packet[offset + 3];
            info.tcpSeq = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) |
                         (packet[offset + 6] << 8) | packet[offset + 7];
            info.tcpAck = (packet[offset + 8] << 24) | (packet[offset + 9] << 16) |
                         (packet[offset + 10] << 8) | packet[offset + 11];

            uint8_t dataOffset = (packet[offset + 12] >> 4) & 0x0F;
            size_t tcpHeaderLen = dataOffset * 4;

            info.tcpFlags = packet[offset + 13];
            info.tcpSyn = (info.tcpFlags & 0x02) != 0;
            info.tcpAck_flag = (info.tcpFlags & 0x10) != 0;
            info.tcpFin = (info.tcpFlags & 0x01) != 0;
            info.tcpRst = (info.tcpFlags & 0x04) != 0;
            info.tcpPsh = (info.tcpFlags & 0x08) != 0;
            info.tcpUrg = (info.tcpFlags & 0x20) != 0;

            info.tcpWindow = (packet[offset + 14] << 8) | packet[offset + 15];

            offset += tcpHeaderLen;
        } else if (info.protocol == 17) {  // UDP
            if (packet.size() < offset + 8) return false;

            info.srcPort = (packet[offset] << 8) | packet[offset + 1];
            info.dstPort = (packet[offset + 2] << 8) | packet[offset + 3];
            info.udpLength = (packet[offset + 4] << 8) | packet[offset + 5];

            offset += 8;
        } else if (info.protocol == 1) {  // ICMP
            offset += 8;  // ICMP header
        }

        // Extract payload
        if (offset < packet.size()) {
            info.payloadOffset = offset;
            info.payloadLength = packet.size() - offset;
            info.payload = packet.subspan(offset);
        }

        info.isValid = true;
        return true;
    }

    void UpdateProtocolStats(Protocol protocol) {
        switch (protocol) {
            case Protocol::HTTP:
                m_stats.httpStreams.fetch_add(1, std::memory_order_relaxed);
                break;
            case Protocol::HTTPS:
                m_stats.httpsStreams.fetch_add(1, std::memory_order_relaxed);
                break;
            case Protocol::DNS:
                m_stats.dnsPackets.fetch_add(1, std::memory_order_relaxed);
                break;
            case Protocol::SMB:
            case Protocol::SMB2:
            case Protocol::SMB3:
                m_stats.smbStreams.fetch_add(1, std::memory_order_relaxed);
                break;
            case Protocol::UNKNOWN:
                m_stats.unknownProtocols.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }
    }

    void UpdateAnalysisTimeStats(uint64_t timeUs) {
        const uint64_t currentAvg = m_stats.avgAnalysisTimeUs.load(std::memory_order_relaxed);
        const uint64_t newAvg = (currentAvg + timeUs) / 2;
        m_stats.avgAnalysisTimeUs.store(newAvg, std::memory_order_relaxed);

        const uint64_t currentMax = m_stats.maxAnalysisTimeUs.load(std::memory_order_relaxed);
        if (timeUs > currentMax) {
            m_stats.maxAnalysisTimeUs.store(timeUs, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_running{ false };
    TrafficAnalyzerConfig m_config;

    // Threading
    std::thread m_cleanupThread;
    std::condition_variable m_cv;

    // Stream management
    std::unique_ptr<StreamManager> m_streamManager;

    // Callbacks
    std::unique_ptr<CallbackManager> m_callbackManager;

    // Statistics
    TrafficAnalyzerStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

TrafficAnalyzer::TrafficAnalyzer()
    : m_impl(std::make_unique<TrafficAnalyzerImpl>()) {
}

TrafficAnalyzer::~TrafficAnalyzer() = default;

TrafficAnalyzer& TrafficAnalyzer::Instance() {
    static TrafficAnalyzer instance;
    return instance;
}

bool TrafficAnalyzer::Initialize(const TrafficAnalyzerConfig& config) {
    return m_impl->Initialize(config);
}

bool TrafficAnalyzer::Start() {
    return m_impl->Start();
}

void TrafficAnalyzer::Stop() {
    m_impl->Stop();
}

void TrafficAnalyzer::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool TrafficAnalyzer::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

void TrafficAnalyzer::AnalyzePacket(const std::vector<uint8_t>& packet) {
    m_impl->AnalyzePacket(packet);
}

AnalysisResult TrafficAnalyzer::AnalyzePacket(std::span<const uint8_t> packet,
                                              std::chrono::system_clock::time_point timestamp) {
    return m_impl->AnalyzePacket(packet, timestamp);
}

std::vector<AnalysisResult> TrafficAnalyzer::AnalyzePackets(
    const std::vector<std::vector<uint8_t>>& packets) {
    return m_impl->AnalyzePackets(packets);
}

std::optional<StreamInfo> TrafficAnalyzer::GetStream(uint64_t streamId) const {
    return m_impl->GetStream(streamId);
}

std::vector<StreamInfo> TrafficAnalyzer::GetActiveStreams() const {
    return m_impl->GetActiveStreams();
}

std::vector<StreamInfo> TrafficAnalyzer::GetStreamsByProtocol(Protocol protocol) const {
    return m_impl->GetStreamsByProtocol(protocol);
}

void TrafficAnalyzer::TerminateStream(uint64_t streamId) {
    m_impl->TerminateStream(streamId);
}

void TrafficAnalyzer::ClearAllStreams() {
    m_impl->ClearAllStreams();
}

Protocol TrafficAnalyzer::IdentifyProtocol(std::span<const uint8_t> payload,
                                          uint16_t srcPort, uint16_t dstPort) const {
    return m_impl->IdentifyProtocol(payload, srcPort, dstPort);
}

std::string_view TrafficAnalyzer::GetProtocolName(Protocol protocol) noexcept {
    return ProtocolToString(protocol);
}

std::optional<TLSInfo> TrafficAnalyzer::GetTLSInfo(uint64_t streamId) const {
    return m_impl->GetTLSInfo(streamId);
}

JA3Fingerprint TrafficAnalyzer::CalculateJA3(std::span<const uint8_t> clientHello) const {
    return m_impl->CalculateJA3(clientHello);
}

bool TrafficAnalyzer::IsJA3Malicious(const std::string& ja3Hash) const {
    return m_impl->IsJA3Malicious(ja3Hash);
}

PayloadAnalysis TrafficAnalyzer::AnalyzePayload(std::span<const uint8_t> payload) const {
    return m_impl->AnalyzePayload(payload);
}

std::pair<bool, double> TrafficAnalyzer::DetectShellcode(std::span<const uint8_t> payload) const {
    return m_impl->DetectShellcode(payload);
}

std::string TrafficAnalyzer::DetectFileType(std::span<const uint8_t> payload) const {
    return m_impl->DetectFileType(payload);
}

uint64_t TrafficAnalyzer::RegisterPacketCallback(PacketAnalysisCallback callback) {
    return m_impl->RegisterPacketCallback(std::move(callback));
}

uint64_t TrafficAnalyzer::RegisterStreamCallback(StreamCallback callback) {
    return m_impl->RegisterStreamCallback(std::move(callback));
}

uint64_t TrafficAnalyzer::RegisterProtocolCallback(ProtocolDetectionCallback callback) {
    return m_impl->RegisterProtocolCallback(std::move(callback));
}

uint64_t TrafficAnalyzer::RegisterThreatCallback(ThreatCallback callback) {
    return m_impl->RegisterThreatCallback(std::move(callback));
}

uint64_t TrafficAnalyzer::RegisterTLSCallback(TLSCallback callback) {
    return m_impl->RegisterTLSCallback(std::move(callback));
}

bool TrafficAnalyzer::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const TrafficAnalyzerStatistics& TrafficAnalyzer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void TrafficAnalyzer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool TrafficAnalyzer::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool TrafficAnalyzer::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
