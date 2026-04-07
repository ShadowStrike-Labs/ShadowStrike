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
#include "../../Utils/HashUtils.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../FileSystem/FileTypeAnalyzer.hpp"

// Network sub-module headers for dispatch wiring
#include "DNSMonitor.hpp"
#include "URLAnalyzer.hpp"
#include "TorDetector.hpp"
#include "VPNDetector.hpp"
#include "P2PMonitor.hpp"
#include "BotnetDetector.hpp"

// Standard library
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <fstream>

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
 * @brief Checks if payload looks like SMTP.
 */
bool IsSMTPPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return false;

    const char* data = reinterpret_cast<const char*>(payload.data());
    std::string_view sv(data, std::min(payload.size(), size_t(16)));

    return sv.starts_with("220 ") || sv.starts_with("EHLO ") ||
           sv.starts_with("HELO ") || sv.starts_with("MAIL FROM:") ||
           sv.starts_with("RCPT TO:");
}

/**
 * @brief Checks if payload looks like FTP.
 */
bool IsFTPPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return false;

    const char* data = reinterpret_cast<const char*>(payload.data());
    std::string_view sv(data, std::min(payload.size(), size_t(16)));

    return sv.starts_with("220 ") || sv.starts_with("USER ") ||
           sv.starts_with("PASS ") || sv.starts_with("LIST") ||
           sv.starts_with("RETR ") || sv.starts_with("STOR ");
}

/**
 * @brief Checks if payload looks like RDP (TPKT + X.224 COTP).
 */
bool IsRDPPayload(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return false;
    // TPKT header: version=3, reserved=0, length(2)
    return payload[0] == 0x03 && payload[1] == 0x00;
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
 * @brief Known shellcode patterns — static constexpr to avoid heap at startup.
 */
struct ShellcodePattern {
    const uint8_t* data;
    size_t length;
};

constexpr uint8_t kNopSled[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
constexpr uint8_t kJmpShort[] = {0xEB, 0x1E};
constexpr uint8_t kCallSelf[] = {0xE8, 0x00, 0x00, 0x00, 0x00};
constexpr uint8_t kCallAddr[] = {0xFF, 0x15};
constexpr uint8_t kCallEbp[] = {0xFF, 0x55};
constexpr uint8_t kGetPC[] = {0xE8, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr uint8_t kXorEax[] = {0x31, 0xC0};
constexpr uint8_t kXorEcx[] = {0x31, 0xC9};
// Note: single-byte patterns like 0x68 (push imm32) removed — too high FP rate.

constexpr ShellcodePattern g_shellcodePatterns[] = {
    {kNopSled,  sizeof(kNopSled)},
    {kJmpShort, sizeof(kJmpShort)},
    {kCallSelf, sizeof(kCallSelf)},
    {kCallAddr, sizeof(kCallAddr)},
    {kCallEbp,  sizeof(kCallEbp)},
    {kGetPC,    sizeof(kGetPC)},
    {kXorEax,   sizeof(kXorEax)},
    {kXorEcx,   sizeof(kXorEcx)},
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
        for (size_t i = 0; i + pattern.length <= payload.size(); ++i) {
            if (std::equal(pattern.data, pattern.data + pattern.length, payload.begin() + i)) {
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
    // Use FNV-1a for collision resistance — the naive XOR-shift hash was
    // trivially collision-craftable for hash-table DoS.
    const size_t ipLen = key.isIPv6 ? 16 : 4;

    // Pack the fixed-size fields into a contiguous buffer
    // Layout: [srcIP(4|16)] [dstIP(4|16)] [srcPort(2)] [dstPort(2)] [protocol(1)]
    uint8_t buf[16 + 16 + 2 + 2 + 1];  // max 37 bytes
    size_t off = 0;

    std::memcpy(buf + off, key.srcIP.data(), ipLen);
    off += ipLen;
    std::memcpy(buf + off, key.dstIP.data(), ipLen);
    off += ipLen;
    std::memcpy(buf + off, &key.srcPort, 2);
    off += 2;
    std::memcpy(buf + off, &key.dstPort, 2);
    off += 2;
    buf[off++] = key.protocol;

    return static_cast<size_t>(
        Utils::HashUtils::Fnv1a64(buf, off));
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
                SS_LOG_ERROR(L"Network", L"PacketCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeStreamCallbacks(const StreamInfo& stream, bool isNew) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_streamCallbacks) {
            try {
                callback(stream, isNew);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"StreamCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeProtocolCallbacks(uint64_t streamId, Protocol protocol, const StreamInfo& stream) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_protocolCallbacks) {
            try {
                callback(streamId, protocol, stream);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"ProtocolCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeThreatCallbacks(uint64_t streamId, TrafficThreatIndicator threat, const AnalysisResult& result) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_threatCallbacks) {
            try {
                callback(streamId, threat, result);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"ThreatCallback exception: %hs", e.what());
            }
        }
    }

    void InvokeTLSCallbacks(uint64_t streamId, const TrafficAnalyzerTLSInfo& tlsInfo) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_tlsCallbacks) {
            try {
                callback(streamId, tlsInfo);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"TLSCallback exception: %hs", e.what());
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

    /**
     * @brief Finds an existing stream by key (does NOT create).
     */
    std::optional<uint64_t> FindStream(const StreamKey& key) const {
        std::shared_lock lock(m_mutex);
        auto it = m_streamMap.find(key);
        if (it != m_streamMap.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * @brief Creates a new stream for the given key.
     *        Returns nullopt if max streams reached or key already exists.
     */
    std::optional<uint64_t> CreateStream(const StreamKey& key) {
        std::unique_lock lock(m_mutex);

        // Double-check: another thread may have created it
        auto it = m_streamMap.find(key);
        if (it != m_streamMap.end()) {
            return it->second;
        }

        // Check limit
        if (m_streams.size() >= m_maxStreams) {
            SS_LOG_WARN(L"Network", L"StreamManager: Max streams reached (%zu)", m_maxStreams);
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
            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Initializing...");

            m_config = config;

            // Initialize callback manager
            m_callbackManager = std::make_unique<CallbackManager>();

            // Initialize stream manager
            m_streamManager = std::make_unique<StreamManager>(
                m_config.maxActiveStreams,
                m_config.streamTimeoutMs
            );

            // Note: ThreatIntelLookup and SignatureStore are wired via
            // SetThreatIntelLookup / SetSignatureStore by the orchestrator
            // after all subsystems are initialized.

            m_initialized = true;
            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: Initialization failed: %hs", e.what());
            return false;
        }
    }

    /**
     * @brief Wire the ThreatIntel subsystem for JA3 reputation checks.
     *        Caller must guarantee the pointer outlives TrafficAnalyzer.
     */
    void SetThreatIntelLookup(ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
        std::unique_lock lock(m_mutex);
        m_threatIntelLookup = lookup;
        if (lookup) {
            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: ThreatIntel subsystem wired");
        }
    }

    /**
     * @brief Wire the SignatureStore for payload signature scanning.
     *        Caller must guarantee the pointer outlives TrafficAnalyzer.
     */
    void SetSignatureStore(ShadowStrike::SignatureStore::SignatureStore* store) noexcept {
        std::unique_lock lock(m_mutex);
        m_signatureStore = store;
        if (store) {
            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: SignatureStore subsystem wired");
        }
    }

    bool Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: Not initialized");
            return false;
        }

        if (m_running) {
            SS_LOG_WARN(L"Network", L"TrafficAnalyzer: Already running");
            return true;
        }

        try {
            m_running = true;

            // Start cleanup thread
            m_cleanupThread = std::thread([this]() { CleanupThread(); });

            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Started");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: Start failed: %hs", e.what());
            m_running = false;
            return false;
        }
    }

    void Stop() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return;

            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Stopping...");
            m_running = false;
        }

        m_cv.notify_all();

        if (m_cleanupThread.joinable()) {
            m_cleanupThread.join();
        }

        SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Stopped");
    }

    void Shutdown() noexcept {
        Stop();
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        if (m_streamManager) {
            m_streamManager->ClearAll();
        }
        SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Shutdown complete");
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

        // Reject packets exceeding IP maximum
        if (packet.size() > TrafficAnalyzerConstants::MAX_PACKET_SIZE) {
            m_stats.packetsDropped.fetch_add(1, std::memory_order_relaxed);
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

        if (packet.size() > TrafficAnalyzerConstants::MAX_PACKET_SIZE) {
            m_stats.packetsDropped.fetch_add(1, std::memory_order_relaxed);
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
        auto stream = m_streamManager->GetStream(streamId);
        if (stream) {
            m_streamManager->RemoveStream(streamId);
            // Safely decrement: load-CAS loop to prevent unsigned underflow
            uint32_t current = m_stats.activeStreams.load(std::memory_order_relaxed);
            while (current > 0) {
                if (m_stats.activeStreams.compare_exchange_weak(
                        current, current - 1, std::memory_order_relaxed)) {
                    break;
                }
            }
        }
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

        // Port-based identification first (with content validation)
        if (srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080) {
            if (IsHTTPPayload(payload)) return Protocol::HTTP;
        }
        if (srcPort == 443 || dstPort == 443 || srcPort == 8443 || dstPort == 8443) {
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
            if (IsRDPPayload(payload)) return Protocol::RDP;
        }
        if (srcPort == 25 || dstPort == 25 || srcPort == 587 || dstPort == 587) {
            if (IsSMTPPayload(payload)) return Protocol::SMTP;
        }
        if (srcPort == 21 || dstPort == 21) {
            if (IsFTPPayload(payload)) return Protocol::FTP;
        }
        if (srcPort == 993 || dstPort == 993) {
            if (IsTLSPayload(payload)) return Protocol::IMAPS;
        }
        if (srcPort == 995 || dstPort == 995) {
            if (IsTLSPayload(payload)) return Protocol::POP3S;
        }
        if (srcPort == 389 || dstPort == 389) return Protocol::LDAP;
        if (srcPort == 636 || dstPort == 636) {
            if (IsTLSPayload(payload)) return Protocol::LDAPS;
        }
        if (srcPort == 88 || dstPort == 88) return Protocol::KERBEROS;
        if (srcPort == 1433 || dstPort == 1433) return Protocol::MSSQL;
        if (srcPort == 3306 || dstPort == 3306) return Protocol::MYSQL;
        if (srcPort == 5432 || dstPort == 5432) return Protocol::POSTGRESQL;
        if (srcPort == 6379 || dstPort == 6379) return Protocol::REDIS;
        if (srcPort == 27017 || dstPort == 27017) return Protocol::MONGODB;

        // Content-based identification (port-independent — catches protocol on unexpected ports)
        if (IsHTTPPayload(payload)) return Protocol::HTTP;
        if (IsTLSPayload(payload)) return Protocol::TLS_UNKNOWN;
        if (IsDNSPayload(payload)) return Protocol::DNS;
        if (IsSSHPayload(payload)) return Protocol::SSH;
        if (IsSMBPayload(payload)) return Protocol::SMB;
        if (IsSMTPPayload(payload)) return Protocol::SMTP;
        if (IsRDPPayload(payload)) return Protocol::RDP;

        return Protocol::UNKNOWN;
    }

    // ========================================================================
    // TLS ANALYSIS
    // ========================================================================

    std::optional<TrafficAnalyzerTLSInfo> GetTLSInfo(uint64_t streamId) const {
        auto stream = m_streamManager->GetStream(streamId);
        if (stream && stream->tlsInfo) {
            return stream->tlsInfo;
        }
        return std::nullopt;
    }

    TrafficAnalyzerJA3Fingerprint CalculateJA3(std::span<const uint8_t> clientHello) const {
        TrafficAnalyzerJA3Fingerprint ja3;

        if (clientHello.size() < 43) {
            return ja3;
        }

        try {
            // TLS Record: [Type(1)] [Version(2)] [Length(2)] [Handshake...]
            // Handshake: [Type(1)] [Length(3)] [Version(2)] [Random(32)] [SessionID...]

            size_t offset = 5;  // Skip TLS record header

            if (offset >= clientHello.size() || clientHello[offset] != 0x01) {
                return ja3;
            }

            offset += 4;  // Skip handshake type and length

            if (offset + 2 > clientHello.size()) return ja3;
            uint16_t version = (static_cast<uint16_t>(clientHello[offset]) << 8) | clientHello[offset + 1];
            ja3.version = static_cast<TrafficAnalyzerTLSVersion>(version);
            offset += 2;

            offset += 32;  // Skip random

            // Skip session ID
            if (offset >= clientHello.size()) return ja3;
            uint8_t sessionIdLen = clientHello[offset++];
            if (offset + sessionIdLen > clientHello.size()) return ja3;
            offset += sessionIdLen;

            // Parse cipher suites
            if (offset + 2 > clientHello.size()) return ja3;
            uint16_t cipherLen = (static_cast<uint16_t>(clientHello[offset]) << 8) | clientHello[offset + 1];
            offset += 2;

            if (offset + cipherLen > clientHello.size()) return ja3;
            for (size_t i = 0; i < cipherLen && offset + 2 <= clientHello.size(); i += 2) {
                uint16_t cipher = (static_cast<uint16_t>(clientHello[offset]) << 8) | clientHello[offset + 1];
                // Skip GREASE values (0x?a?a pattern)
                if ((cipher & 0x0f0f) != 0x0a0a) {
                    ja3.cipherSuites.push_back(cipher);
                }
                offset += 2;
            }

            // Skip compression methods
            if (offset >= clientHello.size()) return ja3;
            uint8_t compLen = clientHello[offset++];
            if (offset + compLen > clientHello.size()) return ja3;
            offset += compLen;

            // Parse extensions
            if (offset + 2 > clientHello.size()) {
                // No extensions — build partial JA3
            } else {
                uint16_t extTotalLen = (static_cast<uint16_t>(clientHello[offset]) << 8) | clientHello[offset + 1];
                offset += 2;

                const size_t extEnd = std::min(offset + static_cast<size_t>(extTotalLen), clientHello.size());

                while (offset + 4 <= extEnd) {
                    uint16_t extType = (static_cast<uint16_t>(clientHello[offset]) << 8) | clientHello[offset + 1];
                    uint16_t extLen  = (static_cast<uint16_t>(clientHello[offset + 2]) << 8) | clientHello[offset + 3];
                    offset += 4;

                    if (offset + extLen > extEnd) break;

                    // Skip GREASE extension types
                    if ((extType & 0x0f0f) != 0x0a0a) {
                        ja3.extensions.push_back(extType);
                    }

                    // Supported Groups (elliptic_curves) — extension type 0x000A
                    if (extType == 0x000A && extLen >= 2) {
                        uint16_t groupListLen = (static_cast<uint16_t>(clientHello[offset]) << 8) | clientHello[offset + 1];
                        size_t gOff = offset + 2;
                        for (size_t g = 0; g < groupListLen && gOff + 2 <= offset + extLen; g += 2) {
                            uint16_t group = (static_cast<uint16_t>(clientHello[gOff]) << 8) | clientHello[gOff + 1];
                            if ((group & 0x0f0f) != 0x0a0a) {
                                ja3.ellipticCurves.push_back(group);
                            }
                            gOff += 2;
                        }
                    }

                    // EC Point Formats — extension type 0x000B
                    if (extType == 0x000B && extLen >= 1) {
                        uint8_t fmtCount = clientHello[offset];
                        for (size_t f = 0; f < fmtCount && (offset + 1 + f) < offset + extLen; ++f) {
                            ja3.ecPointFormats.push_back(clientHello[offset + 1 + f]);
                        }
                    }

                    offset += extLen;
                }
            }

            // Build JA3 string: version,ciphers,extensions,curves,formats
            std::ostringstream ja3String;
            ja3String << version << ",";

            for (size_t i = 0; i < ja3.cipherSuites.size(); ++i) {
                if (i > 0) ja3String << "-";
                ja3String << ja3.cipherSuites[i];
            }
            ja3String << ",";

            for (size_t i = 0; i < ja3.extensions.size(); ++i) {
                if (i > 0) ja3String << "-";
                ja3String << ja3.extensions[i];
            }
            ja3String << ",";

            for (size_t i = 0; i < ja3.ellipticCurves.size(); ++i) {
                if (i > 0) ja3String << "-";
                ja3String << ja3.ellipticCurves[i];
            }
            ja3String << ",";

            for (size_t i = 0; i < ja3.ecPointFormats.size(); ++i) {
                if (i > 0) ja3String << "-";
                ja3String << static_cast<uint16_t>(ja3.ecPointFormats[i]);
            }

            ja3.rawString = ja3String.str();

            // Calculate MD5 hash using Hasher API
            Utils::HashUtils::Hasher md5Hasher(Utils::HashUtils::Algorithm::MD5);
            if (md5Hasher.Init()) {
                if (md5Hasher.Update(ja3.rawString.data(), ja3.rawString.size())) {
                    std::string hexOut;
                    if (md5Hasher.FinalHex(hexOut, false)) {
                        ja3.hash = std::move(hexOut);
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer::CalculateJA3: %hs", e.what());
        }

        return ja3;
    }

    bool IsJA3Malicious(const std::string& ja3Hash) const {
        // Check against known malicious JA3 hashes from ThreatIntel DB
        static const std::unordered_set<std::string> knownMaliciousJA3 = {
            // Trickbot family
            "6734f37431670b3ab4292b8f60f29984",
            // Emotet family
            "839bbe3ed07fed922ded5aaf18d1f03e",
            // Cobalt Strike default
            "72a589da586844d7f0818ce684948eea",
            // Metasploit Meterpreter default
            "5d65ea3ab1d764ee114c1af3f9043a9d",
            // Dridex
            "51c64c77e60f3980eea90869b68c58a8",
            // IcedID
            "3b5074b1b5d032e5620f69f9f700ff0e",
            // QakBot
            "c12f54a3f91dc7bafd92b1aabc53d8ff",
            // BazarLoader
            "e35df3e1e753e3de8492dbbe25badb37",
        };

        if (knownMaliciousJA3.contains(ja3Hash)) {
            return true;
        }

        // Also check via ThreatIntel hash lookup if available
        try {
            auto& threatIntel = m_threatIntelLookup;
            if (threatIntel && threatIntel->IsInitialized()) {
                auto result = threatIntel->LookupHash(ja3Hash);
                if (result.IsMalicious()) {
                    return true;
                }
            }
        } catch (...) {
            // Fail-open for ThreatIntel lookup errors — static list still applies
        }

        return false;
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

        // Pattern/signature matching via SignatureStore
        if (m_config.enableSignatureScanning) {
            try {
                auto& sigStore = m_signatureStore;
                if (sigStore && sigStore->IsInitialized()) {
                    const size_t scanLen = std::min(payload.size(), m_config.maxPayloadScan);
                    ShadowStrike::SignatureStore::ScanOptions opts;
                    opts.enablePatternScan = true;
                    opts.enableYaraScan = false;
                    opts.enableHashLookup = false;
                    opts.stopOnFirstMatch = false;

                    auto scanResult = sigStore->ScanBuffer(payload.subspan(0, scanLen), opts);

                    for (const auto& det : scanResult.patternMatches) {
                        analysis.matchedSignatures.push_back(det.signatureName);
                    }

                    if (!scanResult.patternMatches.empty()) {
                        m_stats.signaturesMatched.fetch_add(
                            scanResult.patternMatches.size(), std::memory_order_relaxed);
                    }
                }
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: Signature scan failed: %hs", e.what());
            }
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
        SS_LOG_INFO(L"Network", L"TrafficAnalyzer Diagnostics:");
        SS_LOG_INFO(L"Network", L"  Initialized: %d", m_initialized ? 1 : 0);
        SS_LOG_INFO(L"Network", L"  Running: %d", m_running.load() ? 1 : 0);
        SS_LOG_INFO(L"Network", L"  Active Streams: %u", m_stats.activeStreams.load());
        SS_LOG_INFO(L"Network", L"  Packets Analyzed: %llu", m_stats.packetsAnalyzed.load());
        SS_LOG_INFO(L"Network", L"  Threats Detected: %llu", m_stats.threatsDetected.load());
        SS_LOG_INFO(L"Network", L"  Anomalies Detected: %llu", m_stats.anomaliesDetected.load());
        SS_LOG_INFO(L"Network", L"  JA3 Fingerprints: %llu", m_stats.ja3Fingerprints.load());
        SS_LOG_INFO(L"Network", L"  Malicious JA3: %llu", m_stats.maliciousJA3.load());
        SS_LOG_INFO(L"Network", L"  Avg Analysis Time: %llu us", m_stats.avgAnalysisTimeUs.load());
        SS_LOG_INFO(L"Network", L"  Max Analysis Time: %llu us", m_stats.maxAnalysisTimeUs.load());
        return true;
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        if (outputPath.empty()) {
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: ExportDiagnostics called with empty path");
            return false;
        }

        try {
            std::wofstream file(outputPath, std::ios::out | std::ios::trunc);
            if (!file.is_open()) {
                SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: Failed to open diagnostics file: %ls", outputPath.c_str());
                return false;
            }

            file << L"=== ShadowStrike TrafficAnalyzer Diagnostics ===\n";
            file << L"Initialized: " << (m_initialized ? L"Yes" : L"No") << L"\n";
            file << L"Running: " << (m_running.load() ? L"Yes" : L"No") << L"\n";
            file << L"\n--- Packet Statistics ---\n";
            file << L"Total Packets: " << m_stats.totalPackets.load() << L"\n";
            file << L"Packets Analyzed: " << m_stats.packetsAnalyzed.load() << L"\n";
            file << L"Packets Dropped: " << m_stats.packetsDropped.load() << L"\n";
            file << L"Bytes Processed: " << m_stats.bytesProcessed.load() << L"\n";
            file << L"\n--- Stream Statistics ---\n";
            file << L"Total Streams: " << m_stats.totalStreams.load() << L"\n";
            file << L"Active Streams: " << m_stats.activeStreams.load() << L"\n";
            file << L"Streams Timed Out: " << m_stats.streamsTimedOut.load() << L"\n";
            file << L"\n--- Protocol Statistics ---\n";
            file << L"HTTP Streams: " << m_stats.httpStreams.load() << L"\n";
            file << L"HTTPS Streams: " << m_stats.httpsStreams.load() << L"\n";
            file << L"DNS Packets: " << m_stats.dnsPackets.load() << L"\n";
            file << L"SMB Streams: " << m_stats.smbStreams.load() << L"\n";
            file << L"Unknown Protocols: " << m_stats.unknownProtocols.load() << L"\n";
            file << L"\n--- Detection Statistics ---\n";
            file << L"Threats Detected: " << m_stats.threatsDetected.load() << L"\n";
            file << L"Anomalies Detected: " << m_stats.anomaliesDetected.load() << L"\n";
            file << L"Shellcode Detected: " << m_stats.shellcodeDetected.load() << L"\n";
            file << L"Signatures Matched: " << m_stats.signaturesMatched.load() << L"\n";
            file << L"\n--- TLS Statistics ---\n";
            file << L"TLS Handshakes: " << m_stats.tlsHandshakes.load() << L"\n";
            file << L"Certs Extracted: " << m_stats.certsExtracted.load() << L"\n";
            file << L"JA3 Fingerprints: " << m_stats.ja3Fingerprints.load() << L"\n";
            file << L"Malicious JA3: " << m_stats.maliciousJA3.load() << L"\n";
            file << L"\n--- Performance ---\n";
            file << L"Avg Analysis Time: " << m_stats.avgAnalysisTimeUs.load() << L" us\n";
            file << L"Max Analysis Time: " << m_stats.maxAnalysisTimeUs.load() << L" us\n";

            file.close();
            SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Diagnostics exported to %ls", outputPath.c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer: ExportDiagnostics failed: %hs", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void CleanupThread() {
        SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Cleanup thread started");

        while (m_running.load(std::memory_order_acquire)) {
            std::unique_lock lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(30));

            if (!m_running.load(std::memory_order_acquire)) break;

            // Cleanup timed out streams
            size_t removed = m_streamManager->CleanupTimedOut();
            if (removed > 0) {
                m_stats.streamsTimedOut.fetch_add(removed, std::memory_order_relaxed);

                // Safely decrement activeStreams — prevent unsigned underflow
                uint32_t current = m_stats.activeStreams.load(std::memory_order_relaxed);
                while (current > 0) {
                    const uint32_t target = (static_cast<size_t>(current) >= removed)
                        ? static_cast<uint32_t>(current - removed)
                        : 0u;
                    if (m_stats.activeStreams.compare_exchange_weak(
                            current, target, std::memory_order_relaxed)) {
                        break;
                    }
                }

                SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Cleaned up %zu timed-out streams", removed);
            }
        }

        SS_LOG_INFO(L"Network", L"TrafficAnalyzer: Cleanup thread exited");
    }

    AnalysisResult AnalyzePacketImpl(std::span<const uint8_t> packet,
                                    std::chrono::system_clock::time_point timestamp) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        AnalysisResult result;
        result.packet.timestamp = timestamp;
        result.packet.captureLength = packet.size();
        result.packet.wireLength = packet.size();
        result.packet.rawData = packet;

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

                // Reverse key for bidirectional matching
                StreamKey reverseKey;
                reverseKey.srcIP = result.packet.dstIP;
                reverseKey.dstIP = result.packet.srcIP;
                reverseKey.srcPort = result.packet.dstPort;
                reverseKey.dstPort = result.packet.srcPort;
                reverseKey.protocol = result.packet.protocol;
                reverseKey.isIPv6 = result.packet.isIPv6;

                // First: try to FIND existing stream in either direction (no creation)
                auto streamIdOpt = m_streamManager->FindStream(key);
                bool isServerDirection = false;

                if (!streamIdOpt) {
                    // Check reverse direction (we are the server / reply side)
                    streamIdOpt = m_streamManager->FindStream(reverseKey);
                    if (streamIdOpt) {
                        isServerDirection = true;
                    }
                }

                // If no existing stream in either direction, create one
                if (!streamIdOpt) {
                    streamIdOpt = m_streamManager->CreateStream(key);
                }

                if (streamIdOpt) {
                    result.streamId = *streamIdOpt;

                    // Check if this is a new stream
                    auto stream = m_streamManager->GetStream(result.streamId);
                    bool isNew = (stream && stream->state == StreamState::NEW);

                    // Update stream with directional tracking
                    m_streamManager->UpdateStream(result.streamId, [&](StreamInfo& s) {
                        if (s.state == StreamState::NEW) {
                            s.state = StreamState::ESTABLISHED;
                            m_stats.totalStreams.fetch_add(1, std::memory_order_relaxed);
                            m_stats.activeStreams.fetch_add(1, std::memory_order_relaxed);
                        }

                        if (isServerDirection) {
                            s.packetsServer++;
                            s.bytesServer += result.packet.payloadLength;
                        } else {
                            s.packetsClient++;
                            s.bytesClient += result.packet.payloadLength;
                        }

                        s.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            timestamp - s.startTime
                        );
                    });

                    // Protocol identification
                    // SAFETY: Protocol callbacks are invoked OUTSIDE the StreamManager lock
                    //         to prevent deadlock if callbacks call back into StreamManager.
                    Protocol detectedProto = Protocol::UNKNOWN;
                    bool shouldNotifyProtocol = false;
                    StreamInfo protoStreamSnapshot;

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
                                    detectedProto = proto;
                                    shouldNotifyProtocol = true;
                                    protoStreamSnapshot = s;  // snapshot for callback
                                }
                            });
                        }
                    }

                    // Invoke protocol callbacks OUTSIDE StreamManager lock
                    if (shouldNotifyProtocol) {
                        m_callbackManager->InvokeProtocolCallbacks(
                            result.streamId, detectedProto, protoStreamSnapshot);
                    }

                    // Payload analysis
                    // Use a wide accumulator to prevent uint8_t overflow;
                    // clamped to [0,100] before assigning to result.threatScore.
                    uint32_t accumulatedThreatScore = 0;

                    if (m_config.enablePayloadAnalysis && !result.packet.payload.empty()) {
                        result.payloadAnalysis = AnalyzePayload(result.packet.payload);

                        if (result.payloadAnalysis.hasShellcode) {
                            result.threats.push_back(TrafficThreatIndicator::SHELLCODE_DETECTED);
                            accumulatedThreatScore += 80;
                            m_stats.shellcodeDetected.fetch_add(1, std::memory_order_relaxed);
                            m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);

                            SS_LOG_WARN(L"Network",
                                L"TrafficAnalyzer: Shellcode detected in stream %llu (score: %.2f)",
                                static_cast<unsigned long long>(result.streamId),
                                result.payloadAnalysis.shellcodeScore);
                        }

                        if (result.payloadAnalysis.isHighEntropy) {
                            result.anomalies.push_back(AnomalyType::ENCODING_ANOMALY);
                            m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);
                        }

                        // XOR-encoded payload detection
                        if (result.payloadAnalysis.isPossiblyXORed) {
                            result.anomalies.push_back(AnomalyType::ENCODING_ANOMALY);
                            result.threats.push_back(TrafficThreatIndicator::C2_PATTERN);
                            accumulatedThreatScore += 40;
                        }
                    }

                    // Anomaly detection
                    if (m_config.enableAnomalyDetection) {
                        DetectAnomalies(result, isServerDirection, accumulatedThreatScore);
                    }

                    // TLS inspection
                    if (m_config.enableTLSInspection &&
                        (result.protocol == Protocol::HTTPS || result.protocol == Protocol::TLS_UNKNOWN)) {
                        if (IsTLSPayload(result.packet.payload) && result.packet.payload.size() > 5) {
                            // ClientHello
                            if (result.packet.payload[5] == 0x01) {
                                auto ja3 = CalculateJA3(result.packet.payload);

                                if (!ja3.hash.empty()) {
                                    m_stats.ja3Fingerprints.fetch_add(1, std::memory_order_relaxed);

                                    if (IsJA3Malicious(ja3.hash)) {
                                        result.threats.push_back(TrafficThreatIndicator::KNOWN_BAD_JA3);
                                        accumulatedThreatScore += 70;
                                        m_stats.maliciousJA3.fetch_add(1, std::memory_order_relaxed);
                                        m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);

                                        SS_LOG_FATAL(L"Network",
                                            L"TrafficAnalyzer: Malicious JA3 detected: %hs (stream %llu)",
                                            ja3.hash.c_str(),
                                            static_cast<unsigned long long>(result.streamId));
                                    }

                                    m_streamManager->UpdateStream(result.streamId, [&](StreamInfo& s) {
                                        if (!s.tlsInfo) {
                                            s.tlsInfo = TrafficAnalyzerTLSInfo{};
                                        }
                                        s.tlsInfo->ja3 = ja3;
                                        s.isEncrypted = true;
                                    });

                                    m_stats.tlsHandshakes.fetch_add(1, std::memory_order_relaxed);
                                }
                            }

                            // Extract SNI from ClientHello
                            ExtractSNI(result.packet.payload, result.streamId);
                        }
                    }

                    // Clamp accumulated score to [0, 100] and assign
                    result.threatScore = static_cast<uint8_t>(std::min(accumulatedThreatScore, uint32_t{100}));

                    // Invoke threat callbacks
                    for (const auto& threat : result.threats) {
                        m_callbackManager->InvokeThreatCallbacks(result.streamId, threat, result);
                    }

                    // Invoke stream callback if new — re-fetch fresh state
                    if (isNew) {
                        auto freshStream = m_streamManager->GetStream(result.streamId);
                        if (freshStream) {
                            m_callbackManager->InvokeStreamCallbacks(*freshStream, true);
                        }
                    }

                    // Dispatch to specialized sub-modules for domain-specific analysis
                    if (result.protocol != Protocol::UNKNOWN || !result.threats.empty()) {
                        auto dispatchStream = m_streamManager->GetStream(result.streamId);
                        if (dispatchStream) {
                            DispatchToSubModules(result, *dispatchStream);
                        }
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
            SS_LOG_ERROR(L"Network", L"TrafficAnalyzer::AnalyzePacketImpl: %hs", e.what());
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
        info.etherType = (static_cast<uint16_t>(packet[12]) << 8) | packet[13];
        offset = 14;

        // Handle VLAN tagging (802.1Q)
        if (info.etherType == 0x8100) {
            if (packet.size() < offset + 4) return false;
            info.hasVlan = true;
            info.vlanId = ((static_cast<uint16_t>(packet[offset]) << 8) | packet[offset + 1]) & 0x0FFF;
            info.etherType = (static_cast<uint16_t>(packet[offset + 2]) << 8) | packet[offset + 3];
            offset += 4;
        }

        // Parse IP header
        if (info.etherType == 0x0800) {  // IPv4
            if (packet.size() < offset + 20) return false;

            info.ipVersion = 4;
            uint8_t ihl = packet[offset] & 0x0F;
            if (ihl < 5) {
                info.parseError = "Invalid IPv4 IHL";
                return false;
            }
            size_t ipHeaderLen = static_cast<size_t>(ihl) * 4;

            if (packet.size() < offset + ipHeaderLen) return false;

            info.ttl = packet[offset + 8];
            info.protocol = packet[offset + 9];
            info.ipId = (static_cast<uint16_t>(packet[offset + 4]) << 8) | packet[offset + 5];

            uint16_t fragFlags = (static_cast<uint16_t>(packet[offset + 6]) << 8) | packet[offset + 7];
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

            info.srcPort = (static_cast<uint16_t>(packet[offset]) << 8) | packet[offset + 1];
            info.dstPort = (static_cast<uint16_t>(packet[offset + 2]) << 8) | packet[offset + 3];
            info.tcpSeq = (static_cast<uint32_t>(packet[offset + 4]) << 24) |
                         (static_cast<uint32_t>(packet[offset + 5]) << 16) |
                         (static_cast<uint32_t>(packet[offset + 6]) << 8) |
                          static_cast<uint32_t>(packet[offset + 7]);
            info.tcpAck = (static_cast<uint32_t>(packet[offset + 8]) << 24) |
                         (static_cast<uint32_t>(packet[offset + 9]) << 16) |
                         (static_cast<uint32_t>(packet[offset + 10]) << 8) |
                          static_cast<uint32_t>(packet[offset + 11]);

            uint8_t dataOffset = (packet[offset + 12] >> 4) & 0x0F;
            size_t tcpHeaderLen = static_cast<size_t>(dataOffset) * 4;

            // Validate TCP header length (minimum 20 bytes = data offset 5)
            if (tcpHeaderLen < 20 || packet.size() < offset + tcpHeaderLen) {
                info.parseError = "Invalid TCP header length";
                return false;
            }

            info.tcpFlags = packet[offset + 13];
            info.tcpSyn = (info.tcpFlags & 0x02) != 0;
            info.tcpAck_flag = (info.tcpFlags & 0x10) != 0;
            info.tcpFin = (info.tcpFlags & 0x01) != 0;
            info.tcpRst = (info.tcpFlags & 0x04) != 0;
            info.tcpPsh = (info.tcpFlags & 0x08) != 0;
            info.tcpUrg = (info.tcpFlags & 0x20) != 0;

            info.tcpWindow = (static_cast<uint16_t>(packet[offset + 14]) << 8) | packet[offset + 15];

            offset += tcpHeaderLen;
        } else if (info.protocol == 17) {  // UDP
            if (packet.size() < offset + 8) return false;

            info.srcPort = (static_cast<uint16_t>(packet[offset]) << 8) | packet[offset + 1];
            info.dstPort = (static_cast<uint16_t>(packet[offset + 2]) << 8) | packet[offset + 3];
            info.udpLength = (static_cast<uint16_t>(packet[offset + 4]) << 8) | packet[offset + 5];

            offset += 8;
        } else if (info.protocol == 1 || info.protocol == 58) {  // ICMP or ICMPv6
            if (packet.size() < offset + 8) {
                info.parseError = "Packet too small for ICMP header";
                return false;
            }
            offset += 8;
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

        uint64_t currentMax = m_stats.maxAnalysisTimeUs.load(std::memory_order_relaxed);
        while (timeUs > currentMax) {
            if (m_stats.maxAnalysisTimeUs.compare_exchange_weak(
                    currentMax, timeUs, std::memory_order_relaxed)) {
                break;
            }
        }
    }

    // ========================================================================
    // ANOMALY DETECTION
    // ========================================================================

    void DetectAnomalies(AnalysisResult& result, bool isServerDirection, uint32_t& accScore) {
        const auto& pkt = result.packet;

        // 1. Protocol on unexpected port (protocol abuse detection)
        if (result.protocol != Protocol::UNKNOWN) {
            bool portMismatch = false;
            switch (result.protocol) {
                case Protocol::HTTP:
                    portMismatch = (pkt.srcPort != 80 && pkt.dstPort != 80 &&
                                   pkt.srcPort != 8080 && pkt.dstPort != 8080 &&
                                   pkt.srcPort != 8443 && pkt.dstPort != 8443);
                    break;
                case Protocol::DNS:
                    portMismatch = (pkt.srcPort != 53 && pkt.dstPort != 53);
                    break;
                case Protocol::SSH:
                    portMismatch = (pkt.srcPort != 22 && pkt.dstPort != 22);
                    break;
                default:
                    break;
            }

            if (portMismatch) {
                result.anomalies.push_back(AnomalyType::UNEXPECTED_PORT);
                accScore += 20;
                m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 2. DNS tunneling detection — unusually large DNS payloads or high query frequency
        if (result.protocol == Protocol::DNS && !pkt.payload.empty()) {
            // DNS payloads over 512 bytes (without EDNS) or with long labels suggest tunneling
            if (pkt.payloadLength > 512) {
                result.anomalies.push_back(AnomalyType::TUNNELING);
                result.threats.push_back(TrafficThreatIndicator::C2_PATTERN);
                accScore += 50;
                m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_WARN(L"Network",
                    L"TrafficAnalyzer: Potential DNS tunneling detected — payload size %zu in stream %llu",
                    pkt.payloadLength, static_cast<unsigned long long>(result.streamId));
            }

            // Check for unusually long DNS labels (>40 chars per label = likely encoded data)
            if (pkt.payload.size() >= 13) {
                size_t labelOffset = 12;  // Skip DNS header
                while (labelOffset < pkt.payload.size()) {
                    uint8_t labelLen = pkt.payload[labelOffset];
                    if (labelLen == 0) break;
                    if ((labelLen & 0xC0) == 0xC0) break;  // Compression pointer
                    if (labelLen > 40) {
                        result.anomalies.push_back(AnomalyType::COVERT_CHANNEL);
                        result.threats.push_back(TrafficThreatIndicator::EXFILTRATION_PATTERN);
                        accScore += 60;
                        break;
                    }
                    labelOffset += labelLen + 1;
                    if (labelOffset > pkt.payload.size()) break;
                }
            }
        }

        // 3. ICMP tunneling detection — ICMP packets with large payloads
        if (pkt.protocol == 1 || pkt.protocol == 58) {  // ICMP/ICMPv6
            if (pkt.payloadLength > 64) {
                result.anomalies.push_back(AnomalyType::COVERT_CHANNEL);
                result.threats.push_back(TrafficThreatIndicator::C2_PATTERN);
                accScore += 45;
                m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 4. Unusual packet size (very small or very large payloads for protocol)
        if (pkt.payloadLength > 0 && result.protocol == Protocol::HTTP) {
            if (pkt.payloadLength > 10 * 1024 * 1024) {  // >10 MB in single HTTP segment
                result.anomalies.push_back(AnomalyType::UNUSUAL_SIZE);
                m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 5. TCP RST flood indicator
        if (pkt.tcpRst) {
            m_streamManager->UpdateStream(result.streamId, [&](StreamInfo& s) {
                s.retransmissions++;
                if (s.retransmissions > 20) {
                    result.anomalies.push_back(AnomalyType::PROTOCOL_VIOLATION);
                }
            });
        }

        // 6. Exfiltration pattern — large upload from client
        if (!isServerDirection) {
            auto streamOpt = m_streamManager->GetStream(result.streamId);
            if (streamOpt && streamOpt->bytesClient > 5 * 1024 * 1024 &&
                streamOpt->bytesClient > streamOpt->bytesServer * 10) {
                result.anomalies.push_back(AnomalyType::EXFILTRATION);
                result.threats.push_back(TrafficThreatIndicator::EXFILTRATION_PATTERN);
                accScore += 55;
                m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    // ========================================================================
    // TLS SNI EXTRACTION
    // ========================================================================

    void ExtractSNI(std::span<const uint8_t> payload, uint64_t streamId) {
        // TLS Record: [Type(1)] [Version(2)] [Length(2)] [Handshake...]
        // ClientHello contains SNI in extensions (type 0x0000)
        if (payload.size() < 44) return;

        size_t offset = 5;  // Skip TLS record header
        if (offset >= payload.size() || payload[offset] != 0x01) return;

        // Skip handshake header (type + length)
        offset += 4;
        if (offset + 34 > payload.size()) return;

        offset += 2;   // version
        offset += 32;  // random

        // Session ID
        if (offset >= payload.size()) return;
        uint8_t sidLen = payload[offset++];
        offset += sidLen;

        // Cipher suites
        if (offset + 2 > payload.size()) return;
        uint16_t csLen = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1];
        offset += 2 + csLen;

        // Compression
        if (offset >= payload.size()) return;
        uint8_t compLen = payload[offset++];
        offset += compLen;

        // Extensions
        if (offset + 2 > payload.size()) return;
        uint16_t extTotalLen = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1];
        offset += 2;

        const size_t extEnd = std::min(offset + static_cast<size_t>(extTotalLen), payload.size());

        while (offset + 4 <= extEnd) {
            uint16_t extType = (static_cast<uint16_t>(payload[offset]) << 8) | payload[offset + 1];
            uint16_t extLen  = (static_cast<uint16_t>(payload[offset + 2]) << 8) | payload[offset + 3];
            offset += 4;

            if (offset + extLen > extEnd) break;

            // SNI extension = type 0x0000
            if (extType == 0x0000 && extLen >= 5) {
                // SNI list: [ListLength(2)] [Type(1)] [NameLength(2)] [Name...]
                size_t sniOff = offset;
                if (sniOff + 2 > offset + extLen) { offset += extLen; continue; }
                sniOff += 2;  // Skip list length

                if (sniOff + 3 > offset + extLen) { offset += extLen; continue; }
                uint8_t nameType = payload[sniOff++];
                uint16_t nameLen = (static_cast<uint16_t>(payload[sniOff]) << 8) | payload[sniOff + 1];
                sniOff += 2;

                if (nameType == 0 && nameLen > 0 && nameLen <= 255 && sniOff + nameLen <= offset + extLen) {
                    std::string sni(reinterpret_cast<const char*>(&payload[sniOff]), nameLen);

                    m_streamManager->UpdateStream(streamId, [&](StreamInfo& s) {
                        if (!s.tlsInfo) {
                            s.tlsInfo = TrafficAnalyzerTLSInfo{};
                        }
                        s.tlsInfo->sni = std::move(sni);
                    });
                }
                return;
            }

            offset += extLen;
        }
    }

    // ========================================================================
    // MODULE DISPATCH
    // ========================================================================

    /**
     * @brief Dispatches analysis results to specialized network sub-modules.
     *
     * TrafficAnalyzer is the central traffic orchestrator. After protocol
     * identification and threat scoring, it forwards relevant data to the
     * appropriate specialist module (DNSMonitor, URLAnalyzer, TorDetector,
     * VPNDetector, P2PMonitor, BotnetDetector) so they can apply their
     * domain-specific detection logic.
     *
     * All dispatches are fire-and-forget via singleton access. If a module
     * is not yet initialized or has been shut down, the call is a no-op.
     */
    void DispatchToSubModules(const AnalysisResult& result, const StreamInfo& stream) {
        try {
            switch (result.protocol) {
                case Protocol::DNS:
                case Protocol::DNS_OVER_TLS:
                case Protocol::DNS_OVER_HTTPS:
                    // DNSMonitor handles deep DNS analysis, DGA detection,
                    // and DNS tunneling correlation via its own ETW/callback pipeline.
                    // TrafficAnalyzer provides anomaly flags above (tunneling, long labels);
                    // no additional dispatch needed since DNSMonitor has its own data source.
                    break;

                case Protocol::HTTP:
                case Protocol::HTTPS:
                case Protocol::HTTP2:
                case Protocol::HTTP3_QUIC: {
                    // URLAnalyzer: inspect extracted domains/SNI for reputation
                    auto& urlAnalyzer = URLAnalyzer::Instance();
                    if (urlAnalyzer.IsInitialized()) {
                        std::string targetHost;
                        if (stream.tlsInfo && !stream.tlsInfo->sni.empty()) {
                            targetHost = stream.tlsInfo->sni;
                        } else if (stream.httpInfo && !stream.httpInfo->host.empty()) {
                            targetHost = stream.httpInfo->host;
                        }
                        if (!targetHost.empty()) {
                            (void)urlAnalyzer.AnalyzeDomain(targetHost);
                        }
                    }
                    break;
                }

                case Protocol::TOR:
                case Protocol::I2P: {
                    // TorDetector: correlate with known Tor indicators
                    auto& torDetector = TorDetector::Instance();
                    if (torDetector.IsRunning()) {
                        std::string dstStr = IPToString(stream.key.dstIP, stream.key.isIPv6);
                        (void)torDetector.IsTorTraffic(dstStr);
                    }
                    break;
                }

                case Protocol::OPENVPN:
                case Protocol::WIREGUARD:
                case Protocol::IPSEC_IKE:
                case Protocol::IPSEC_ESP:
                case Protocol::L2TP:
                case Protocol::PPTP: {
                    // VPNDetector: check if the remote IP is a known VPN endpoint
                    auto& vpnDetector = VPNDetector::Instance();
                    if (vpnDetector.IsRunning()) {
                        std::string dstStr = IPToString(stream.key.dstIP, stream.key.isIPv6);
                        (void)vpnDetector.IsKnownVPNIP(dstStr);
                    }
                    break;
                }

                case Protocol::BITTORRENT: {
                    // P2PMonitor: feed packet for P2P protocol analysis
                    auto& p2pMonitor = P2PMonitor::Instance();
                    if (p2pMonitor.IsRunning() && !result.packet.payload.empty()) {
                        p2pMonitor.FeedPacket(
                            result.streamId, result.packet.payload);
                    }
                    break;
                }

                case Protocol::BITCOIN:
                case Protocol::ETHEREUM:
                case Protocol::STRATUM:
                    // Crypto-mining traffic: flagged via anomaly/threat indicators above.
                    // BotnetDetector correlation handled in the general block below.
                    break;

                default:
                    break;
            }

            // BotnetDetector: forward high-threat C2 indicators for correlation
            if (!result.threats.empty()) {
                auto& botnetDetector = BotnetDetector::Instance();
                if (botnetDetector.IsRunning() && !result.packet.payload.empty()) {
                    for (const auto& threat : result.threats) {
                        if (threat == TrafficThreatIndicator::C2_PATTERN ||
                            threat == TrafficThreatIndicator::BEACONING ||
                            threat == TrafficThreatIndicator::KNOWN_BAD_JA3) {
                            (void)botnetDetector.AnalyzePayloadForC2(
                                result.packet.payload,
                                C2Protocol::UNKNOWN);
                            break;  // One analysis per packet is sufficient
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network",
                L"TrafficAnalyzer: Module dispatch failed: %hs", e.what());
        } catch (...) {
            // Sub-module failures must never crash the traffic analyzer
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_running{ false };
    TrafficAnalyzerConfig m_config;

    // Threading — must use condition_variable_any with shared_mutex
    std::thread m_cleanupThread;
    std::condition_variable_any m_cv;

    // Stream management
    std::unique_ptr<StreamManager> m_streamManager;

    // Callbacks
    std::unique_ptr<CallbackManager> m_callbackManager;

    // External subsystem references (non-owning, set during init)
    ShadowStrike::ThreatIntel::ThreatIntelLookup* m_threatIntelLookup{ nullptr };
    ShadowStrike::SignatureStore::SignatureStore* m_signatureStore{ nullptr };

    // Statistics
    mutable TrafficAnalyzerStatistics m_stats;
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

std::optional<TrafficAnalyzerTLSInfo> TrafficAnalyzer::GetTLSInfo(uint64_t streamId) const {
    return m_impl->GetTLSInfo(streamId);
}

TrafficAnalyzerJA3Fingerprint TrafficAnalyzer::CalculateJA3(std::span<const uint8_t> clientHello) const {
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

void TrafficAnalyzer::SetThreatIntelLookup(
    ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
    m_impl->SetThreatIntelLookup(lookup);
}

void TrafficAnalyzer::SetSignatureStore(
    ShadowStrike::SignatureStore::SignatureStore* store) noexcept {
    m_impl->SetSignatureStore(store);
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
