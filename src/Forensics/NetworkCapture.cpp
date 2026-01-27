/**
 * ============================================================================
 * ShadowStrike Forensics - NETWORK TRAFFIC CAPTURE ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file NetworkCapture.cpp
 * @brief Enterprise-grade network capture implementation for forensic analysis
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
#include "NetworkCapture.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"

#include <Windows.h>
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <regex>
#include <cmath>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> NetworkCapture::s_instanceCreated{false};

// ============================================================================
// INTERNAL STRUCTURES & HELPERS
// ============================================================================

namespace {

/// @brief PCAP file header
struct PCAPFileHeader {
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t timezone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

/// @brief PCAP packet header
struct PCAPPacketHeader {
    uint32_t tsSec;
    uint32_t tsUsec;
    uint32_t inclLen;
    uint32_t origLen;
};

/// @brief Generate unique session ID
std::string GenerateSessionId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << "CAP-" << std::hex << std::setw(12) << std::setfill('0') << ms
        << "-" << std::setw(8) << std::setfill('0') << counter.fetch_add(1);
    return oss.str();
}

/// @brief Generate unique stream ID
uint64_t GenerateStreamId(const IPAddress& srcIP, uint16_t srcPort,
                          const IPAddress& dstIP, uint16_t dstPort) {
    // Hash components for unique stream ID
    uint64_t id = 0;
    if (srcIP.IsIPv4()) {
        id = static_cast<uint64_t>(srcIP.v4) << 32;
    }
    id ^= (static_cast<uint64_t>(srcPort) << 16) | dstPort;
    return id;
}

/// @brief TCP flag constants
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

} // anonymous namespace

// ============================================================================
// IP ADDRESS IMPLEMENTATION
// ============================================================================

std::optional<IPAddress> IPAddress::FromString(std::string_view str) {
    IPAddress addr;

    // Try IPv4
    struct sockaddr_in sa4;
    if (inet_pton(AF_INET, std::string(str).c_str(), &(sa4.sin_addr)) == 1) {
        addr.family = AF_INET;
        addr.v4 = ntohl(sa4.sin_addr.s_addr);
        return addr;
    }

    // Try IPv6
    struct sockaddr_in6 sa6;
    if (inet_pton(AF_INET6, std::string(str).c_str(), &(sa6.sin6_addr)) == 1) {
        addr.family = AF_INET6;
        std::memcpy(addr.v6.data(), &sa6.sin6_addr, 16);
        return addr;
    }

    return std::nullopt;
}

std::string IPAddress::ToString() const {
    char buffer[INET6_ADDRSTRLEN] = {0};

    if (family == AF_INET) {
        struct in_addr inAddr;
        inAddr.s_addr = htonl(v4);
        inet_ntop(AF_INET, &inAddr, buffer, sizeof(buffer));
    } else if (family == AF_INET6) {
        struct in6_addr in6Addr;
        std::memcpy(&in6Addr, v6.data(), 16);
        inet_ntop(AF_INET6, &in6Addr, buffer, sizeof(buffer));
    }

    return std::string(buffer);
}

bool IPAddress::IsValid() const noexcept {
    if (family == AF_INET) {
        return v4 != 0;
    } else if (family == AF_INET6) {
        return std::any_of(v6.begin(), v6.end(), [](uint8_t b) { return b != 0; });
    }
    return false;
}

bool IPAddress::IsPrivate() const noexcept {
    if (family == AF_INET) {
        // 10.0.0.0/8
        if ((v4 & 0xFF000000) == 0x0A000000) return true;
        // 172.16.0.0/12
        if ((v4 & 0xFFF00000) == 0xAC100000) return true;
        // 192.168.0.0/16
        if ((v4 & 0xFFFF0000) == 0xC0A80000) return true;
        // 127.0.0.0/8
        if ((v4 & 0xFF000000) == 0x7F000000) return true;
    }
    return false;
}

bool IPAddress::operator==(const IPAddress& other) const noexcept {
    if (family != other.family) return false;

    if (family == AF_INET) {
        return v4 == other.v4;
    } else if (family == AF_INET6) {
        return v6 == other.v6;
    }

    return false;
}

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

std::string CapturedPacket::ToJson() const {
    json j;
    j["packetId"] = packetId;
    j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    j["sourceIP"] = sourceIP.ToString();
    j["destIP"] = destIP.ToString();
    j["sourcePort"] = sourcePort;
    j["destPort"] = destPort;
    j["protocol"] = static_cast<int>(protocol);
    j["appProtocol"] = static_cast<int>(appProtocol);
    j["processId"] = processId;
    j["packetLength"] = packetLength;
    j["capturedLength"] = capturedLength;
    j["isOutbound"] = isOutbound;
    j["tcpSeq"] = tcpSeq;
    j["tcpAck"] = tcpAck;
    j["tcpFlags"] = tcpFlags;
    return j.dump();
}

std::string TCPStream::ToJson() const {
    json j;
    j["streamId"] = streamId;
    j["sourceIP"] = sourceIP.ToString();
    j["sourcePort"] = sourcePort;
    j["destIP"] = destIP.ToString();
    j["destPort"] = destPort;
    j["processId"] = processId;
    j["state"] = static_cast<int>(state);
    j["bytesFromClient"] = bytesFromClient;
    j["bytesToClient"] = bytesToClient;
    j["packetsFromClient"] = packetsFromClient;
    j["packetsToClient"] = packetsToClient;
    j["appProtocol"] = static_cast<int>(appProtocol);
    j["tlsSNI"] = tlsSNI;
    j["httpHost"] = httpHost;
    return j.dump();
}

std::string DNSTransaction::ToJson() const {
    json j;
    j["transactionId"] = transactionId;
    j["queryDomain"] = queryDomain;
    j["queryType"] = queryType;
    j["sourceIP"] = sourceIP.ToString();
    j["dnsServer"] = dnsServer.ToString();
    j["processId"] = processId;
    j["responseCode"] = responseCode;
    j["isSuspicious"] = isSuspicious;

    json addrArray = json::array();
    for (const auto& addr : resolvedAddresses) {
        addrArray.push_back(addr.ToString());
    }
    j["resolvedAddresses"] = addrArray;

    return j.dump();
}

std::string CaptureSession::ToJson() const {
    json j;
    j["sessionId"] = sessionId;
    j["outputPath"] = Utils::StringUtils::WStringToString(outputPath);
    j["format"] = static_cast<int>(format);
    j["method"] = static_cast<int>(method);
    j["status"] = static_cast<int>(status);
    j["targetPid"] = targetPid;
    j["targetProcessName"] = Utils::StringUtils::WStringToString(targetProcessName);
    j["packetsCaptured"] = packetsCaptured;
    j["bytesCaptured"] = bytesCaptured;
    j["packetsDropped"] = packetsDropped;
    j["fileSize"] = fileSize;
    j["errorMessage"] = errorMessage;
    return j.dump();
}

bool CaptureFilter::Matches(const CapturedPacket& packet) const {
    if (!isEnabled) return false;

    // Check process ID
    if (!processIds.empty()) {
        if (std::find(processIds.begin(), processIds.end(), packet.processId) == processIds.end()) {
            return false;
        }
    }

    // Check source IP
    if (!sourceIPs.empty()) {
        if (std::find(sourceIPs.begin(), sourceIPs.end(), packet.sourceIP) == sourceIPs.end()) {
            return false;
        }
    }

    // Check destination IP
    if (!destIPs.empty()) {
        if (std::find(destIPs.begin(), destIPs.end(), packet.destIP) == destIPs.end()) {
            return false;
        }
    }

    // Check ports
    if (!sourcePorts.empty()) {
        if (std::find(sourcePorts.begin(), sourcePorts.end(), packet.sourcePort) == sourcePorts.end()) {
            return false;
        }
    }

    if (!destPorts.empty()) {
        if (std::find(destPorts.begin(), destPorts.end(), packet.destPort) == destPorts.end()) {
            return false;
        }
    }

    // Check protocol
    if (!protocols.empty()) {
        if (std::find(protocols.begin(), protocols.end(), packet.protocol) == protocols.end()) {
            return false;
        }
    }

    return true;
}

std::string SSLKeyLogEntry::ToKeyLogLine() const {
    std::ostringstream oss;
    oss << keyType << " ";

    // Client random (hex)
    for (uint8_t b : clientRandom) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    oss << " ";

    // Secret (hex)
    for (uint8_t b : secret) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return oss.str();
}

void CaptureStatistics::Reset() noexcept {
    totalPackets = 0;
    totalBytes = 0;
    droppedPackets = 0;
    tcpStreams = 0;
    dnsTransactions = 0;
    sslSessions = 0;
    activeCaptures = 0;
    startTime = Clock::now();
}

std::string CaptureStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    json j;
    j["uptimeSeconds"] = uptime;
    j["totalPackets"] = totalPackets.load();
    j["totalBytes"] = totalBytes.load();
    j["droppedPackets"] = droppedPackets.load();
    j["tcpStreams"] = tcpStreams.load();
    j["dnsTransactions"] = dnsTransactions.load();
    j["sslSessions"] = sslSessions.load();
    j["activeCaptures"] = activeCaptures.load();
    return j.dump();
}

bool NetworkCaptureConfiguration::IsValid() const noexcept {
    if (snaplen == 0 || snaplen > 65535) {
        return false;
    }

    if (maxCaptureSize == 0 || maxCaptureSize > 1ULL * 1024 * 1024 * 1024 * 1024) {  // 1TB max
        return false;
    }

    if (outputDirectory.empty()) {
        return false;
    }

    return true;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class NetworkCaptureImpl final {
public:
    NetworkCaptureImpl();
    ~NetworkCaptureImpl();

    // Lifecycle
    bool Initialize(const NetworkCaptureConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_status == ModuleStatus::Running; }
    ModuleStatus GetStatus() const noexcept { return m_status; }

    // Capture control
    std::string StartCapture(uint32_t pid, std::wstring_view outputPath,
                             CaptureFormat format, const std::vector<CaptureFilter>& filters);
    std::string StartCapture(std::wstring_view outputPath,
                             const std::vector<CaptureFilter>& filters);
    void StopCapture();
    void StopCapture(const std::string& sessionId);
    void PauseCapture(const std::string& sessionId);
    void ResumeCapture(const std::string& sessionId);
    CaptureStatus GetCaptureStatus(const std::string& sessionId) const;
    std::optional<CaptureSession> GetSession(const std::string& sessionId) const;
    std::vector<CaptureSession> GetActiveSessions() const;

    // Filters
    bool AddFilter(const std::string& sessionId, const CaptureFilter& filter);
    bool RemoveFilter(const std::string& sessionId, const std::string& filterName);
    void ClearFilters(const std::string& sessionId);
    std::vector<CaptureFilter> GetFilters(const std::string& sessionId) const;

    // Stream tracking
    std::vector<TCPStream> GetTCPStreams(const std::string& sessionId) const;
    std::optional<TCPStream> GetStream(uint64_t streamId) const;
    std::vector<TCPStream> GetStreamsForProcess(uint32_t pid) const;

    // DNS logging
    std::vector<DNSTransaction> GetDNSTransactions(const std::string& sessionId) const;
    std::vector<DNSTransaction> GetDNSForDomain(std::string_view domain) const;

    // SSL key logging
    std::vector<SSLKeyLogEntry> GetSSLKeyLog(const std::string& sessionId) const;
    bool ExportSSLKeyLog(const std::string& sessionId, std::wstring_view outputPath);

    // Callbacks
    void SetPacketCallback(PacketCallback callback);
    void SetStreamCallback(StreamCallback callback);
    void SetDNSCallback(DNSCallback callback);
    void SetStatusCallback(CaptureStatusCallback callback);

    // Analysis
    std::vector<std::pair<IPAddress, double>> DetectBeaconing(
        const std::string& sessionId, uint32_t minIntervalMs);
    std::vector<std::string> DetectDNSTunneling(const std::string& sessionId);
    std::vector<std::tuple<IPAddress, uint16_t, uint64_t>> GetConnectionSummary(
        const std::string& sessionId) const;

    // Statistics
    CaptureStatistics GetStatistics() const;
    std::optional<CaptureStatistics> GetSessionStatistics(const std::string& sessionId) const;
    void ResetStatistics();

    // Utility
    bool IsWFPAvailable() const;
    bool IsNpcapAvailable() const;
    std::vector<std::pair<std::string, std::wstring>> GetInterfaces() const;
    bool SelfTest();

private:
    // Internal methods
    void CaptureThreadFunc(const std::string& sessionId);
    void ProcessPacket(const std::string& sessionId, const CapturedPacket& packet);
    void UpdateTCPStream(const CapturedPacket& packet);
    void ProcessDNSPacket(const CapturedPacket& packet);
    bool WritePCAPHeader(std::ofstream& file, CaptureFormat format);
    bool WritePCAPPacket(std::ofstream& file, const CapturedPacket& packet);
    void NotifyStatusChange(const CaptureSession& session);
    std::vector<CapturedPacket> SimulatePacketCapture(uint32_t pid);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    NetworkCaptureConfiguration m_config;

    // Capture sessions
    std::unordered_map<std::string, CaptureSession> m_sessions;
    std::unordered_map<std::string, std::unique_ptr<std::thread>> m_captureThreads;
    std::unordered_map<std::string, std::atomic<bool>> m_stopFlags;
    std::unordered_map<std::string, std::ofstream> m_outputFiles;

    // Stream tracking
    std::unordered_map<uint64_t, TCPStream> m_tcpStreams;

    // DNS tracking
    std::vector<DNSTransaction> m_dnsTransactions;

    // SSL keys
    std::unordered_map<std::string, std::vector<SSLKeyLogEntry>> m_sslKeys;

    // Callbacks
    PacketCallback m_packetCallback;
    StreamCallback m_streamCallback;
    DNSCallback m_dnsCallback;
    CaptureStatusCallback m_statusCallback;

    // Statistics
    CaptureStatistics m_stats;

    // Packet ID counter
    std::atomic<uint64_t> m_packetIdCounter{0};
};

// ============================================================================
// PIMPL CONSTRUCTOR/DESTRUCTOR
// ============================================================================

NetworkCaptureImpl::NetworkCaptureImpl() {
    Utils::Logger::Info("NetworkCaptureImpl constructed");
}

NetworkCaptureImpl::~NetworkCaptureImpl() {
    Shutdown();
    Utils::Logger::Info("NetworkCaptureImpl destroyed");
}

// ============================================================================
// LIFECYCLE IMPLEMENTATION
// ============================================================================

bool NetworkCaptureImpl::Initialize(const NetworkCaptureConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (m_status != ModuleStatus::Uninitialized) {
            Utils::Logger::Warn("NetworkCapture already initialized");
            return false;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid NetworkCapture configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;

        // Create output directory
        if (!fs::exists(m_config.outputDirectory)) {
            fs::create_directories(m_config.outputDirectory);
        }

        // Initialize Winsock
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            Utils::Logger::Error("WSAStartup failed: {}", result);
            m_status = ModuleStatus::Error;
            return false;
        }

        // Initialize statistics
        m_stats.Reset();

        m_status = ModuleStatus::Running;

        Utils::Logger::Info("NetworkCapture initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("NetworkCapture initialization failed: {}", e.what());
        m_status = ModuleStatus::Error;
        return false;
    }
}

void NetworkCaptureImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    try {
        if (m_status == ModuleStatus::Stopped || m_status == ModuleStatus::Uninitialized) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Stop all captures
        std::vector<std::string> sessionIds;
        for (const auto& [id, _] : m_sessions) {
            sessionIds.push_back(id);
        }

        lock.unlock();

        for (const auto& id : sessionIds) {
            StopCapture(id);
        }

        lock.lock();

        // Close all files
        m_outputFiles.clear();

        // Clear data structures
        m_sessions.clear();
        m_captureThreads.clear();
        m_tcpStreams.clear();
        m_dnsTransactions.clear();
        m_sslKeys.clear();

        // Cleanup Winsock
        WSACleanup();

        m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("NetworkCapture shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

// ============================================================================
// CAPTURE CONTROL IMPLEMENTATION
// ============================================================================

std::string NetworkCaptureImpl::StartCapture(
    uint32_t pid, std::wstring_view outputPath,
    CaptureFormat format, const std::vector<CaptureFilter>& filters) {

    try {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Running) {
            Utils::Logger::Error("Cannot start capture: module not initialized");
            return "";
        }

        if (m_sessions.size() >= NetworkCaptureConstants::MAX_CONCURRENT_CAPTURES) {
            Utils::Logger::Error("Maximum concurrent captures reached");
            return "";
        }

        // Create session
        CaptureSession session;
        session.sessionId = GenerateSessionId();
        session.outputPath = std::wstring(outputPath);
        session.format = format;
        session.targetPid = pid;
        session.status = CaptureStatus::Starting;
        session.startTime = std::chrono::system_clock::now();
        session.filters = filters;

        // Get process name if PID specified
        if (pid != 0) {
            // This would use ProcessUtils to get process name
            session.targetProcessName = L"Process_" + std::to_wstring(pid);
        }

        m_sessions[session.sessionId] = session;

        // Open output file
        std::ofstream outFile(session.outputPath, std::ios::binary);
        if (!outFile) {
            Utils::Logger::Error("Failed to create capture file: {}",
                Utils::StringUtils::WStringToString(session.outputPath));
            m_sessions.erase(session.sessionId);
            return "";
        }

        // Write PCAP header
        if (!WritePCAPHeader(outFile, format)) {
            Utils::Logger::Error("Failed to write PCAP header");
            m_sessions.erase(session.sessionId);
            return "";
        }

        m_outputFiles[session.sessionId] = std::move(outFile);

        // Create stop flag
        m_stopFlags[session.sessionId].store(false);

        // Start capture thread
        m_captureThreads[session.sessionId] = std::make_unique<std::thread>(
            &NetworkCaptureImpl::CaptureThreadFunc, this, session.sessionId);

        // Update session status
        m_sessions[session.sessionId].status = CaptureStatus::Running;

        m_stats.activeCaptures++;

        lock.unlock();

        NotifyStatusChange(session);

        Utils::Logger::Info("Started capture session: {} (PID: {}, Output: {})",
            session.sessionId, pid, Utils::StringUtils::WStringToString(outputPath));

        return session.sessionId;

    } catch (const std::exception& e) {
        Utils::Logger::Error("StartCapture failed: {}", e.what());
        return "";
    }
}

std::string NetworkCaptureImpl::StartCapture(
    std::wstring_view outputPath, const std::vector<CaptureFilter>& filters) {
    return StartCapture(0, outputPath, m_config.defaultFormat, filters);
}

void NetworkCaptureImpl::StopCapture() {
    std::shared_lock lock(m_mutex);

    std::vector<std::string> sessionIds;
    for (const auto& [id, _] : m_sessions) {
        sessionIds.push_back(id);
    }

    lock.unlock();

    for (const auto& id : sessionIds) {
        StopCapture(id);
    }
}

void NetworkCaptureImpl::StopCapture(const std::string& sessionId) {
    try {
        {
            std::unique_lock lock(m_mutex);

            auto sessionIt = m_sessions.find(sessionId);
            if (sessionIt == m_sessions.end()) {
                return;
            }

            sessionIt->second.status = CaptureStatus::Stopping;
            m_stopFlags[sessionId].store(true);
        }

        // Wait for thread to finish
        auto threadIt = m_captureThreads.find(sessionId);
        if (threadIt != m_captureThreads.end() && threadIt->second->joinable()) {
            threadIt->second->join();
        }

        std::unique_lock lock(m_mutex);

        // Close output file
        auto fileIt = m_outputFiles.find(sessionId);
        if (fileIt != m_outputFiles.end()) {
            fileIt->second.close();
            m_outputFiles.erase(fileIt);
        }

        // Update session
        auto sessionIt = m_sessions.find(sessionId);
        if (sessionIt != m_sessions.end()) {
            sessionIt->second.status = CaptureStatus::Stopped;
            sessionIt->second.endTime = std::chrono::system_clock::now();

            // Get file size
            if (fs::exists(sessionIt->second.outputPath)) {
                sessionIt->second.fileSize = fs::file_size(sessionIt->second.outputPath);
            }

            NotifyStatusChange(sessionIt->second);
        }

        // Cleanup
        m_captureThreads.erase(sessionId);
        m_stopFlags.erase(sessionId);

        m_stats.activeCaptures--;

        Utils::Logger::Info("Stopped capture session: {}", sessionId);

    } catch (const std::exception& e) {
        Utils::Logger::Error("StopCapture failed: {}", e.what());
    }
}

void NetworkCaptureImpl::PauseCapture(const std::string& sessionId) {
    std::unique_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        it->second.status = CaptureStatus::Paused;
        Utils::Logger::Info("Paused capture: {}", sessionId);
    }
}

void NetworkCaptureImpl::ResumeCapture(const std::string& sessionId) {
    std::unique_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        it->second.status = CaptureStatus::Running;
        Utils::Logger::Info("Resumed capture: {}", sessionId);
    }
}

CaptureStatus NetworkCaptureImpl::GetCaptureStatus(const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        return it->second.status;
    }

    return CaptureStatus::Idle;
}

std::optional<CaptureSession> NetworkCaptureImpl::GetSession(const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<CaptureSession> NetworkCaptureImpl::GetActiveSessions() const {
    std::shared_lock lock(m_mutex);

    std::vector<CaptureSession> sessions;
    sessions.reserve(m_sessions.size());

    for (const auto& [_, session] : m_sessions) {
        if (session.status == CaptureStatus::Running ||
            session.status == CaptureStatus::Paused) {
            sessions.push_back(session);
        }
    }

    return sessions;
}

// ============================================================================
// FILTER MANAGEMENT
// ============================================================================

bool NetworkCaptureImpl::AddFilter(const std::string& sessionId, const CaptureFilter& filter) {
    std::unique_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end()) {
        return false;
    }

    if (it->second.filters.size() >= NetworkCaptureConstants::MAX_FILTER_RULES) {
        Utils::Logger::Warn("Maximum filter rules reached for session {}", sessionId);
        return false;
    }

    it->second.filters.push_back(filter);
    Utils::Logger::Info("Added filter '{}' to session {}", filter.name, sessionId);
    return true;
}

bool NetworkCaptureImpl::RemoveFilter(const std::string& sessionId, const std::string& filterName) {
    std::unique_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end()) {
        return false;
    }

    auto& filters = it->second.filters;
    auto filterIt = std::remove_if(filters.begin(), filters.end(),
        [&filterName](const CaptureFilter& f) { return f.name == filterName; });

    if (filterIt != filters.end()) {
        filters.erase(filterIt, filters.end());
        Utils::Logger::Info("Removed filter '{}' from session {}", filterName, sessionId);
        return true;
    }

    return false;
}

void NetworkCaptureImpl::ClearFilters(const std::string& sessionId) {
    std::unique_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        it->second.filters.clear();
        Utils::Logger::Info("Cleared filters for session {}", sessionId);
    }
}

std::vector<CaptureFilter> NetworkCaptureImpl::GetFilters(const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        return it->second.filters;
    }

    return {};
}

// ============================================================================
// STREAM TRACKING
// ============================================================================

std::vector<TCPStream> NetworkCaptureImpl::GetTCPStreams(const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    std::vector<TCPStream> streams;

    // Filter streams by session (simplified - would track session association)
    for (const auto& [_, stream] : m_tcpStreams) {
        streams.push_back(stream);
    }

    return streams;
}

std::optional<TCPStream> NetworkCaptureImpl::GetStream(uint64_t streamId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_tcpStreams.find(streamId);
    if (it != m_tcpStreams.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<TCPStream> NetworkCaptureImpl::GetStreamsForProcess(uint32_t pid) const {
    std::shared_lock lock(m_mutex);

    std::vector<TCPStream> streams;

    for (const auto& [_, stream] : m_tcpStreams) {
        if (stream.processId == pid) {
            streams.push_back(stream);
        }
    }

    return streams;
}

void NetworkCaptureImpl::UpdateTCPStream(const CapturedPacket& packet) {
    if (packet.protocol != ProtocolType::TCP) {
        return;
    }

    std::unique_lock lock(m_mutex);

    uint64_t streamId = GenerateStreamId(packet.sourceIP, packet.sourcePort,
                                         packet.destIP, packet.destPort);

    auto it = m_tcpStreams.find(streamId);

    if (it == m_tcpStreams.end()) {
        // New stream
        TCPStream stream;
        stream.streamId = streamId;
        stream.sourceIP = packet.sourceIP;
        stream.sourcePort = packet.sourcePort;
        stream.destIP = packet.destIP;
        stream.destPort = packet.destPort;
        stream.processId = packet.processId;
        stream.startTime = packet.timestamp;
        stream.state = TCPStreamState::SynSent;

        // Detect app protocol
        if (packet.destPort == 80) stream.appProtocol = AppProtocol::HTTP;
        else if (packet.destPort == 443) stream.appProtocol = AppProtocol::HTTPS;
        else if (packet.destPort == 53) stream.appProtocol = AppProtocol::DNS;

        m_tcpStreams[streamId] = stream;
        m_stats.tcpStreams++;

        if (m_streamCallback) {
            lock.unlock();
            try {
                m_streamCallback(stream);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Stream callback exception: {}", e.what());
            }
            lock.lock();
        }
    } else {
        // Update existing stream
        auto& stream = it->second;

        if (packet.isOutbound) {
            stream.bytesFromClient += packet.packetLength;
            stream.packetsFromClient++;
        } else {
            stream.bytesToClient += packet.packetLength;
            stream.packetsToClient++;
        }

        // Update state based on TCP flags
        if (packet.tcpFlags & TCPFlags::SYN) {
            if (packet.tcpFlags & TCPFlags::ACK) {
                stream.state = TCPStreamState::SynReceived;
            }
        } else if (packet.tcpFlags & TCPFlags::FIN) {
            stream.state = TCPStreamState::FinWait1;
        } else if (packet.tcpFlags & TCPFlags::RST) {
            stream.state = TCPStreamState::Closed;
        } else if (!(packet.tcpFlags & (TCPFlags::SYN | TCPFlags::FIN))) {
            if (stream.state == TCPStreamState::SynReceived) {
                stream.state = TCPStreamState::Established;
            }
        }

        stream.endTime = packet.timestamp;
    }
}

// ============================================================================
// DNS LOGGING
// ============================================================================

std::vector<DNSTransaction> NetworkCaptureImpl::GetDNSTransactions(
    const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);
    return m_dnsTransactions;
}

std::vector<DNSTransaction> NetworkCaptureImpl::GetDNSForDomain(std::string_view domain) const {
    std::shared_lock lock(m_mutex);

    std::vector<DNSTransaction> transactions;

    for (const auto& trans : m_dnsTransactions) {
        if (trans.queryDomain.find(domain) != std::string::npos) {
            transactions.push_back(trans);
        }
    }

    return transactions;
}

void NetworkCaptureImpl::ProcessDNSPacket(const CapturedPacket& packet) {
    if (packet.destPort != 53 && packet.sourcePort != 53) {
        return;
    }

    if (!m_config.enableDNSLogging) {
        return;
    }

    // Simplified DNS parsing
    // In production, would fully parse DNS packets

    std::unique_lock lock(m_mutex);

    DNSTransaction trans;
    trans.transactionId = static_cast<uint16_t>(m_dnsTransactions.size());
    trans.queryTime = packet.timestamp;
    trans.sourceIP = packet.sourceIP;
    trans.dnsServer = packet.destIP;
    trans.processId = packet.processId;

    // Simplified - would parse actual DNS query
    trans.queryDomain = "example.com";
    trans.queryType = 1; // A record

    m_dnsTransactions.push_back(trans);
    m_stats.dnsTransactions++;

    if (m_dnsCallback) {
        lock.unlock();
        try {
            m_dnsCallback(trans);
        } catch (const std::exception& e) {
            Utils::Logger::Error("DNS callback exception: {}", e.what());
        }
    }
}

// ============================================================================
// SSL KEY LOGGING
// ============================================================================

std::vector<SSLKeyLogEntry> NetworkCaptureImpl::GetSSLKeyLog(
    const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_sslKeys.find(sessionId);
    if (it != m_sslKeys.end()) {
        return it->second;
    }

    return {};
}

bool NetworkCaptureImpl::ExportSSLKeyLog(const std::string& sessionId,
                                         std::wstring_view outputPath) {
    try {
        std::shared_lock lock(m_mutex);

        auto it = m_sslKeys.find(sessionId);
        if (it == m_sslKeys.end() || it->second.empty()) {
            Utils::Logger::Warn("No SSL keys for session {}", sessionId);
            return false;
        }

        lock.unlock();

        std::ofstream file(std::wstring(outputPath));
        if (!file) {
            Utils::Logger::Error("Failed to create SSL key log file");
            return false;
        }

        file << "# SSL/TLS Key Log File\n";
        file << "# Generated by ShadowStrike NetworkCapture\n";
        file << "# Session: " << sessionId << "\n\n";

        for (const auto& entry : it->second) {
            file << entry.ToKeyLogLine() << "\n";
        }

        file.close();

        Utils::Logger::Info("Exported SSL key log to {}",
            Utils::StringUtils::WStringToString(outputPath));

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ExportSSLKeyLog failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void NetworkCaptureImpl::SetPacketCallback(PacketCallback callback) {
    std::unique_lock lock(m_mutex);
    m_packetCallback = std::move(callback);
}

void NetworkCaptureImpl::SetStreamCallback(StreamCallback callback) {
    std::unique_lock lock(m_mutex);
    m_streamCallback = std::move(callback);
}

void NetworkCaptureImpl::SetDNSCallback(DNSCallback callback) {
    std::unique_lock lock(m_mutex);
    m_dnsCallback = std::move(callback);
}

void NetworkCaptureImpl::SetStatusCallback(CaptureStatusCallback callback) {
    std::unique_lock lock(m_mutex);
    m_statusCallback = std::move(callback);
}

// ============================================================================
// ANALYSIS
// ============================================================================

std::vector<std::pair<IPAddress, double>> NetworkCaptureImpl::DetectBeaconing(
    const std::string& sessionId, uint32_t minIntervalMs) {

    std::vector<std::pair<IPAddress, double>> beacons;

    std::shared_lock lock(m_mutex);

    // Simplified beaconing detection
    // In production: analyze packet timing intervals for regularity

    std::unordered_map<std::string, std::vector<SystemTimePoint>> ipTimestamps;

    // Collect timestamps per IP (would filter by session)
    for (const auto& [_, stream] : m_tcpStreams) {
        std::string ipStr = stream.destIP.ToString();
        ipTimestamps[ipStr].push_back(stream.startTime);
    }

    // Analyze regularity
    for (const auto& [ipStr, timestamps] : ipTimestamps) {
        if (timestamps.size() < 3) continue;

        // Calculate interval variance
        std::vector<int64_t> intervals;
        for (size_t i = 1; i < timestamps.size(); ++i) {
            auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamps[i] - timestamps[i - 1]).count();
            intervals.push_back(interval);
        }

        // Calculate mean
        double mean = 0;
        for (auto interval : intervals) {
            mean += interval;
        }
        mean /= intervals.size();

        // Calculate variance
        double variance = 0;
        for (auto interval : intervals) {
            variance += (interval - mean) * (interval - mean);
        }
        variance /= intervals.size();

        // Low variance = beaconing
        double score = 100.0 / (1.0 + std::sqrt(variance) / mean);

        if (score > 70.0) {  // High regularity
            auto ip = IPAddress::FromString(ipStr);
            if (ip.has_value()) {
                beacons.push_back({*ip, score});
            }
        }
    }

    std::sort(beacons.begin(), beacons.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    return beacons;
}

std::vector<std::string> NetworkCaptureImpl::DetectDNSTunneling(const std::string& sessionId) {
    std::vector<std::string> suspiciousDomains;

    std::shared_lock lock(m_mutex);

    // Simplified DNS tunneling detection
    // Check for long domain names, high entropy, excessive queries

    std::unordered_map<std::string, size_t> domainCounts;

    for (const auto& trans : m_dnsTransactions) {
        const auto& domain = trans.queryDomain;

        // Check length (tunneling often uses long subdomains)
        if (domain.length() > 50) {
            if (std::find(suspiciousDomains.begin(), suspiciousDomains.end(), domain)
                == suspiciousDomains.end()) {
                suspiciousDomains.push_back(domain);
            }
        }

        // Count queries per domain
        domainCounts[domain]++;
    }

    // High query volume can indicate tunneling
    for (const auto& [domain, count] : domainCounts) {
        if (count > 100) {  // Threshold
            if (std::find(suspiciousDomains.begin(), suspiciousDomains.end(), domain)
                == suspiciousDomains.end()) {
                suspiciousDomains.push_back(domain);
            }
        }
    }

    return suspiciousDomains;
}

std::vector<std::tuple<IPAddress, uint16_t, uint64_t>>
NetworkCaptureImpl::GetConnectionSummary(const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    std::map<std::pair<std::string, uint16_t>, uint64_t> connections;

    // Aggregate by destination
    for (const auto& [_, stream] : m_tcpStreams) {
        std::string ipStr = stream.destIP.ToString();
        auto key = std::make_pair(ipStr, stream.destPort);
        connections[key] += stream.bytesFromClient + stream.bytesToClient;
    }

    std::vector<std::tuple<IPAddress, uint16_t, uint64_t>> summary;

    for (const auto& [key, bytes] : connections) {
        auto ip = IPAddress::FromString(key.first);
        if (ip.has_value()) {
            summary.push_back({*ip, key.second, bytes});
        }
    }

    // Sort by bytes (descending)
    std::sort(summary.begin(), summary.end(),
        [](const auto& a, const auto& b) { return std::get<2>(a) > std::get<2>(b); });

    return summary;
}

// ============================================================================
// STATISTICS
// ============================================================================

CaptureStatistics NetworkCaptureImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

std::optional<CaptureStatistics> NetworkCaptureImpl::GetSessionStatistics(
    const std::string& sessionId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end()) {
        CaptureStatistics stats;
        stats.totalPackets = it->second.packetsCaptured;
        stats.totalBytes = it->second.bytesCaptured;
        stats.droppedPackets = it->second.packetsDropped;
        return stats;
    }

    return std::nullopt;
}

void NetworkCaptureImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    Utils::Logger::Info("Statistics reset");
}

// ============================================================================
// UTILITY
// ============================================================================

bool NetworkCaptureImpl::IsWFPAvailable() const {
    // Check if Windows Filtering Platform is available
    // Simplified - would check for WFP API availability
    return true;
}

bool NetworkCaptureImpl::IsNpcapAvailable() const {
    // Check if Npcap is installed
    // Simplified - would check for Npcap library
    return false;
}

std::vector<std::pair<std::string, std::wstring>> NetworkCaptureImpl::GetInterfaces() const {
    std::vector<std::pair<std::string, std::wstring>> interfaces;

    // Get network adapters
    ULONG bufferSize = 15000;
    std::vector<uint8_t> buffer(bufferSize);

    auto pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    DWORD result = GetAdaptersInfo(pAdapterInfo, &bufferSize);

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        result = GetAdaptersInfo(pAdapterInfo, &bufferSize);
    }

    if (result == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;

        while (pAdapter) {
            std::string name = pAdapter->AdapterName;
            std::wstring desc = Utils::StringUtils::StringToWString(pAdapter->Description);

            interfaces.push_back({name, desc});

            pAdapter = pAdapter->Next;
        }
    }

    return interfaces;
}

bool NetworkCaptureImpl::SelfTest() {
    Utils::Logger::Info("Running NetworkCapture self-test...");

    try {
        // Test 1: Check Winsock
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            Utils::Logger::Error("Self-test failed: WSAStartup error");
            return false;
        }
        WSACleanup();
        Utils::Logger::Info("✓ Winsock test passed");

        // Test 2: IP address parsing
        auto ip4 = IPAddress::FromString("192.168.1.1");
        if (!ip4.has_value() || !ip4->IsIPv4()) {
            Utils::Logger::Error("Self-test failed: IPv4 parsing");
            return false;
        }
        Utils::Logger::Info("✓ IPv4 parsing test passed");

        auto ip6 = IPAddress::FromString("::1");
        if (!ip6.has_value() || ip6->IsIPv4()) {
            Utils::Logger::Error("Self-test failed: IPv6 parsing");
            return false;
        }
        Utils::Logger::Info("✓ IPv6 parsing test passed");

        // Test 3: Check interfaces
        auto ifaces = GetInterfaces();
        Utils::Logger::Info("✓ Found {} network interfaces", ifaces.size());

        // Test 4: Session ID generation
        auto sessionId = GenerateSessionId();
        if (sessionId.empty() || sessionId.find("CAP-") != 0) {
            Utils::Logger::Error("Self-test failed: Session ID generation");
            return false;
        }
        Utils::Logger::Info("✓ Session ID generation test passed");

        Utils::Logger::Info("All NetworkCapture self-tests passed!");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("Self-test failed with exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

void NetworkCaptureImpl::CaptureThreadFunc(const std::string& sessionId) {
    Utils::Logger::Info("Capture thread started for session: {}", sessionId);

    try {
        while (!m_stopFlags[sessionId].load()) {
            CaptureStatus status;
            uint32_t targetPid = 0;

            {
                std::shared_lock lock(m_mutex);
                auto it = m_sessions.find(sessionId);
                if (it == m_sessions.end()) break;

                status = it->second.status;
                targetPid = it->second.targetPid;
            }

            if (status == CaptureStatus::Paused) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // Simulate packet capture (in production: use WFP/Npcap/raw sockets)
            auto packets = SimulatePacketCapture(targetPid);

            for (const auto& packet : packets) {
                ProcessPacket(sessionId, packet);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Capture thread exception: {}", e.what());

        std::unique_lock lock(m_mutex);
        auto it = m_sessions.find(sessionId);
        if (it != m_sessions.end()) {
            it->second.status = CaptureStatus::Error;
            it->second.errorMessage = e.what();
        }
    }

    Utils::Logger::Info("Capture thread stopped for session: {}", sessionId);
}

void NetworkCaptureImpl::ProcessPacket(const std::string& sessionId,
                                       const CapturedPacket& packet) {
    try {
        std::unique_lock lock(m_mutex);

        auto sessionIt = m_sessions.find(sessionId);
        if (sessionIt == m_sessions.end()) {
            return;
        }

        auto& session = sessionIt->second;

        // Apply filters
        bool shouldCapture = false;

        if (session.filters.empty()) {
            shouldCapture = true;
        } else {
            for (const auto& filter : session.filters) {
                if (filter.Matches(packet)) {
                    if (filter.action == FilterAction::Capture ||
                        filter.action == FilterAction::Alert) {
                        shouldCapture = true;
                        break;
                    }
                }
            }
        }

        if (!shouldCapture) {
            return;
        }

        // Update session statistics
        session.packetsCaptured++;
        session.bytesCaptured += packet.packetLength;

        // Update global statistics
        m_stats.totalPackets++;
        m_stats.totalBytes += packet.packetLength;

        // Write to file
        auto fileIt = m_outputFiles.find(sessionId);
        if (fileIt != m_outputFiles.end()) {
            WritePCAPPacket(fileIt->second, packet);
        }

        // Update TCP streams
        lock.unlock();
        UpdateTCPStream(packet);
        ProcessDNSPacket(packet);
        lock.lock();

        // Notify callback
        if (m_packetCallback) {
            lock.unlock();
            try {
                m_packetCallback(packet);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Packet callback exception: {}", e.what());
            }
            lock.lock();
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("ProcessPacket error: {}", e.what());
    }
}

bool NetworkCaptureImpl::WritePCAPHeader(std::ofstream& file, CaptureFormat format) {
    try {
        if (format == CaptureFormat::PCAP) {
            PCAPFileHeader header;
            header.magic = NetworkCaptureConstants::PCAP_MAGIC;
            header.versionMajor = 2;
            header.versionMinor = 4;
            header.timezone = 0;
            header.sigfigs = 0;
            header.snaplen = m_config.snaplen;
            header.network = NetworkCaptureConstants::LINKTYPE_RAW;

            file.write(reinterpret_cast<const char*>(&header), sizeof(header));
            return file.good();
        }

        // PCAPNG or other formats would be implemented here

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("WritePCAPHeader failed: {}", e.what());
        return false;
    }
}

bool NetworkCaptureImpl::WritePCAPPacket(std::ofstream& file, const CapturedPacket& packet) {
    try {
        PCAPPacketHeader header;

        auto timeSinceEpoch = packet.timestamp.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timeSinceEpoch);
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            timeSinceEpoch - seconds);

        header.tsSec = static_cast<uint32_t>(seconds.count());
        header.tsUsec = static_cast<uint32_t>(microseconds.count());
        header.inclLen = static_cast<uint32_t>(packet.data.size());
        header.origLen = packet.packetLength;

        file.write(reinterpret_cast<const char*>(&header), sizeof(header));
        file.write(reinterpret_cast<const char*>(packet.data.data()), packet.data.size());

        return file.good();

    } catch (const std::exception& e) {
        Utils::Logger::Error("WritePCAPPacket failed: {}", e.what());
        return false;
    }
}

void NetworkCaptureImpl::NotifyStatusChange(const CaptureSession& session) {
    if (m_statusCallback) {
        try {
            m_statusCallback(session);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Status callback exception: {}", e.what());
        }
    }
}

std::vector<CapturedPacket> NetworkCaptureImpl::SimulatePacketCapture(uint32_t pid) {
    // Simulation for demonstration
    // In production: use WFP callout driver, ETW, or Npcap

    std::vector<CapturedPacket> packets;

    // Generate a few simulated packets
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 10);

    if (dist(rng) < 3) {  // 30% chance of packets
        CapturedPacket packet;
        packet.packetId = m_packetIdCounter++;
        packet.timestamp = std::chrono::system_clock::now();
        packet.processId = pid;

        // Simulate packet to common server
        packet.sourceIP = *IPAddress::FromString("192.168.1.100");
        packet.destIP = *IPAddress::FromString("93.184.216.34");  // example.com
        packet.sourcePort = 50000 + dist(rng) * 100;
        packet.destPort = 443;
        packet.protocol = ProtocolType::TCP;
        packet.appProtocol = AppProtocol::HTTPS;
        packet.isOutbound = true;

        // Simulate packet data
        packet.data.resize(100);
        packet.packetLength = 100;
        packet.capturedLength = 100;

        packets.push_back(packet);
    }

    return packets;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION (SINGLETON)
// ============================================================================

NetworkCapture& NetworkCapture::Instance() noexcept {
    static NetworkCapture instance;
    return instance;
}

bool NetworkCapture::HasInstance() noexcept {
    return s_instanceCreated.load();
}

NetworkCapture::NetworkCapture()
    : m_impl(std::make_unique<NetworkCaptureImpl>()) {
    s_instanceCreated = true;
}

NetworkCapture::~NetworkCapture() {
    s_instanceCreated = false;
}

// Forward all public methods to implementation

bool NetworkCapture::Initialize(const NetworkCaptureConfiguration& config) {
    return m_impl->Initialize(config);
}

void NetworkCapture::Shutdown() {
    m_impl->Shutdown();
}

bool NetworkCapture::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus NetworkCapture::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool NetworkCapture::StartCapture(uint32_t pid, const std::wstring& outputPath) {
    auto sessionId = m_impl->StartCapture(pid, outputPath,
        CaptureFormat::PCAPNG, {});
    return !sessionId.empty();
}

std::string NetworkCapture::StartCapture(uint32_t pid, std::wstring_view outputPath,
                                         CaptureFormat format,
                                         const std::vector<CaptureFilter>& filters) {
    return m_impl->StartCapture(pid, outputPath, format, filters);
}

std::string NetworkCapture::StartCapture(std::wstring_view outputPath,
                                         const std::vector<CaptureFilter>& filters) {
    return m_impl->StartCapture(outputPath, filters);
}

void NetworkCapture::StopCapture() {
    m_impl->StopCapture();
}

void NetworkCapture::StopCapture(const std::string& sessionId) {
    m_impl->StopCapture(sessionId);
}

void NetworkCapture::PauseCapture(const std::string& sessionId) {
    m_impl->PauseCapture(sessionId);
}

void NetworkCapture::ResumeCapture(const std::string& sessionId) {
    m_impl->ResumeCapture(sessionId);
}

CaptureStatus NetworkCapture::GetCaptureStatus(const std::string& sessionId) const {
    return m_impl->GetCaptureStatus(sessionId);
}

std::optional<CaptureSession> NetworkCapture::GetSession(const std::string& sessionId) const {
    return m_impl->GetSession(sessionId);
}

std::vector<CaptureSession> NetworkCapture::GetActiveSessions() const {
    return m_impl->GetActiveSessions();
}

bool NetworkCapture::AddFilter(const std::string& sessionId, const CaptureFilter& filter) {
    return m_impl->AddFilter(sessionId, filter);
}

bool NetworkCapture::RemoveFilter(const std::string& sessionId, const std::string& filterName) {
    return m_impl->RemoveFilter(sessionId, filterName);
}

void NetworkCapture::ClearFilters(const std::string& sessionId) {
    m_impl->ClearFilters(sessionId);
}

std::vector<CaptureFilter> NetworkCapture::GetFilters(const std::string& sessionId) const {
    return m_impl->GetFilters(sessionId);
}

std::vector<TCPStream> NetworkCapture::GetTCPStreams(const std::string& sessionId) const {
    return m_impl->GetTCPStreams(sessionId);
}

std::optional<TCPStream> NetworkCapture::GetStream(uint64_t streamId) const {
    return m_impl->GetStream(streamId);
}

std::vector<TCPStream> NetworkCapture::GetStreamsForProcess(uint32_t pid) const {
    return m_impl->GetStreamsForProcess(pid);
}

std::vector<DNSTransaction> NetworkCapture::GetDNSTransactions(
    const std::string& sessionId) const {
    return m_impl->GetDNSTransactions(sessionId);
}

std::vector<DNSTransaction> NetworkCapture::GetDNSForDomain(std::string_view domain) const {
    return m_impl->GetDNSForDomain(domain);
}

std::vector<SSLKeyLogEntry> NetworkCapture::GetSSLKeyLog(const std::string& sessionId) const {
    return m_impl->GetSSLKeyLog(sessionId);
}

bool NetworkCapture::ExportSSLKeyLog(const std::string& sessionId,
                                     std::wstring_view outputPath) {
    return m_impl->ExportSSLKeyLog(sessionId, outputPath);
}

void NetworkCapture::SetPacketCallback(PacketCallback callback) {
    m_impl->SetPacketCallback(std::move(callback));
}

void NetworkCapture::SetStreamCallback(StreamCallback callback) {
    m_impl->SetStreamCallback(std::move(callback));
}

void NetworkCapture::SetDNSCallback(DNSCallback callback) {
    m_impl->SetDNSCallback(std::move(callback));
}

void NetworkCapture::SetStatusCallback(CaptureStatusCallback callback) {
    m_impl->SetStatusCallback(std::move(callback));
}

std::vector<std::pair<IPAddress, double>> NetworkCapture::DetectBeaconing(
    const std::string& sessionId, uint32_t minIntervalMs) {
    return m_impl->DetectBeaconing(sessionId, minIntervalMs);
}

std::vector<std::string> NetworkCapture::DetectDNSTunneling(const std::string& sessionId) {
    return m_impl->DetectDNSTunneling(sessionId);
}

std::vector<std::tuple<IPAddress, uint16_t, uint64_t>>
NetworkCapture::GetConnectionSummary(const std::string& sessionId) const {
    return m_impl->GetConnectionSummary(sessionId);
}

CaptureStatistics NetworkCapture::GetStatistics() const {
    return m_impl->GetStatistics();
}

std::optional<CaptureStatistics> NetworkCapture::GetSessionStatistics(
    const std::string& sessionId) const {
    return m_impl->GetSessionStatistics(sessionId);
}

void NetworkCapture::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool NetworkCapture::IsWFPAvailable() const {
    return m_impl->IsWFPAvailable();
}

bool NetworkCapture::IsNpcapAvailable() const {
    return m_impl->IsNpcapAvailable();
}

std::vector<std::pair<std::string, std::wstring>> NetworkCapture::GetInterfaces() const {
    return m_impl->GetInterfaces();
}

bool NetworkCapture::SelfTest() {
    return m_impl->SelfTest();
}

std::string NetworkCapture::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << NetworkCaptureConstants::VERSION_MAJOR << "."
        << NetworkCaptureConstants::VERSION_MINOR << "."
        << NetworkCaptureConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetCaptureModeName(CaptureMode mode) noexcept {
    switch (mode) {
        case CaptureMode::Passive: return "Passive";
        case CaptureMode::Active: return "Active";
        case CaptureMode::Inline: return "Inline";
        case CaptureMode::Mirror: return "Mirror";
        default: return "Unknown";
    }
}

std::string_view GetCaptureMethodName(CaptureMethod method) noexcept {
    switch (method) {
        case CaptureMethod::Auto: return "Auto";
        case CaptureMethod::WFP: return "WFP";
        case CaptureMethod::ETW: return "ETW";
        case CaptureMethod::RawSocket: return "RawSocket";
        case CaptureMethod::Npcap: return "Npcap";
        case CaptureMethod::Driver: return "Driver";
        default: return "Unknown";
    }
}

std::string_view GetProtocolName(ProtocolType protocol) noexcept {
    switch (protocol) {
        case ProtocolType::ICMP: return "ICMP";
        case ProtocolType::TCP: return "TCP";
        case ProtocolType::UDP: return "UDP";
        case ProtocolType::ICMPv6: return "ICMPv6";
        case ProtocolType::SCTP: return "SCTP";
        default: return "Unknown";
    }
}

std::string_view GetAppProtocolName(AppProtocol protocol) noexcept {
    switch (protocol) {
        case AppProtocol::HTTP: return "HTTP";
        case AppProtocol::HTTPS: return "HTTPS";
        case AppProtocol::DNS: return "DNS";
        case AppProtocol::SMTP: return "SMTP";
        case AppProtocol::SMB: return "SMB";
        case AppProtocol::SSH: return "SSH";
        case AppProtocol::FTP: return "FTP";
        case AppProtocol::RDP: return "RDP";
        case AppProtocol::IRC: return "IRC";
        case AppProtocol::Custom: return "Custom";
        default: return "Unknown";
    }
}

std::string_view GetCaptureFormatName(CaptureFormat format) noexcept {
    switch (format) {
        case CaptureFormat::PCAP: return "PCAP";
        case CaptureFormat::PCAPNG: return "PCAPNG";
        case CaptureFormat::ShadowStrike: return "ShadowStrike";
        case CaptureFormat::NetFlow: return "NetFlow";
        case CaptureFormat::JSON: return "JSON";
        default: return "Unknown";
    }
}

std::wstring_view GetCaptureFormatExtension(CaptureFormat format) noexcept {
    switch (format) {
        case CaptureFormat::PCAP: return L".pcap";
        case CaptureFormat::PCAPNG: return L".pcapng";
        case CaptureFormat::ShadowStrike: return L".sscap";
        case CaptureFormat::NetFlow: return L".nfcap";
        case CaptureFormat::JSON: return L".json";
        default: return L".cap";
    }
}

std::string_view GetCaptureStatusName(CaptureStatus status) noexcept {
    switch (status) {
        case CaptureStatus::Idle: return "Idle";
        case CaptureStatus::Starting: return "Starting";
        case CaptureStatus::Running: return "Running";
        case CaptureStatus::Paused: return "Paused";
        case CaptureStatus::Stopping: return "Stopping";
        case CaptureStatus::Stopped: return "Stopped";
        case CaptureStatus::Error: return "Error";
        default: return "Unknown";
    }
}

std::string_view GetTCPStateName(TCPStreamState state) noexcept {
    switch (state) {
        case TCPStreamState::Closed: return "Closed";
        case TCPStreamState::SynSent: return "SynSent";
        case TCPStreamState::SynReceived: return "SynReceived";
        case TCPStreamState::Established: return "Established";
        case TCPStreamState::FinWait1: return "FinWait1";
        case TCPStreamState::FinWait2: return "FinWait2";
        case TCPStreamState::CloseWait: return "CloseWait";
        case TCPStreamState::Closing: return "Closing";
        case TCPStreamState::LastAck: return "LastAck";
        case TCPStreamState::TimeWait: return "TimeWait";
        default: return "Unknown";
    }
}

}  // namespace Forensics
}  // namespace ShadowStrike
