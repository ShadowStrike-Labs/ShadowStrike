/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * IOCExtractor.hpp — Extracts Indicators of Compromise from emulation sessions
 *
 * Collects and classifies all IOCs observed during emulation: domains, IPs,
 * URLs, file hashes, registry keys, mutexes, certificates, command lines,
 * pipe names, and more. Each IOC is tracked with provenance (where/how it
 * was observed), occurrence count, and confidence score.
 *
 * Includes DGA (Domain Generation Algorithm) detection via entropy analysis,
 * consonant-ratio heuristics, and digit-density checks. Also performs
 * in-memory string scanning for embedded IOCs in allocated guest memory.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "../WinAPI/APITypes.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// ============================================================================
// IOC Types
// ============================================================================

enum class IOCType : uint8_t {
    Domain,
    IPv4,
    IPv6,
    URL,
    FilePath,
    FileName,
    FileHashMD5,
    FileHashSHA1,
    FileHashSHA256,
    RegistryKey,
    RegistryValue,
    MutexName,
    ServiceName,
    PipeName,
    UserAgent,
    EmailAddress,
    Certificate,
    JA3Hash,
    SSDeepHash,
    YARAMatch,
    CommandLine,
};

// ============================================================================
// IOC Entry — a single indicator with provenance
// ============================================================================

struct IOCEntry {
    IOCType     type          = IOCType::Domain;
    std::string value;
    std::string context;
    float       confidence    = 0.0f;
    uint32_t    firstSeen     = 0;
    uint32_t    lastSeen      = 0;
    uint32_t    occurrences   = 0;
    bool        isDefanged    = false;
};

// ============================================================================
// IOC Report — full extraction results
// ============================================================================

struct IOCReport {
    std::vector<IOCEntry> indicators;
    uint32_t totalDomains  = 0;
    uint32_t totalIPs      = 0;
    uint32_t totalURLs     = 0;
    uint32_t totalFiles    = 0;
    uint32_t totalRegistry = 0;
    uint32_t totalMutexes  = 0;
    std::string summary;
};

// ============================================================================
// IOCExtractor — collects all IOCs from emulation
// ============================================================================

class IOCExtractor {
public:
    explicit IOCExtractor(const EmulationConfig& config) noexcept;
    ~IOCExtractor() noexcept;

    IOCExtractor(const IOCExtractor&) = delete;
    IOCExtractor& operator=(const IOCExtractor&) = delete;

    // === Feed Events ===
    void OnAPICall(const APICallDetail& call) noexcept;
    void OnMemoryScan(const uint8_t* data, size_t size, GuestAddress base) noexcept;
    void OnStringFound(const std::string& str, GuestAddress addr) noexcept;

    // === Extract from specific API calls ===
    void OnNetworkConnect(const std::string& addr, uint16_t port) noexcept;
    void OnDnsQuery(const std::string& domain) noexcept;
    void OnFileAccess(const std::wstring& path, bool isCreate) noexcept;
    void OnRegistryAccess(const std::wstring& key, const std::wstring& value) noexcept;
    void OnMutexCreate(const std::wstring& name) noexcept;
    void OnServiceCreate(const std::wstring& name) noexcept;
    void OnProcessCreate(const std::wstring& cmdline) noexcept;
    void OnPipeCreate(const std::string& name) noexcept;
    void OnUserAgent(const std::string& ua) noexcept;

    // === Results ===
    [[nodiscard]] IOCReport GenerateReport() const noexcept;
    [[nodiscard]] const std::vector<IOCEntry>& GetAllIOCs() const noexcept;
    [[nodiscard]] std::vector<const IOCEntry*> GetByType(IOCType type) const noexcept;
    [[nodiscard]] uint32_t GetTotalIOCCount() const noexcept;

    // === Domain Analysis ===
    [[nodiscard]] bool IsSuspiciousDomain(const std::string& domain) const noexcept;
    [[nodiscard]] float CalculateDomainEntropy(const std::string& domain) const noexcept;
    [[nodiscard]] bool IsDGA(const std::string& domain) const noexcept;

    // === IP Analysis ===
    [[nodiscard]] bool IsPrivateIP(const std::string& ip) const noexcept;
    [[nodiscard]] bool IsReservedIP(const std::string& ip) const noexcept;

    // === String Scanning ===
    void ScanForIOCsInBuffer(const uint8_t* data, size_t size) noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
