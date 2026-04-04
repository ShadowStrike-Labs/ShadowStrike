/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// Forward declarations
class VirtualMemory;

// ============================================================================
// String Categories
// ============================================================================

enum class StringCategory : uint8_t {
    Unknown,
    URL,
    Domain,
    IPAddress,
    FilePath,
    RegistryKey,
    CommandLine,
    UserAgent,
    APIName,
    DLLName,
    MutexName,
    CryptoKey,
    Base64Data,
    EmailAddress,
    Credential,
    SuspiciousCommand,
    BenignString,
};

// ============================================================================
// Extracted String Record
// ============================================================================

struct ExtractedString {
    std::string     value;          // The string content (UTF-8)
    StringCategory  category      = StringCategory::Unknown;
    GuestAddress    address       = 0;   // Location in guest memory
    uint32_t        occurrences   = 1;
    bool            isWide        = false; // Was UTF-16LE
    bool            isDecoded     = false; // Was encoded/encrypted; we decoded it
    std::string     encoding;              // "ascii", "utf16", "base64", "xor_0x42", etc.
    float           suspiciousness = 0.0f; // 0.0 – 1.0
};

// ============================================================================
// String Extractor
// ============================================================================
// Extracts and analyses strings from guest memory during/after emulation.
// Critical for IOC discovery, C2 URL extraction, command identification,
// and malware family classification.
//
// Thread-safe: designed for single-threaded post-emulation analysis.

class StringExtractor {
public:
    explicit StringExtractor(const EmulationConfig& config) noexcept;
    ~StringExtractor() noexcept;

    // Non-copyable, movable
    StringExtractor(const StringExtractor&) = delete;
    StringExtractor& operator=(const StringExtractor&) = delete;
    StringExtractor(StringExtractor&&) noexcept;
    StringExtractor& operator=(StringExtractor&&) noexcept;

    // Scan a contiguous memory region for strings
    void ScanRegion(const uint8_t* data, size_t size, GuestAddress base) noexcept;

    // Scan entire guest address space
    void ScanAll(const VirtualMemory& memory) noexcept;

    // Track stack-string construction during emulation
    void OnStackWrite(GuestAddress rsp, uint8_t byte, uint64_t instrCount) noexcept;

    // --- Results ---

    [[nodiscard]] const std::vector<ExtractedString>& GetStrings() const noexcept;
    [[nodiscard]] std::vector<const ExtractedString*> GetByCategory(StringCategory cat) const noexcept;
    [[nodiscard]] uint32_t GetStringCount() const noexcept;
    [[nodiscard]] std::vector<const ExtractedString*> GetSuspiciousStrings(float minScore = 0.5f) const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
