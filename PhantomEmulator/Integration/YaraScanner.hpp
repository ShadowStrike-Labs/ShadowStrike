/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * YaraScanner.hpp — YARA rule scanner for emulated process memory
 *
 * Provides two scanning modes:
 *   1. Runtime-loaded libyara (LoadLibrary/dlopen) for full YARA rule support
 *   2. Built-in pattern matching (always available, no external dependency)
 *
 * The scanner operates on guest virtual memory page-by-page via VirtualMemory
 * and can run during or after emulation. When the YARA library is absent the
 * scanner gracefully degrades to built-in signatures covering the most common
 * malware families, shellcode stagers, and attacker tool indicators.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>
#include <span>
#include <string_view>

namespace Phantom {

class VirtualMemory;

// ============================================================================
// YARA Match Result
// ============================================================================

struct YaraMatch {
    std::string ruleName;
    std::string ruleNamespace;
    std::string description;
    std::string author;
    std::string severity;       // "info", "suspicious", "malicious", "critical"

    struct StringMatch {
        std::string  identifier;
        GuestAddress offset;
        uint32_t     length;
    };
    std::vector<StringMatch> strings;

    std::vector<std::string> mitreTags;
    std::string family;
};

// ============================================================================
// YaraScanner — Runtime-loaded YARA integration for memory scanning
// ============================================================================

class YaraScanner {
public:
    YaraScanner() noexcept;
    ~YaraScanner() noexcept;

    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;
    YaraScanner(YaraScanner&&) noexcept;
    YaraScanner& operator=(YaraScanner&&) noexcept;

    // Initialize: attempt to load the YARA shared library.
    // Returns true if libyara was found and initialized.
    // Built-in patterns are always loaded regardless of the return value.
    [[nodiscard]] bool Initialize() noexcept;

    // True when libyara is loaded and operational.
    [[nodiscard]] bool IsAvailable() const noexcept;

    // === Rule Loading ========================================================

    [[nodiscard]] bool LoadRulesFromFile(const std::filesystem::path& path) noexcept;
    [[nodiscard]] bool LoadRulesFromString(std::string_view ruleSource) noexcept;
    [[nodiscard]] bool LoadCompiledRules(std::span<const uint8_t> data) noexcept;

    // === Scanning =============================================================

    [[nodiscard]] std::vector<YaraMatch> ScanBuffer(
        std::span<const uint8_t> buffer,
        uint32_t timeoutSeconds = 30) noexcept;

    [[nodiscard]] std::vector<YaraMatch> ScanGuestMemory(
        VirtualMemory& memory,
        GuestAddress startAddr,
        GuestSize size,
        uint32_t timeoutSeconds = 60) noexcept;

    [[nodiscard]] std::vector<YaraMatch> ScanAllGuestMemory(
        VirtualMemory& memory,
        uint32_t timeoutSeconds = 120) noexcept;

    // Built-in pattern scan — always available regardless of libyara presence.
    [[nodiscard]] std::vector<YaraMatch> ScanWithBuiltinRules(
        std::span<const uint8_t> buffer) noexcept;

    // === Statistics ===========================================================

    [[nodiscard]] uint32_t GetRuleCount() const noexcept;
    [[nodiscard]] uint32_t GetTotalScans() const noexcept;
    [[nodiscard]] uint32_t GetTotalMatches() const noexcept;
    [[nodiscard]] uint32_t GetScanErrors() const noexcept;

    void Reset() noexcept;

    // === Limits ===============================================================

    static constexpr uint32_t kMaxScanSize = 64 * 1024 * 1024;  // 64 MB
    static constexpr uint32_t kMaxRules    = 10000;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
