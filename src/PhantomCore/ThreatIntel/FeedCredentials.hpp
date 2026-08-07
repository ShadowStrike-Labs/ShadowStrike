// ============================================================================
//  ShadowStrike Phantom - Threat Intelligence
//  FeedCredentials.hpp
//
//  Supplies API keys to the threat-intelligence feeds that require them.
//
//  Two constraints shape this, and both were learned the hard way elsewhere in
//  this codebase:
//
//    1. The credentials live in the MACHINE-WIDE data directory, not in any
//       per-user location. The service runs as LocalSystem, so %LOCALAPPDATA%
//       resolves to C:\Windows\system32\config\systemprofile - a profile no
//       administrator would think to put a key in, and the same trap that left
//       five detection modules scanning an empty profile.
//
//    2. Credentials are refused outright unless the data directory is hardened.
//       WhitelistStore already takes this position for trust entries, and the
//       reasoning carries: a file any unprivileged process can rewrite is not a
//       credential, it is an injection point into our outbound requests.
//
//  Values are never logged. Diagnostics name the key and give its length, which
//  is enough to tell "absent" from "present but wrong" without printing secrets
//  into a log file that ships with a support bundle.
//
//  Copyright (c) ShadowStrike-Labs. Licensed under AGPL-3.0.
// ============================================================================

#pragma once

#include <optional>
#include <vector>
#include <string>

namespace ShadowStrike {
namespace ThreatIntel {

// ----------------------------------------------------------------------------
// Credential identifiers
// ----------------------------------------------------------------------------

/// @brief Keys recognised in the credentials file
namespace FeedCredentialKeys {
    /// abuse.ch Auth-Key, shared by MalwareBazaar, ThreatFox and URLhaus APIs.
    /// Obtainable free from https://auth.abuse.ch/ for non-commercial use.
    inline constexpr const char* AbuseChAuthKey = "ABUSECH_AUTH_KEY";

    /// AlienVault OTX API key, sent as X-OTX-API-KEY.
    inline constexpr const char* OtxApiKey = "OTX_API_KEY";

    /// VirusTotal API key, sent as x-apikey.
    inline constexpr const char* VirusTotalApiKey = "VIRUSTOTAL_API_KEY";

    /// AbuseIPDB API key, sent as Key.
    inline constexpr const char* AbuseIpdbApiKey = "ABUSEIPDB_API_KEY";
}

// ----------------------------------------------------------------------------
// FeedCredentials
// ----------------------------------------------------------------------------

/**
 * @brief Reads feed API keys from the hardened machine-wide data directory
 *
 * The file is `<DataDirectory>\feeds.credentials`, one `NAME=VALUE` per line.
 * Blank lines and lines beginning with '#' are ignored. It is deliberately not
 * part of the installer payload and must never be committed: see .gitignore.
 */
class FeedCredentials {
public:
    /// @brief Loads credentials from the machine-wide data directory
    /// @return Loaded instance; may hold nothing if the file is absent
    /// @note Absence is a normal, supported state - the product runs on public
    ///       key-free feeds alone, just with narrower coverage.
    [[nodiscard]] static FeedCredentials Load() noexcept;

    /// @brief Absolute path the credentials are read from
    [[nodiscard]] static std::wstring CredentialsPath();

    /// @brief Retrieves one credential
    /// @param name One of FeedCredentialKeys
    /// @return The value, or nullopt when absent or when the store is unusable
    [[nodiscard]] std::optional<std::string> Get(const std::string& name) const;

    /// @brief True when a non-empty value exists for @p name
    [[nodiscard]] bool Has(const std::string& name) const;

    /// @brief Number of credentials loaded
    [[nodiscard]] std::size_t Count() const noexcept { return m_count; }

    /// @brief True when the file existed and was readable
    [[nodiscard]] bool FileFound() const noexcept { return m_fileFound; }

    /// @brief True when credentials were refused because the directory is not hardened
    /// @note Distinguishes "no credentials configured" from "configured but
    ///       untrustworthy", which need different operator responses.
    [[nodiscard]] bool RefusedUnhardened() const noexcept { return m_refusedUnhardened; }

    /// @brief Emits a summary naming which credentials are present, without values
    void LogSummary() const;

private:
    FeedCredentials() = default;

    // Storage is intentionally opaque: a plain map member in the header would
    // invite callers to iterate and print it.
    struct Entry {
        std::string name;
        std::string value;
    };
    std::vector<Entry> m_entries;

    std::size_t m_count{ 0 };
    bool        m_fileFound{ false };
    bool        m_refusedUnhardened{ false };
};

} // namespace ThreatIntel
} // namespace ShadowStrike
