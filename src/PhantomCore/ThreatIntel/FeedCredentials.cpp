// ============================================================================
//  ShadowStrike Phantom - Threat Intelligence
//  FeedCredentials.cpp
//
//  Copyright (c) ShadowStrike-Labs. Licensed under AGPL-3.0.
// ============================================================================

#include "pch.h"
#include "FeedCredentials.hpp"

#include "../Utils/DataStorePaths.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string_view>

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace ThreatIntel {

namespace {

constexpr const wchar_t* kCredentialsFileName = L"feeds.credentials";

// A credential longer than this is not a key we recognise; refusing it keeps a
// malformed file from being pushed into an outbound header.
constexpr std::size_t kMaxCredentialLength = 512;

[[nodiscard]] std::string Trim(std::string_view s) {
    const auto notSpace = [](unsigned char c) { return std::isspace(c) == 0; };
    const auto begin = std::find_if(s.begin(), s.end(), notSpace);
    const auto end = std::find_if(s.rbegin(), s.rend(), notSpace).base();
    return (begin < end) ? std::string(begin, end) : std::string{};
}

} // namespace

// ----------------------------------------------------------------------------

std::wstring FeedCredentials::CredentialsPath() {
    return (fs::path(Utils::DataStorePaths::GetDataDirectory()) / kCredentialsFileName)
        .wstring();
}

// ----------------------------------------------------------------------------

FeedCredentials FeedCredentials::Load() noexcept {
    FeedCredentials creds;

    try {
        const std::wstring path = CredentialsPath();

        std::error_code ec;
        if (!fs::exists(path, ec)) {
            // Normal state. The product runs on public key-free feeds alone; the
            // caller decides whether to say anything about the narrower coverage.
            return creds;
        }
        creds.m_fileFound = true;

        // A credentials file that an unprivileged process can rewrite is not a
        // credential store. Refuse rather than send an attacker-supplied value in
        // our own outbound requests.
        if (!Utils::DataStorePaths::IsDataDirectoryHardened()) {
            creds.m_refusedUnhardened = true;
            Utils::Logger::Error(
                "[FeedCredentials] Refusing to use '{}': the data directory is not "
                "hardened, so the file is writable by unprivileged processes. Feeds "
                "requiring a key will stay disabled until the directory ACL is fixed.",
                Utils::StringUtils::ToNarrow(path));
            return creds;
        }

        std::ifstream in(path);
        if (!in) {
            Utils::Logger::Warn(
                "[FeedCredentials] '{}' exists but could not be opened",
                Utils::StringUtils::ToNarrow(path));
            return creds;
        }

        std::string line;
        std::size_t lineNumber = 0;
        while (std::getline(in, line)) {
            ++lineNumber;

            const std::string trimmed = Trim(line);
            if (trimmed.empty() || trimmed.front() == '#') {
                continue;
            }

            const std::size_t eq = trimmed.find('=');
            if (eq == std::string::npos) {
                Utils::Logger::Warn(
                    "[FeedCredentials] Ignoring line {} - expected NAME=VALUE",
                    lineNumber);
                continue;
            }

            std::string name = Trim(std::string_view(trimmed).substr(0, eq));
            std::string value = Trim(std::string_view(trimmed).substr(eq + 1));

            if (name.empty() || value.empty()) {
                Utils::Logger::Warn(
                    "[FeedCredentials] Ignoring line {} - empty name or value",
                    lineNumber);
                continue;
            }
            if (value.size() > kMaxCredentialLength) {
                // Deliberately does not echo the value.
                Utils::Logger::Warn(
                    "[FeedCredentials] Ignoring '{}' - value is {} bytes, over the "
                    "{} byte ceiling",
                    name, value.size(), kMaxCredentialLength);
                continue;
            }

            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

            creds.m_entries.push_back(Entry{ std::move(name), std::move(value) });
        }

        creds.m_count = creds.m_entries.size();
    }
    catch (const std::exception& ex) {
        Utils::Logger::Error("[FeedCredentials] Load failed: {}", ex.what());
    }
    catch (...) {
        Utils::Logger::Error("[FeedCredentials] Load failed with an unknown exception");
    }

    return creds;
}

// ----------------------------------------------------------------------------

std::optional<std::string> FeedCredentials::Get(const std::string& name) const {
    const auto it = std::find_if(m_entries.begin(), m_entries.end(),
        [&name](const Entry& e) { return e.name == name; });
    if (it == m_entries.end() || it->value.empty()) {
        return std::nullopt;
    }
    return it->value;
}

bool FeedCredentials::Has(const std::string& name) const {
    return Get(name).has_value();
}

// ----------------------------------------------------------------------------

void FeedCredentials::LogSummary() const {
    if (m_refusedUnhardened) {
        // Already reported as an error during Load; do not repeat it as info.
        return;
    }
    if (!m_fileFound) {
        Utils::Logger::Info(
            "[FeedCredentials] No credentials file at '{}'. Feeds needing an API "
            "key stay disabled; public key-free feeds are unaffected.",
            Utils::StringUtils::ToNarrow(CredentialsPath()));
        return;
    }

    // Names and lengths only. Enough to tell absent from present-but-wrong
    // without writing a secret into a log that ends up in a support bundle.
    std::string summary;
    for (const auto& e : m_entries) {
        if (!summary.empty()) {
            summary += ", ";
        }
        summary += e.name + " (" + std::to_string(e.value.size()) + " chars)";
    }
    Utils::Logger::Info("[FeedCredentials] {} credential(s) loaded: {}",
                        m_count, summary.empty() ? std::string("none") : summary);
}

} // namespace ThreatIntel
} // namespace ShadowStrike
