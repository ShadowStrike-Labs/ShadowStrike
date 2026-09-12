/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DomainUtils.cpp
 * @brief Public Suffix List algorithm, per https://publicsuffix.org/list/ .
 *
 * The algorithm is small but every clause of it matters, so it is spelled out here rather
 * than left implicit in the code:
 *
 *   1. A rule matches a host when the rule's labels equal the host's rightmost labels. A
 *      "*" label matches exactly one label of the host - never zero, and never more.
 *   2. An exception rule, written "!suffix", wins over any other match. Its public suffix
 *      is the rule with its LEFTMOST label removed, which is how "!www.ck" carves www.ck
 *      back out of "*.ck".
 *   3. Otherwise the matching rule with the MOST labels wins.
 *   4. If nothing matches, the implicit rule is "*": the public suffix is the last label.
 *   5. The registrable domain is the public suffix plus one more label. A host that IS a
 *      public suffix has no registrable domain, and that is a real answer, not an error.
 *
 * Clause 4 is the one that quietly matters for a security product: an unknown TLD still
 * produces an answer, so a caller cannot tell a real result from a fallback unless it is
 * told. DomainParts::matchedExplicitRule is that signal.
 */

#include "pch.h"

#include "DomainUtils.hpp"

#include "DataStorePaths.hpp"
#include "Logger.hpp"

#include <algorithm>
#include <atomic>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
namespace Utils {
namespace Domain {

namespace {

constexpr const wchar_t* kLogCategory = L"DomainUtils";

/// Guards against a malformed or hostile list file exhausting memory. The real list carries
/// roughly ten thousand rules, so this is two orders of magnitude of headroom rather than a
/// tight fit that a legitimate update would trip.
constexpr std::size_t kMaxRules = 1'000'000;

/// A hostname longer than this is not a hostname. DNS caps a name at 253 characters.
constexpr std::size_t kMaxHostLength = 253;

[[nodiscard]] std::string AsciiLower(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        out.push_back(static_cast<char>(
            (c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c));
    }
    return out;
}

/// @brief Splits on '.', rejecting empty labels. An empty label means a malformed host
///        such as "a..b" or a leading dot, and those must not be normalised away silently.
[[nodiscard]] bool SplitLabels(std::string_view host, std::vector<std::string_view>& out) {
    out.clear();
    std::size_t start = 0;
    while (start <= host.size()) {
        const std::size_t dot = host.find('.', start);
        const std::size_t end = (dot == std::string_view::npos) ? host.size() : dot;
        if (end == start) {
            return false;  // empty label
        }
        out.push_back(host.substr(start, end - start));
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    return !out.empty();
}

/// @brief True when the string is an IPv4 dotted quad or contains ':' (IPv6). Such inputs
///        have no public suffix, and returning one for them would be a fabricated answer.
[[nodiscard]] bool LooksLikeIpLiteral(std::string_view host) {
    if (host.find(':') != std::string_view::npos) {
        return true;
    }
    int octets = 0;
    std::size_t start = 0;
    while (start <= host.size()) {
        const std::size_t dot = host.find('.', start);
        const std::size_t end = (dot == std::string_view::npos) ? host.size() : dot;
        if (end == start || end - start > 3) {
            return false;
        }
        for (std::size_t i = start; i < end; ++i) {
            if (host[i] < '0' || host[i] > '9') {
                return false;
            }
        }
        ++octets;
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    return octets == 4;
}

[[nodiscard]] std::string JoinFrom(const std::vector<std::string_view>& labels,
                                   std::size_t first) {
    std::string out;
    for (std::size_t i = first; i < labels.size(); ++i) {
        if (!out.empty()) {
            out.push_back('.');
        }
        out.append(labels[i]);
    }
    return out;
}

}  // namespace

struct PublicSuffixList::Impl {
    mutable std::mutex           loadMutex;
    std::atomic<bool>            loaded{false};

    /// Rule text (without any leading '!') mapped to its section. Wildcard rules are stored
    /// with their "*." prefix intact so a lookup can ask for the exact form it needs.
    std::unordered_map<std::string, SuffixSection> rules;
    std::unordered_map<std::string, SuffixSection> exceptions;
    std::size_t  icannCount = 0;
    std::string  version;
};

PublicSuffixList::PublicSuffixList() : m_impl(new Impl()) {}
PublicSuffixList::~PublicSuffixList() { delete m_impl; }

PublicSuffixList& PublicSuffixList::Instance() noexcept {
    static PublicSuffixList instance;
    return instance;
}

bool PublicSuffixList::IsLoaded() const noexcept {
    return m_impl->loaded.load(std::memory_order_acquire);
}

std::size_t PublicSuffixList::RuleCount() const noexcept {
    if (!IsLoaded()) {
        return 0;
    }
    return m_impl->rules.size() + m_impl->exceptions.size();
}

std::size_t PublicSuffixList::IcannRuleCount() const noexcept {
    if (!IsLoaded()) {
        return 0;
    }
    return m_impl->icannCount;
}

std::string PublicSuffixList::Version() const {
    if (!IsLoaded()) {
        return {};
    }
    std::lock_guard<std::mutex> lock(m_impl->loadMutex);
    return m_impl->version;
}

bool PublicSuffixList::LoadFromFile(const std::wstring& path) noexcept {
    try {
        std::lock_guard<std::mutex> lock(m_impl->loadMutex);
        if (m_impl->loaded.load(std::memory_order_acquire)) {
            return true;
        }

        std::ifstream file(path, std::ios::binary);
        if (!file) {
            SS_LOG_ERROR(kLogCategory,
                L"Public Suffix List could not be opened at %ls - domain decomposition is "
                L"unavailable, so no caller can determine a registrable domain this session",
                path.c_str());
            return false;
        }

        // The section markers are the only thing distinguishing an ICANN rule from a
        // PRIVATE one, and the distinction is a trust decision for every caller. A list
        // without them is not usable, so parsing refuses rather than guessing.
        bool sawIcannBegin   = false;
        bool inPrivate       = false;
        SuffixSection section = SuffixSection::None;

        std::string line;
        std::size_t total = 0;
        while (std::getline(file, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.rfind("// VERSION:", 0) == 0) {
                m_impl->version = line.substr(11);
                const std::size_t at = m_impl->version.find_first_not_of(" \t");
                m_impl->version = (at == std::string::npos)
                                ? std::string{} : m_impl->version.substr(at);
                continue;
            }
            if (line.find("===BEGIN ICANN DOMAINS===") != std::string::npos) {
                sawIcannBegin = true;
                section = SuffixSection::Icann;
                continue;
            }
            if (line.find("===END ICANN DOMAINS===") != std::string::npos) {
                section = SuffixSection::None;
                continue;
            }
            if (line.find("===BEGIN PRIVATE DOMAINS===") != std::string::npos) {
                inPrivate = true;
                section = SuffixSection::Private;
                continue;
            }
            if (line.find("===END PRIVATE DOMAINS===") != std::string::npos) {
                section = SuffixSection::None;
                continue;
            }
            if (line.empty() || line.rfind("//", 0) == 0) {
                continue;
            }
            if (section == SuffixSection::None) {
                continue;  // a rule outside both sections has no trust classification
            }
            if (++total > kMaxRules) {
                SS_LOG_ERROR(kLogCategory,
                    L"Public Suffix List exceeds %zu rules - refusing to load", kMaxRules);
                m_impl->rules.clear();
                m_impl->exceptions.clear();
                return false;
            }

            const std::string rule = AsciiLower(line);
            if (rule.front() == '!') {
                m_impl->exceptions.emplace(rule.substr(1), section);
            } else {
                m_impl->rules.emplace(rule, section);
            }
            if (section == SuffixSection::Icann) {
                ++m_impl->icannCount;
            }
        }

        if (!sawIcannBegin || !inPrivate) {
            SS_LOG_ERROR(kLogCategory,
                L"Public Suffix List is missing its section markers (icann=%d private=%d) - "
                L"refusing to load, because without them an ICANN rule cannot be told from a "
                L"PRIVATE one and every trust decision keyed on that would be wrong",
                sawIcannBegin ? 1 : 0, inPrivate ? 1 : 0);
            m_impl->rules.clear();
            m_impl->exceptions.clear();
            m_impl->icannCount = 0;
            return false;
        }
        if (m_impl->rules.empty()) {
            SS_LOG_ERROR(kLogCategory, L"Public Suffix List parsed to zero rules");
            return false;
        }

        m_impl->loaded.store(true, std::memory_order_release);
        SS_LOG_INFO(kLogCategory,
            L"Public Suffix List loaded: %zu rules (%zu ICANN, %zu private), %zu exceptions, "
            L"version %hs",
            m_impl->rules.size() + m_impl->exceptions.size(), m_impl->icannCount,
            m_impl->rules.size() - m_impl->icannCount, m_impl->exceptions.size(),
            m_impl->version.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCategory, L"Public Suffix List load failed: %hs", e.what());
        return false;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Public Suffix List load failed with unknown exception");
        return false;
    }
}

bool PublicSuffixList::EnsureLoaded() noexcept {
    if (IsLoaded()) {
        return true;
    }
    try {
        const std::wstring path =
            DataStorePaths::GetShippedContentDirectory() + L"\\psl\\public_suffix_list.dat";
        return LoadFromFile(path);
    } catch (...) {
        return false;
    }
}

DomainParts PublicSuffixList::Decompose(std::string_view host, SuffixScope scope) const {
    DomainParts parts;
    if (!IsLoaded() || host.empty() || host.size() > kMaxHostLength) {
        return parts;
    }

    std::string lowered = AsciiLower(host);
    if (!lowered.empty() && lowered.back() == '.') {
        lowered.pop_back();  // a fully-qualified name's trailing root dot is not a label
    }
    if (lowered.empty() || LooksLikeIpLiteral(lowered)) {
        return parts;
    }

    std::vector<std::string_view> labels;
    if (!SplitLabels(lowered, labels) || labels.size() < 2) {
        // A single label has no registrable domain under any rule, and saying otherwise
        // would invent one.
        return parts;
    }

    const bool icannOnly = (scope == SuffixScope::IcannOnly);
    const auto acceptable = [icannOnly](SuffixSection s) {
        return !icannOnly || s == SuffixSection::Icann;
    };

    // Clause 2 first: an exception rule beats every other match regardless of length.
    for (std::size_t i = 0; i + 1 < labels.size(); ++i) {
        const std::string candidate = JoinFrom(labels, i);
        const auto found = m_impl->exceptions.find(candidate);
        if (found != m_impl->exceptions.end() && acceptable(found->second)) {
            parts.publicSuffix        = JoinFrom(labels, i + 1);
            parts.registrableDomain   = candidate;
            if (i > 0) {
                parts.subdomain = std::string(
                    lowered.substr(0, lowered.size() - candidate.size() - 1));
            }
            parts.subdomainLabelCount   = i;
            parts.section               = found->second;
            parts.matchedExplicitRule   = true;
            parts.valid                 = true;
            return parts;
        }
    }

    // Clauses 1 and 3: longest match wins, so walk from the longest candidate inward and
    // stop at the first hit.
    std::size_t suffixStart = std::string::npos;
    SuffixSection matched   = SuffixSection::None;
    for (std::size_t i = 0; i < labels.size(); ++i) {
        const std::string candidate = JoinFrom(labels, i);
        const auto exact = m_impl->rules.find(candidate);
        if (exact != m_impl->rules.end() && acceptable(exact->second)) {
            suffixStart = i;
            matched     = exact->second;
            break;
        }
        if (i + 1 < labels.size()) {
            // A "*" label matches exactly one label: it CONSUMES labels[i], so the
            // wildcard form of a candidate starting at i is "*." plus everything from
            // i + 1. The bound belongs on the RIGHT - there must be at least one label
            // after the wildcard for the rule to have a body. Bounding it on the left
            // instead (i > 0) stopped "*.ck" from ever matching "b.ck" at position 0,
            // which handed a public suffix a registrable domain of its own.
            const std::string wild = "*." + JoinFrom(labels, i + 1);
            const auto found = m_impl->rules.find(wild);
            if (found != m_impl->rules.end() && acceptable(found->second)) {
                suffixStart = i;
                matched     = found->second;
                break;
            }
        }
    }

    if (suffixStart == std::string::npos) {
        // Clause 4: the implicit "*" rule. Reported as a non-explicit match so a caller can
        // distinguish an unknown TLD from a known one.
        suffixStart = labels.size() - 1;
        matched     = SuffixSection::None;
        parts.matchedExplicitRule = false;
    } else {
        parts.matchedExplicitRule = true;
    }

    parts.publicSuffix = JoinFrom(labels, suffixStart);
    parts.section      = matched;
    parts.valid        = true;

    if (suffixStart == 0) {
        // The host is itself a public suffix. There is no registrable domain, and that is
        // the answer rather than a failure.
        return parts;
    }

    parts.registrableDomain     = JoinFrom(labels, suffixStart - 1);
    parts.subdomainLabelCount   = suffixStart - 1;
    if (parts.subdomainLabelCount > 0) {
        parts.subdomain = std::string(
            lowered.substr(0, lowered.size() - parts.registrableDomain.size() - 1));
    }
    return parts;
}

std::string RegistrableDomain(std::string_view host, SuffixScope scope) {
    auto& psl = PublicSuffixList::Instance();
    if (!psl.EnsureLoaded()) {
        return {};
    }
    return psl.Decompose(host, scope).registrableDomain;
}

std::string PublicSuffix(std::string_view host, SuffixScope scope) {
    auto& psl = PublicSuffixList::Instance();
    if (!psl.EnsureLoaded()) {
        return {};
    }
    return psl.Decompose(host, scope).publicSuffix;
}

std::string Subdomain(std::string_view host, SuffixScope scope) {
    auto& psl = PublicSuffixList::Instance();
    if (!psl.EnsureLoaded()) {
        return {};
    }
    return psl.Decompose(host, scope).subdomain;
}

}  // namespace Domain
}  // namespace Utils
}  // namespace ShadowStrike
