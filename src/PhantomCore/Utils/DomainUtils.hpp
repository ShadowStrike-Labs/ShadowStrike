/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file DomainUtils.hpp
 * @brief Public Suffix List lookups: the registrable domain of a hostname.
 *
 * WHY THIS EXISTS. Nothing in this codebase knew the difference between a public suffix
 * and a registrable domain. Sixteen files split hostnames on the last dot and nineteen
 * carried a notion of a "base" or "second-level" domain derived that way, which is wrong
 * for every multi-label suffix:
 *
 *     good.co.uk          registrable is good.co.uk        a last-dot split yields co.uk
 *     evil.blogspot.com   registrable is evil.blogspot.com a last-dot split yields blogspot.com
 *
 * Both directions of that error matter. A DGA scorer measuring entropy or label count over
 * the wrong label scores the wrong string. A reputation or allowlist decision keyed on the
 * wrong registrable domain either trusts every tenant of a shared host because one was
 * trusted, or fails to trust any legitimate site under a multi-label ccTLD.
 *
 * THE ICANN AND PRIVATE SECTIONS ARE NOT INTERCHANGEABLE, and the caller must choose:
 *
 *   IncludePrivate  co.uk and blogspot.com are both suffixes, so evil.blogspot.com and
 *                   good.blogspot.com are DIFFERENT registrable domains. This is correct for
 *                   allowlisting, reputation and trust: one tenant of a shared host must
 *                   never confer trust on another.
 *
 *   IcannOnly       only co.uk is a suffix, so both blogspot sites reduce to blogspot.com.
 *                   This is correct for ownership attribution and for grouping traffic by
 *                   the party that actually registered the name.
 *
 * Choosing wrongly is a security decision, not a formatting one, so there is no default:
 * every caller states which question it is asking.
 *
 * KNOWN LIMITATION, deliberately not hidden. The list stores internationalised suffixes as
 * UTF-8 rather than punycode, and lookups here compare bytes after ASCII-only lowercasing.
 * A hostname supplied in punycode form (xn--...) will therefore not match a UTF-8 IDN rule.
 * ASCII hostnames - which is what the kernel and the network stack hand us - are unaffected.
 *
 * Data: https://publicsuffix.org/list/public_suffix_list.dat, MPL-2.0, vendored under
 * content/psl/. The loader records the list's VERSION header so a field log can state which
 * revision produced a verdict.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace ShadowStrike {
namespace Utils {
namespace Domain {

/// @brief Which sections of the list a lookup should honour.
enum class SuffixScope : std::uint8_t {
    /// Treat ICANN and PRIVATE rules alike. Correct for trust and allowlisting: a tenant
    /// of a shared host such as blogspot.com is its own registrable domain.
    IncludePrivate = 0,
    /// Honour only ICANN rules. Correct for attribution: every blogspot tenant reduces to
    /// blogspot.com, the name someone actually registered.
    IcannOnly      = 1,
};

/// @brief Which section supplied the matching rule.
enum class SuffixSection : std::uint8_t {
    None    = 0,  ///< No rule matched; the implicit "*" default was applied.
    Icann   = 1,
    Private = 2,
};

/// @brief The decomposition of a hostname.
struct DomainParts {
    /// The public suffix, e.g. "co.uk". Empty only when the host is unusable.
    std::string publicSuffix;

    /// The registrable domain, e.g. "good.co.uk". EMPTY when the host is itself a public
    /// suffix and therefore has no registrable domain - "co.uk" alone is not a site.
    /// Callers must treat empty as "no owner", never as "the host".
    std::string registrableDomain;

    /// Everything to the left of the registrable domain, e.g. "a.b" for "a.b.good.co.uk".
    /// Empty when the host IS the registrable domain. This is the string a DNS-tunnel or
    /// DGA heuristic should measure, and measuring the wrong one is the defect this file
    /// exists to remove.
    std::string subdomain;

    /// Number of labels in `subdomain`. Zero when there is no subdomain.
    std::size_t subdomainLabelCount = 0;

    SuffixSection section = SuffixSection::None;

    /// True when an explicit rule matched. False means the implicit "*" default was used,
    /// which happens for an unknown TLD and is worth reporting rather than silently
    /// treating as a normal result.
    bool matchedExplicitRule = false;

    /// True when the input could not be decomposed at all - empty, an IP literal, a single
    /// label, or a malformed host. Every other field is then meaningless.
    bool valid = false;
};

/**
 * @brief The vendored Public Suffix List, loaded once per process.
 *
 * Thread-safe for concurrent lookups after loading. Loading is serialised internally and
 * is idempotent.
 */
class PublicSuffixList final {
public:
    [[nodiscard]] static PublicSuffixList& Instance() noexcept;

    PublicSuffixList(const PublicSuffixList&)            = delete;
    PublicSuffixList& operator=(const PublicSuffixList&) = delete;
    PublicSuffixList(PublicSuffixList&&)                 = delete;
    PublicSuffixList& operator=(PublicSuffixList&&)      = delete;

    /// @brief Loads the list from an explicit path. Idempotent; returns true if loaded.
    [[nodiscard]] bool LoadFromFile(const std::wstring& path) noexcept;

    /// @brief Loads from the shipped content directory. Idempotent.
    [[nodiscard]] bool EnsureLoaded() noexcept;

    [[nodiscard]] bool IsLoaded() const noexcept;

    /// @brief Total rule count, or 0 when not loaded.
    [[nodiscard]] std::size_t RuleCount() const noexcept;

    /// @brief ICANN-section rule count, so a caller can see the sections were separated.
    [[nodiscard]] std::size_t IcannRuleCount() const noexcept;

    /// @brief The list's own VERSION header, for field logs. Empty when not loaded.
    [[nodiscard]] std::string Version() const;

    /// @brief Decomposes a hostname. Never throws; returns valid == false on bad input.
    [[nodiscard]] DomainParts Decompose(std::string_view host, SuffixScope scope) const;

private:
    PublicSuffixList();
    ~PublicSuffixList();
    struct Impl;
    Impl* m_impl;
};

/// @brief The registrable domain of `host`, or empty when it has none.
/// @param scope MUST be chosen deliberately - see SuffixScope.
[[nodiscard]] std::string RegistrableDomain(std::string_view host, SuffixScope scope);

/// @brief The public suffix of `host`, or empty when it cannot be determined.
[[nodiscard]] std::string PublicSuffix(std::string_view host, SuffixScope scope);

/// @brief The labels left of the registrable domain - what a DGA or tunnel heuristic
///        should measure. Empty when the host has no subdomain.
[[nodiscard]] std::string Subdomain(std::string_view host, SuffixScope scope);

}  // namespace Domain
}  // namespace Utils
}  // namespace ShadowStrike
