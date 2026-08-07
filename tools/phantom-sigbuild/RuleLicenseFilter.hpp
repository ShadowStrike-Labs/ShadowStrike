// ============================================================================
//  ShadowStrike Phantom - Signature Builder
//  RuleLicenseFilter.hpp
//
//  Decides which rules of an aggregated YARA package may be redistributed, and
//  which this libyara build is actually able to compile.
//
//  Two separate questions are answered here, and they are reported separately
//  because they have different remedies:
//
//    1. Licensing. An aggregated package pulls from dozens of upstream
//       repositories under different terms. Some carry no licence grant at all,
//       and no licence means no permission to redistribute - that content cannot
//       ship regardless of how good the rules are.
//
//    2. Module availability. A rule referencing a YARA module this build lacks
//       cannot compile, and because the `import` statement sits in the package
//       preamble, ONE unavailable module fails the ENTIRE package rather than
//       just the rules that use it.
//
//  Nothing is ever dropped silently. Every exclusion is attributed to a source
//  and a reason so the caller can print it and so the attribution manifest can
//  be generated from the same data rather than maintained by hand.
//
//  Copyright (c) ShadowStrike-Labs. Licensed under AGPL-3.0.
// ============================================================================

#pragma once

#include <cstddef>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {
namespace SigBuild {

// ----------------------------------------------------------------------------
// One upstream repository's section within an aggregated package.
// ----------------------------------------------------------------------------
struct RuleSetSection {
    std::string repository;       ///< Upstream name, e.g. "Signature Base"
    std::string license;          ///< Resolved licence; empty when none found
    std::string licenseOrigin;    ///< Where the licence was read from
    std::size_t ruleCount{ 0 };   ///< Rules present in the section
    std::size_t rulesDropped{ 0 };///< Rules removed for module reasons
    bool        permitted{ false };///< May this section be redistributed
    std::string reason;           ///< Why it was included or excluded
};

// ----------------------------------------------------------------------------
// Outcome of filtering one rule source.
// ----------------------------------------------------------------------------
struct FilterReport {
    /// False when the input is not an aggregated package. In that case `source`
    /// is the input unchanged: a hand-written rule file is the author's own
    /// content and is never second-guessed here.
    bool isAggregatedPackage{ false };

    std::string source;                        ///< Source to hand to the compiler
    std::vector<RuleSetSection> sections;      ///< Every section, kept and dropped

    std::size_t rulesTotal{ 0 };
    std::size_t rulesKept{ 0 };
    std::size_t rulesDroppedNoLicense{ 0 };
    std::size_t rulesDroppedModule{ 0 };

    std::vector<std::string> importsRemoved;   ///< Modules this build cannot provide
};

// ----------------------------------------------------------------------------
// Filtering
// ----------------------------------------------------------------------------

/// @brief Filters an aggregated rule package by licence and module availability
/// @param source            Full rule source as read from disk
/// @param availableModules  Modules this libyara build can compile. Determined
///                          by probing rather than hardcoded, so the result
///                          self-corrects when the vendored library changes.
/// @return Report carrying the filtered source and every inclusion decision
/// @note A source that is not a recognised aggregated package passes through
///       untouched, so this is safe to apply unconditionally.
[[nodiscard]] FilterReport FilterRuleSource(
    std::string_view source,
    const std::set<std::string>& availableModules);

/// @brief Extracts the module names an `import` statement requests
/// @param source Rule source to scan
/// @return Distinct module names, in the order first seen
[[nodiscard]] std::vector<std::string> ExtractImportedModules(std::string_view source);

/// @brief Renders the third-party attribution manifest for a filtered package
/// @param report Result of FilterRuleSource
/// @return Markdown listing every included source, rule count and licence
/// @note CC BY-SA and the Detection Rule License both require attribution, so
///       this is a redistribution obligation and not documentation polish.
[[nodiscard]] std::string BuildAttributionManifest(const FilterReport& report);

} // namespace SigBuild
} // namespace ShadowStrike
