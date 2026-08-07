// ============================================================================
//  ShadowStrike Phantom - Signature Builder
//  RuleLicenseFilter.cpp
//
//  Implementation note: everything here scans linearly with find/compare rather
//  than std::regex. Aggregated packages run to tens of megabytes and std::regex
//  over that is pathologically slow, which would turn a 8 second build into
//  minutes for no benefit.
//
//  Copyright (c) ShadowStrike-Labs. Licensed under AGPL-3.0.
// ============================================================================

#include "RuleLicenseFilter.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace ShadowStrike {
namespace SigBuild {

namespace {

// Marker yara-forge writes once at the top of a generated package.
constexpr std::string_view kPackageMarker = "YARA-Forge YARA Rule Package";

// Marker that opens each upstream repository's section.
constexpr std::string_view kSectionMarker = "* YARA Rule Set";

// What an aggregator writes when it could not find a licence upstream.
constexpr std::string_view kNoLicense = "NO LICENSE SET";

[[nodiscard]] std::string Trim(std::string_view s) {
    const auto notSpace = [](unsigned char c) { return std::isspace(c) == 0; };
    auto begin = std::find_if(s.begin(), s.end(), notSpace);
    auto end = std::find_if(s.rbegin(), s.rend(), notSpace).base();
    return (begin < end) ? std::string(begin, end) : std::string{};
}

[[nodiscard]] std::string ToUpper(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return out;
}

[[nodiscard]] bool ContainsNoCase(std::string_view haystack, std::string_view needle) {
    return ToUpper(haystack).find(ToUpper(needle)) != std::string::npos;
}

// Returns the offset of the start of the line containing `pos`.
[[nodiscard]] std::size_t LineStart(std::string_view s, std::size_t pos) {
    const std::size_t nl = s.rfind('\n', pos);
    return (nl == std::string_view::npos) ? 0u : nl + 1u;
}

// True when a rule definition begins exactly at `pos`. YARA allows `private`
// and `global` qualifiers before the keyword.
[[nodiscard]] bool IsRuleStartAt(std::string_view s, std::size_t pos) {
    std::size_t p = pos;
    for (int qualifier = 0; qualifier < 2; ++qualifier) {
        for (std::string_view kw : { std::string_view("private"), std::string_view("global") }) {
            if (s.compare(p, kw.size(), kw) == 0 &&
                p + kw.size() < s.size() &&
                std::isspace(static_cast<unsigned char>(s[p + kw.size()])) != 0) {
                p += kw.size();
                while (p < s.size() && std::isspace(static_cast<unsigned char>(s[p])) != 0) {
                    ++p;
                }
                break;
            }
        }
    }
    if (s.compare(p, 4, "rule") != 0) {
        return false;
    }
    const std::size_t after = p + 4;
    return after < s.size() && std::isspace(static_cast<unsigned char>(s[after])) != 0;
}

// Offsets at which each rule in `block` begins.
[[nodiscard]] std::vector<std::size_t> FindRuleStarts(std::string_view block) {
    std::vector<std::size_t> starts;
    std::size_t pos = 0;
    while (pos < block.size()) {
        if ((pos == 0 || block[pos - 1] == '\n') && IsRuleStartAt(block, pos)) {
            starts.push_back(pos);
        }
        const std::size_t nl = block.find('\n', pos);
        if (nl == std::string_view::npos) {
            break;
        }
        pos = nl + 1;
    }
    return starts;
}

// Reads a `Field: value` line out of a section header comment.
[[nodiscard]] std::string HeaderField(std::string_view header, std::string_view field) {
    const std::size_t at = header.find(field);
    if (at == std::string_view::npos) {
        return {};
    }
    const std::size_t valueStart = at + field.size();
    const std::size_t lineEnd = header.find('\n', valueStart);
    return Trim(header.substr(valueStart,
        (lineEnd == std::string_view::npos) ? std::string_view::npos : lineEnd - valueStart));
}

// Pulls the licence text out of a section header. The aggregator writes the
// upstream LICENSE file verbatim after a bare "LICENSE" line, so this keeps only
// enough to identify it - the full text belongs in the manifest, not a log line.
[[nodiscard]] std::string HeaderLicense(std::string_view header) {
    const std::size_t at = header.find("LICENSE");
    if (at == std::string_view::npos) {
        return {};
    }
    std::string text = Trim(header.substr(at + 7));

    // Strip comment decoration so identification is not defeated by '*' prefixes.
    std::string flat;
    flat.reserve(text.size());
    bool lastWasSpace = false;
    for (const char c : text) {
        const char ch = (c == '\r' || c == '\n' || c == '\t') ? ' ' : c;
        if (ch == '*' && (flat.empty() || lastWasSpace)) {
            continue;
        }
        if (ch == ' ') {
            if (lastWasSpace) {
                continue;
            }
            lastWasSpace = true;
        } else {
            lastWasSpace = false;
        }
        flat.push_back(ch);
    }
    return Trim(flat);
}

// Maps licence text onto a short identifier.
//
// Selection is by EARLIEST match, not by the order of this table. A licence file
// routinely mentions other licences in passing - GPL-licensed projects discuss
// Apache compatibility, permissive files cite their own SPDX aliases - so
// first-match-wins over the whole text mislabels them. CAPE is the concrete
// case: its GPLv3 text was being reported as Apache-2.0. A licence file
// announces itself at the top, so the marker appearing first is the real one,
// and mislabelling matters here because this feeds a compliance document.
//
// Recognition stays conservative: an unrecognised licence yields an empty
// string so it surfaces for review rather than being waved through as
// permissive.
[[nodiscard]] std::string IdentifyLicense(std::string_view text) {
    struct Known { std::string_view needle; std::string_view name; };
    static constexpr std::array<Known, 15> kKnown{ {
        { "GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL" },
        { "GNU GENERAL PUBLIC LICENSE",        "GPL" },
        { "GNU LESSER GENERAL PUBLIC LICENSE", "LGPL" },
        { "Detection Rule License",            "DRL 1.1" },
        { "DRL-1.1",                           "DRL 1.1" },
        { "Apache License",                    "Apache-2.0" },
        { "MIT License",                       "MIT" },
        { "The 3-Clause BSD License",          "BSD-3-Clause" },
        { "BSD 3-Clause",                      "BSD-3-Clause" },
        { "BSD-3-Clause",                      "BSD-3-Clause" },
        { "The 2-Clause BSD License",          "BSD-2-Clause" },
        { "BSD 2-Clause",                      "BSD-2-Clause" },
        { "BSD-2-Clause",                      "BSD-2-Clause" },
        { "CC BY-SA 4.0",                      "CC BY-SA 4.0" },
        { "CC BY 4.0",                         "CC BY 4.0" },
    } };

    const std::string upper = ToUpper(text);
    std::size_t bestAt = std::string::npos;
    std::string_view bestName;

    for (const auto& k : kKnown) {
        const std::size_t at = upper.find(ToUpper(k.needle));
        if (at == std::string::npos) {
            continue;
        }
        // Strictly earlier wins. On a tie the earlier table entry wins, which is
        // why the copyleft family is listed first: "GNU GENERAL PUBLIC LICENSE"
        // and a nested mention starting at the same offset should resolve to the
        // more restrictive reading.
        if (bestAt == std::string::npos || at < bestAt) {
            bestAt = at;
            bestName = k.name;
        }
    }
    if (!bestName.empty()) {
        return std::string(bestName);
    }

    // No named licence, but an explicit grant still conveys rights. Name these
    // by their own wording so a human can confirm what they are.
    if (ContainsNoCase(text, "Permission is hereby granted")) {
        return "permissive, unnamed (MIT/ISC-style grant)";
    }
    if (ContainsNoCase(text, "Redistribution and use")) {
        return "permissive, unnamed (BSD-style grant)";
    }
    return {};
}

// Some upstreams carry their licence in per-rule metadata rather than a LICENSE
// file the aggregator can find. Malpedia is the significant case: its section
// header says NO LICENSE SET while every rule declares
// malpedia_license = "CC BY-SA 4.0". Excluding on the header alone would discard
// over a thousand rules that are in fact licensed for commercial use.
[[nodiscard]] std::string LicenseFromRuleMetadata(std::string_view block) {
    std::size_t pos = 0;
    while (pos < block.size()) {
        const std::size_t at = block.find("license", pos);
        if (at == std::string_view::npos) {
            break;
        }
        // Must be a metadata assignment: <name>license... = "value"
        const std::size_t eq = block.find('=', at);
        const std::size_t nl = block.find('\n', at);
        if (eq == std::string_view::npos || (nl != std::string_view::npos && eq > nl)) {
            pos = at + 7;
            continue;
        }
        const std::size_t q1 = block.find('"', eq);
        if (q1 == std::string_view::npos || (nl != std::string_view::npos && q1 > nl)) {
            pos = at + 7;
            continue;
        }
        const std::size_t q2 = block.find('"', q1 + 1);
        if (q2 == std::string_view::npos) {
            break;
        }
        const std::string value = Trim(block.substr(q1 + 1, q2 - q1 - 1));

        // "N/A" and a bare URL are not grants of rights.
        const bool isUrlField = block.compare(at, 11, "license_url") == 0;
        if (!value.empty() && value != "N/A" && !isUrlField) {
            const std::string named = IdentifyLicense(value);
            return named.empty() ? value : named;
        }
        pos = q2 + 1;
    }
    return {};
}

// True when `rule` references `module` as a YARA module identifier.
//
// A plain substring search is wrong here: "self." contains "elf.", so scanning
// for the bare name silently discards unrelated rules - exactly the quiet
// coverage loss this filter exists to prevent. The name must start an
// identifier, so the preceding character cannot itself be part of one.
[[nodiscard]] bool ReferencesModule(std::string_view rule, std::string_view module) {
    const std::string needle = std::string(module) + ".";
    std::size_t pos = 0;
    while ((pos = rule.find(needle, pos)) != std::string_view::npos) {
        const bool atStart = (pos == 0);
        const char prev = atStart ? '\0' : rule[pos - 1];
        const bool prevIsIdent =
            !atStart && (std::isalnum(static_cast<unsigned char>(prev)) != 0 || prev == '_');
        if (!prevIsIdent) {
            return true;
        }
        pos += needle.size();
    }
    return false;
}

} // namespace

// ----------------------------------------------------------------------------

std::vector<std::string> ExtractImportedModules(std::string_view source) {
    std::vector<std::string> modules;
    std::size_t pos = 0;
    while (pos < source.size()) {
        const std::size_t at = source.find("import", pos);
        if (at == std::string_view::npos) {
            break;
        }
        // Only a statement at the start of a line counts; the word appears in
        // rule bodies and comments too.
        if (at != LineStart(source, at)) {
            pos = at + 6;
            continue;
        }
        const std::size_t q1 = source.find('"', at);
        const std::size_t nl = source.find('\n', at);
        if (q1 == std::string_view::npos || (nl != std::string_view::npos && q1 > nl)) {
            pos = at + 6;
            continue;
        }
        const std::size_t q2 = source.find('"', q1 + 1);
        if (q2 == std::string_view::npos) {
            break;
        }
        std::string name = Trim(source.substr(q1 + 1, q2 - q1 - 1));
        if (!name.empty() &&
            std::find(modules.begin(), modules.end(), name) == modules.end()) {
            modules.push_back(std::move(name));
        }
        pos = q2 + 1;
    }
    return modules;
}

// ----------------------------------------------------------------------------

FilterReport FilterRuleSource(std::string_view source,
                              const std::set<std::string>& availableModules) {
    FilterReport report;

    // A hand-written rule file is the author's own content. Only aggregated
    // packages carry third-party sections that need a licence decision.
    if (source.find(kPackageMarker) == std::string_view::npos) {
        report.isAggregatedPackage = false;
        report.source.assign(source);
        report.rulesTotal = FindRuleStarts(source).size();
        report.rulesKept = report.rulesTotal;
        return report;
    }
    report.isAggregatedPackage = true;

    // Which imported modules this build cannot satisfy.
    std::vector<std::string> unavailable;
    for (const auto& m : ExtractImportedModules(source)) {
        if (availableModules.find(m) == availableModules.end()) {
            unavailable.push_back(m);
        }
    }
    report.importsRemoved = unavailable;

    // Preamble is everything before the first repository section: the package
    // banner plus the import statements every section relies on.
    const std::size_t firstSection = source.find(kSectionMarker);
    const std::size_t preambleEnd =
        (firstSection == std::string_view::npos) ? source.size()
                                                 : LineStart(source, firstSection);

    std::string out;
    out.reserve(source.size());

    // Copy the preamble, dropping imports this build cannot provide.
    {
        std::string_view preamble = source.substr(0, preambleEnd);
        std::size_t line = 0;
        while (line < preamble.size()) {
            const std::size_t nl = preamble.find('\n', line);
            const std::size_t len =
                (nl == std::string_view::npos) ? preamble.size() - line : nl - line + 1;
            std::string_view text = preamble.substr(line, len);

            bool skip = false;
            for (const auto& m : unavailable) {
                if (text.find("import") != std::string_view::npos &&
                    text.find('"' + m + '"') != std::string_view::npos) {
                    skip = true;
                    break;
                }
            }
            if (!skip) {
                out.append(text);
            }
            if (nl == std::string_view::npos) {
                break;
            }
            line = nl + 1;
        }
    }

    // Walk the repository sections.
    std::size_t cursor = preambleEnd;
    while (cursor < source.size()) {
        const std::size_t marker = source.find(kSectionMarker, cursor);
        if (marker == std::string_view::npos) {
            break;
        }
        // The section comment opens a little before the marker line.
        std::size_t sectionStart = source.rfind("/*", marker);
        if (sectionStart == std::string_view::npos || sectionStart < cursor) {
            sectionStart = LineStart(source, marker);
        }
        const std::size_t headerEnd = source.find("*/", marker);
        if (headerEnd == std::string_view::npos) {
            break;
        }
        const std::size_t nextMarker = source.find(kSectionMarker, headerEnd);
        std::size_t sectionEnd = source.size();
        if (nextMarker != std::string_view::npos) {
            const std::size_t nextStart = source.rfind("/*", nextMarker);
            sectionEnd = (nextStart == std::string_view::npos || nextStart <= headerEnd)
                             ? LineStart(source, nextMarker)
                             : nextStart;
        }

        std::string_view header = source.substr(sectionStart, headerEnd + 2 - sectionStart);
        std::string_view body = source.substr(headerEnd + 2, sectionEnd - (headerEnd + 2));

        RuleSetSection section;
        section.repository = HeaderField(header, "Repository Name:");
        if (section.repository.empty()) {
            section.repository = "(unnamed)";
        }

        const auto ruleStarts = FindRuleStarts(body);
        section.ruleCount = ruleStarts.size();
        report.rulesTotal += section.ruleCount;

        // Resolve the licence: section header first, per-rule metadata second.
        const std::string headerText = HeaderLicense(header);
        if (!headerText.empty() && !ContainsNoCase(headerText, kNoLicense)) {
            section.license = IdentifyLicense(headerText);
            section.licenseOrigin = "section header";
        }
        if (section.license.empty()) {
            section.license = LicenseFromRuleMetadata(body);
            if (!section.license.empty()) {
                section.licenseOrigin = "rule metadata";
            }
        }

        if (section.license.empty()) {
            section.permitted = false;
            section.reason = "no licence grant found in the section header or rule metadata";
            report.rulesDroppedNoLicense += section.ruleCount;
        } else {
            section.permitted = true;
            section.reason = "licensed for redistribution";

            // Emit the section, dropping rules that need an unavailable module.
            std::string kept;
            kept.reserve(body.size());
            if (unavailable.empty() || ruleStarts.empty()) {
                kept.assign(body);
            } else {
                // Text before the first rule (the section's own comments).
                kept.append(body.substr(0, ruleStarts.empty() ? body.size() : ruleStarts.front()));
                for (std::size_t i = 0; i < ruleStarts.size(); ++i) {
                    const std::size_t begin = ruleStarts[i];
                    const std::size_t end = (i + 1 < ruleStarts.size()) ? ruleStarts[i + 1]
                                                                        : body.size();
                    std::string_view rule = body.substr(begin, end - begin);

                    bool needsMissing = false;
                    for (const auto& m : unavailable) {
                        if (ReferencesModule(rule, m)) {
                            needsMissing = true;
                            break;
                        }
                    }
                    if (needsMissing) {
                        ++section.rulesDropped;
                        ++report.rulesDroppedModule;
                    } else {
                        kept.append(rule);
                    }
                }
            }
            out.append(header);
            out.append(kept);
            report.rulesKept += (section.ruleCount - section.rulesDropped);
        }

        report.sections.push_back(std::move(section));
        cursor = sectionEnd;
    }

    report.source = std::move(out);
    return report;
}

// ----------------------------------------------------------------------------

std::string BuildAttributionManifest(const FilterReport& report) {
    std::string md;
    md.reserve(8192);

    md += "# Third-Party Detection Rules\n\n";
    md += "ShadowStrike Phantom ships YARA rules aggregated from independent\n";
    md += "research repositories. Each retains its own licence and the attribution\n";
    md += "below is a condition of redistributing it - the Detection Rule License\n";
    md += "and CC BY-SA both require credit.\n\n";
    md += "This file is generated by `phantom-sigbuild` from the rule package\n";
    md += "itself. Do not edit it by hand; rebuild the signature database instead.\n\n";

    md += "## Included sources\n\n";
    md += "| Source | Rules | Licence | Licence read from |\n";
    md += "|---|---:|---|---|\n";
    for (const auto& s : report.sections) {
        if (!s.permitted) {
            continue;
        }
        md += "| " + s.repository + " | " + std::to_string(s.ruleCount - s.rulesDropped) +
              " | " + s.license + " | " + s.licenseOrigin + " |\n";
    }

    bool anyExcluded = false;
    for (const auto& s : report.sections) {
        if (!s.permitted) {
            anyExcluded = true;
            break;
        }
    }
    if (anyExcluded) {
        md += "\n## Excluded sources\n\n";
        md += "Excluded because no licence grant could be established. Absence of a\n";
        md += "licence is not permission, so these rules are not redistributed even\n";
        md += "though they are present in the upstream package. Recovering them means\n";
        md += "obtaining an explicit grant from the author.\n\n";
        md += "| Source | Rules withheld | Reason |\n";
        md += "|---|---:|---|\n";
        for (const auto& s : report.sections) {
            if (s.permitted) {
                continue;
            }
            md += "| " + s.repository + " | " + std::to_string(s.ruleCount) +
                  " | " + s.reason + " |\n";
        }
    }

    // Copyleft sources are compatible with this project but a reader who finds
    // GPL in a compliance manifest deserves to know why it is acceptable rather
    // than having to work it out.
    bool anyCopyleft = false;
    for (const auto& s : report.sections) {
        if (s.permitted && (s.license == "GPL" || s.license == "AGPL" || s.license == "LGPL")) {
            anyCopyleft = true;
            break;
        }
    }
    if (anyCopyleft) {
        md += "\n## Copyleft sources\n\n";
        md += "Some included rule sets are under the GNU General Public License.\n";
        md += "ShadowStrike Phantom is itself AGPL-3.0, so this is compatible and\n";
        md += "requires no separate action. It would be a problem only for a\n";
        md += "proprietary redistribution of these rules, which this project does\n";
        md += "not perform.\n";
    }

    if (!report.importsRemoved.empty()) {
        md += "\n## Rules withheld for missing YARA modules\n\n";
        md += "This build of libyara does not provide the following modules, so rules\n";
        md += "depending on them cannot be compiled. This is a build capability gap,\n";
        md += "not a licensing one - see `vendor/yara_lib/README.md`.\n\n";
        for (const auto& m : report.importsRemoved) {
            md += "- `" + m + "`\n";
        }
        md += "\nRules withheld on this basis: " +
              std::to_string(report.rulesDroppedModule) + "\n";
    }

    md += "\n## Totals\n\n";
    md += "- Rules in package: " + std::to_string(report.rulesTotal) + "\n";
    md += "- Rules included: " + std::to_string(report.rulesKept) + "\n";
    md += "- Withheld, unlicensed: " + std::to_string(report.rulesDroppedNoLicense) + "\n";
    md += "- Withheld, missing module: " + std::to_string(report.rulesDroppedModule) + "\n";

    return md;
}

} // namespace SigBuild
} // namespace ShadowStrike
