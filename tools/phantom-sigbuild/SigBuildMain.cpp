// ============================================================================
//  phantom-sigbuild - offline detection content compiler
// ----------------------------------------------------------------------------
//  SignatureBuilder is 9,833 lines across six translation units, with seven
//  working import paths and, until this file existed, zero callers anywhere in
//  the tree. Nothing had ever fed it, which is why signatures.sdb does not
//  exist on a deployed machine and why SignatureStore, PatternStore, HashStore
//  and YaraRuleStore all report initialisation failures in the field log: the
//  engine that consumes content was complete and the content was never built.
//
//  This is the missing entry point. It runs offline, on a build machine, and
//  emits the hardened database the product memory-maps at runtime.
//
//  It deliberately does two things beyond compiling:
//
//    * it fails loudly. An import that matches nothing, or a build that emits
//      an empty index, is an error and not a warning, because the failure mode
//      this whole subsystem actually suffered was silence.
//
//    * it verifies its own output by reopening the finished database through
//      SignatureStore and asserting the counts are non-zero. Producing a file
//      the runtime cannot load is the exact defect that hid here for so long,
//      so the tool refuses to report success without proving the runtime path.
// ============================================================================

#include "../../src/PhantomCore/SignatureStore/SignatureBuilder.hpp"
#include "../../src/PhantomCore/SignatureStore/SignatureStore.hpp"
#include "../../src/PhantomCore/SignatureStore/YaraRuleStore.hpp"   // YaraUtils::ValidateRuleSyntax
#include "../../src/PhantomCore/Whitelist/WhiteListStore.hpp"   // whitelist.wdb output
#include "RuleLicenseFilter.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using ShadowStrike::SignatureStore::SignatureBuilder;
using ShadowStrike::SignatureStore::BuildConfiguration;
using ShadowStrike::SignatureStore::StoreError;

namespace {

// ---------------------------------------------------------------------------
// Console helpers. Plain ASCII: this runs in build pipelines and CI consoles
// where code pages are not worth assuming.
// ---------------------------------------------------------------------------

void Info(const char* fmt, ...) noexcept {
    va_list a;
    va_start(a, fmt);
    std::vprintf(fmt, a);
    va_end(a);
    std::printf("\n");
}

void Fail(const char* fmt, ...) noexcept {
    std::fprintf(stderr, "ERROR: ");
    va_list a;
    va_start(a, fmt);
    std::vfprintf(stderr, fmt, a);
    va_end(a);
    std::fprintf(stderr, "\n");
}

[[nodiscard]] std::string Narrow(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

// Mirror of Narrow. Content files are UTF-8 on disk, and a description that came
// from one has to be widened before it can go into the store's wide-string API.
[[nodiscard]] std::wstring Widen(const std::string& s) {
    if (s.empty()) {
        return {};
    }
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                        nullptr, 0);
    if (n <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          out.data(), n);
    return out;
}

// Renders a StoreError so a failure names itself instead of returning a number.
[[nodiscard]] std::string Describe(const StoreError& e) {
    std::string s = "code=" + std::to_string(static_cast<int>(e.code));
    if (e.win32Error != 0) {
        s += " win32=" + std::to_string(e.win32Error);
    }
    if (!e.message.empty()) {
        s += " (" + e.message + ")";
    }
    return s;
}

void Usage() {
    std::printf(
        "phantom-sigbuild - compile detection content into a signature database\n"
        "\n"
        "Usage:\n"
        "  phantom-sigbuild --out <database.sdb> [inputs...] [options]\n"
        "\n"
        "Inputs (repeatable):\n"
        "  --hashes <file>      hashes as TYPE:HASH:NAME:LEVEL, one per line\n"
        "  --hashes-csv <file>  hashes as CSV\n"
        "  --patterns <file>    byte or string patterns, one per line\n"
        "  --yara <file>        a single YARA rule file\n"
        "  --yara-dir <dir>     a directory of YARA rules, searched recursively\n"
        "  --content <dir>      convention: <dir>/hashes, <dir>/patterns,\n"
        "                       <dir>/yara, <dir>/whitelist\n"
        "\n"
        "Whitelist (a SEPARATE database with the OPPOSITE meaning):\n"
        "  --whitelist <file>   known-good hashes as TYPE:HASH[:DESCRIPTION]\n"
        "  --whitelist-out <f>  write whitelist.wdb here (required with the above)\n"
        "\n"
        "  Entries under --hashes are DETECTIONS: each carries a threat level and\n"
        "  matching one convicts a file. Entries under --whitelist are ALLOW\n"
        "  decisions that let a file skip deeper analysis. Placing a known-good\n"
        "  corpus in --hashes would report all of Windows as malware; placing a\n"
        "  malware corpus in --whitelist would make it invisible. The two formats\n"
        "  differ so that a misplaced file is rejected instead of inverting the\n"
        "  product's behaviour - whitelist lines carry no threat level, and one\n"
        "  that does is a hard error.\n"
        "\n"
        "Options:\n"
        "  --overwrite          replace an existing database\n"
        "  --size-mb <n>        initial database size, default 64\n"
        "  --namespace <name>   YARA namespace, default \"default\"\n"
        "  --no-verify          skip reopening the output to prove it loads\n"
        "  --quiet              suppress per-stage progress\n"
        "\n"
        "Exit codes: 0 success, 1 usage, 2 import failed, 3 build failed,\n"
        "            4 output did not verify, 5 whitelist build failed\n");
}

struct Options {
    std::wstring              output;
    std::vector<std::wstring> hashFiles;
    std::vector<std::wstring> hashCsvFiles;
    std::vector<std::wstring> patternFiles;
    std::vector<std::wstring> yaraFiles;
    std::vector<std::wstring> yaraDirs;
    std::wstring              whitelistOutput;   // empty => no whitelist is built
    std::vector<std::wstring> whitelistFiles;
    std::string               yaraNamespace{ "default" };
    std::uint64_t             sizeMb{ 64 };
    bool                      overwrite{ false };
    bool                      verify{ true };
    std::wstring              attribution;   // empty => beside the output database
    bool                      quiet{ false };
};

// Expands --content into the individual input lists. Kept a convention rather
// than a manifest format so the content tree is self-describing on disk.
//
// NOTE ON hashes/ VERSUS whitelist/: these two directories have OPPOSITE
// meanings and must never be conflated. Everything under hashes/ becomes a
// DETECTION - each entry carries a threat level and matching it convicts a
// file. Everything under whitelist/ becomes an ALLOW decision that causes a
// file to skip deeper analysis. Putting a known-good corpus such as the NIST
// NSRL under hashes/ would make the product report all of Windows as malware;
// putting a malware corpus under whitelist/ would make that malware invisible.
// Both are catastrophic and neither is obvious from a directory listing, which
// is why the two use different line formats and why ParseWhitelistLine rejects
// anything carrying a threat level.
void ExpandContentDirectory(const fs::path& root, Options& opt) {
    const auto collect = [](const fs::path& dir,
                            std::vector<std::wstring>& into,
                            std::initializer_list<const wchar_t*> extensions) {
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) {
            return;
        }
        for (const auto& entry : fs::recursive_directory_iterator(dir, ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_regular_file(ec)) {
                continue;
            }
            std::wstring ext = entry.path().extension().wstring();
            for (auto& c : ext) {
                c = static_cast<wchar_t>(::towlower(c));
            }
            for (const wchar_t* want : extensions) {
                if (ext == want) {
                    into.push_back(entry.path().wstring());
                    break;
                }
            }
        }
    };

    collect(root / "hashes",    opt.hashFiles,      { L".txt", L".hashes" });
    collect(root / "hashes",    opt.hashCsvFiles,   { L".csv" });
    collect(root / "patterns",  opt.patternFiles,   { L".txt", L".patterns" });
    collect(root / "yara",      opt.yaraFiles,      { L".yar", L".yara" });
    collect(root / "whitelist", opt.whitelistFiles, { L".txt", L".whitelist" });
}

// Which YARA modules the libyara we link can actually compile. Probed rather
// than hardcoded, so this self-corrects when the vendored library changes
// instead of drifting into a lie. See vendor/yara_lib/README.md.
[[nodiscard]] std::set<std::string> ProbeAvailableModules(
    const std::vector<std::string>& candidates) {
    std::set<std::string> available;
    for (const auto& m : candidates) {
        const std::string probe = "import \"" + m + "\"\nrule probe { condition: false }\n";
        std::vector<std::string> errors;
        if (ShadowStrike::SignatureStore::YaraUtils::ValidateRuleSyntax(probe, errors)) {
            available.insert(m);
        }
    }
    return available;
}

// Imports one YARA source, withholding anything we may not redistribute and
// anything this build cannot compile. Both are reported: content that vanishes
// quietly is indistinguishable from content that was never there, which is the
// failure mode this whole tool exists to avoid.
[[nodiscard]] bool ImportYaraWithLicenseFilter(SignatureBuilder& builder,
                                              const std::wstring& path,
                                              const Options& opt) {
    std::string source;
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            Fail("yara: cannot open '%ls'", path.c_str());
            return false;
        }
        in.seekg(0, std::ios::end);
        const std::streamoff size = in.tellg();
        if (size <= 0) {
            Fail("yara: '%ls' is empty", path.c_str());
            return false;
        }
        in.seekg(0, std::ios::beg);
        source.resize(static_cast<std::size_t>(size));
        in.read(source.data(), size);
        source.resize(static_cast<std::size_t>(in.gcount()));
    }

    const auto imported = ShadowStrike::SigBuild::ExtractImportedModules(source);
    const auto available = ProbeAvailableModules(imported);
    const auto report = ShadowStrike::SigBuild::FilterRuleSource(source, available);

    if (!report.isAggregatedPackage) {
        // A hand-written file is the author's own content; import it unchanged.
        const StoreError e = builder.ImportYaraRulesFromFile(path, opt.yaraNamespace);
        if (!e.IsSuccess()) {
            Fail("yara failed for '%ls': %s", path.c_str(), Describe(e).c_str());
            return false;
        }
        Info("  imported   : %-11s %ls", "yara", path.c_str());
        return true;
    }

    Info("  yara pack  : %ls", path.c_str());
    Info("    sources  : %zu upstream repositories", report.sections.size());

    for (const auto& s : report.sections) {
        if (!s.permitted) {
            Info("    WITHHELD  : %-22s %5zu rules  (%s)",
                 s.repository.c_str(), s.ruleCount, s.reason.c_str());
        } else if (s.rulesDropped > 0) {
            Info("    included  : %-22s %5zu rules  [%s]  (-%zu need a missing module)",
                 s.repository.c_str(), s.ruleCount - s.rulesDropped,
                 s.license.c_str(), s.rulesDropped);
        }
    }
    if (!report.importsRemoved.empty()) {
        std::string joined;
        for (const auto& m : report.importsRemoved) {
            joined += (joined.empty() ? "" : ", ") + m;
        }
        Info("    no module : %s  (this libyara build lacks it)", joined.c_str());
    }
    Info("    rules     : %zu of %zu kept, %zu unlicensed, %zu missing-module",
         report.rulesKept, report.rulesTotal,
         report.rulesDroppedNoLicense, report.rulesDroppedModule);

    if (report.rulesKept == 0) {
        Fail("yara: every rule in '%ls' was withheld - refusing to build an empty rule set",
             path.c_str());
        return false;
    }

    ShadowStrike::SignatureStore::YaraRuleInput input;
    input.ruleSource = report.source;
    input.namespace_ = opt.yaraNamespace;
    input.source = Narrow(path);

    const StoreError e = builder.AddYaraRule(input);
    if (!e.IsSuccess()) {
        Fail("yara failed for '%ls': %s", path.c_str(), Describe(e).c_str());
        return false;
    }

    // Attribution is a redistribution condition of DRL and CC BY-SA, so write it
    // beside the database that carries the rules rather than leaving it to a
    // human to remember.
    const fs::path manifest = opt.attribution.empty()
        ? (fs::path(opt.output).parent_path() / L"THIRD-PARTY-RULES.md")
        : fs::path(opt.attribution);
    std::error_code ec;
    if (!manifest.parent_path().empty()) {
        fs::create_directories(manifest.parent_path(), ec);
    }
    std::ofstream out(manifest, std::ios::binary | std::ios::trunc);
    if (!out) {
        Fail("yara: cannot write the attribution manifest to '%ls'", manifest.c_str());
        return false;
    }
    const std::string md = ShadowStrike::SigBuild::BuildAttributionManifest(report);
    out.write(md.data(), static_cast<std::streamsize>(md.size()));
    if (!out) {
        Fail("yara: failed writing the attribution manifest");
        return false;
    }
    Info("    attribution: %ls", manifest.c_str());
    return true;
}

[[nodiscard]] bool ParseArgs(int argc, wchar_t** argv, Options& opt) {
    const auto needValue = [&](int i) -> bool {
        if (i + 1 >= argc) {
            Fail("%ls requires a value", argv[i]);
            return false;
        }
        return true;
    };

    for (int i = 1; i < argc; ++i) {
        const std::wstring a = argv[i];

        if (a == L"--help" || a == L"-h" || a == L"/?") {
            Usage();
            return false;
        } else if (a == L"--out") {
            if (!needValue(i)) { return false; }
            opt.output = argv[++i];
        } else if (a == L"--hashes") {
            if (!needValue(i)) { return false; }
            opt.hashFiles.emplace_back(argv[++i]);
        } else if (a == L"--hashes-csv") {
            if (!needValue(i)) { return false; }
            opt.hashCsvFiles.emplace_back(argv[++i]);
        } else if (a == L"--patterns") {
            if (!needValue(i)) { return false; }
            opt.patternFiles.emplace_back(argv[++i]);
        } else if (a == L"--yara") {
            if (!needValue(i)) { return false; }
            opt.yaraFiles.emplace_back(argv[++i]);
        } else if (a == L"--yara-dir") {
            if (!needValue(i)) { return false; }
            opt.yaraDirs.emplace_back(argv[++i]);
        } else if (a == L"--content") {
            if (!needValue(i)) { return false; }
            ExpandContentDirectory(fs::path(argv[++i]), opt);
        } else if (a == L"--whitelist") {
            if (!needValue(i)) { return false; }
            opt.whitelistFiles.emplace_back(argv[++i]);
        } else if (a == L"--whitelist-out") {
            if (!needValue(i)) { return false; }
            opt.whitelistOutput = argv[++i];
        } else if (a == L"--namespace") {
            if (!needValue(i)) { return false; }
            opt.yaraNamespace = Narrow(argv[++i]);
        } else if (a == L"--attribution") {
            if (!needValue(i)) { return false; }
            opt.attribution = argv[++i];
        } else if (a == L"--size-mb") {
            if (!needValue(i)) { return false; }
            opt.sizeMb = std::wcstoull(argv[++i], nullptr, 10);
        } else if (a == L"--overwrite") {
            opt.overwrite = true;
        } else if (a == L"--no-verify") {
            opt.verify = false;
        } else if (a == L"--quiet") {
            opt.quiet = true;
        } else {
            Fail("unrecognised argument: %ls", a.c_str());
            return false;
        }
    }

    if (opt.output.empty()) {
        Fail("--out is required");
        return false;
    }
    if (opt.sizeMb == 0 || opt.sizeMb > 4096) {
        Fail("--size-mb must be between 1 and 4096");
        return false;
    }

    const bool haveInput =
        !opt.hashFiles.empty() || !opt.hashCsvFiles.empty() ||
        !opt.patternFiles.empty() || !opt.yaraFiles.empty() || !opt.yaraDirs.empty();
    if (!haveInput) {
        Fail("no inputs given - nothing to build. An empty database is exactly "
             "the failure this tool exists to prevent.");
        return false;
    }

    // Whitelist inputs and a whitelist output are meaningless apart, and either
    // one alone is a mistake worth stopping for rather than guessing around.
    if (!opt.whitelistFiles.empty() && opt.whitelistOutput.empty()) {
        Fail("%zu whitelist input file(s) were found but --whitelist-out was not "
             "given, so they would be silently discarded. Known-good content that "
             "is dropped without a word is how a whitelist ends up trusting "
             "nothing while appearing to be configured.",
             opt.whitelistFiles.size());
        return false;
    }
    if (!opt.whitelistOutput.empty() && opt.whitelistFiles.empty()) {
        Fail("--whitelist-out was given but no whitelist input was found. Writing "
             "an empty whitelist would produce a database that grants no trust "
             "while looking present, so nothing is written. Add entries under "
             "<content>/whitelist or pass --whitelist <file>.");
        return false;
    }
    if (!opt.whitelistOutput.empty() && opt.whitelistOutput == opt.output) {
        Fail("--whitelist-out and --out are the same path. These are two different "
             "databases with opposite meanings and cannot share a file.");
        return false;
    }
    return true;
}

// ============================================================================
// WHITELIST DATABASE
//
// The whitelist is a separate database (whitelist.wdb) with the opposite meaning
// to the signature database: an entry here is an ALLOW decision that lets a file
// skip deeper analysis. It gets its own output path rather than a section inside
// signatures.sdb because the runtime opens them as two stores with two different
// trust postures - WhitelistStore is refused entirely unless the data directory
// is write-restricted, precisely because an attacker who can add an entry becomes
// invisible.
//
// LINE FORMAT, deliberately different from the malware hash format:
//     TYPE:HASH[:DESCRIPTION]
//   TYPE        MD5 | SHA1 | SHA256 | SHA512
//   HASH        hex, length must match the algorithm
//   DESCRIPTION optional free text for the audit trail
//   '#' starts a comment; blank lines are ignored.
//
// The malware format is TYPE:HASH:NAME:LEVEL, where LEVEL is a threat level. A
// whitelist entry has no threat level because it is not a threat, and that
// difference is load-bearing: it is what lets a file dropped into the wrong
// directory be detected instead of silently inverting the product's behaviour.
// ============================================================================

// Maps a hash type keyword to its algorithm and expected hex length. Returning
// the length matters: a SHA1 value pasted under an MD5 label would otherwise be
// truncated into a hash that matches nothing, which is a silent whitelist miss.
[[nodiscard]] bool ResolveWhitelistHashType(const std::string& keyword,
                                           ShadowStrike::Whitelist::HashAlgorithm& algo,
                                           std::size_t& hexLength) {
    using ShadowStrike::Whitelist::HashAlgorithm;
    if (keyword == "MD5")    { algo = HashAlgorithm::MD5;    hexLength = 32;  return true; }
    if (keyword == "SHA1")   { algo = HashAlgorithm::SHA1;   hexLength = 40;  return true; }
    if (keyword == "SHA256") { algo = HashAlgorithm::SHA256; hexLength = 64;  return true; }
    if (keyword == "SHA512") { algo = HashAlgorithm::SHA512; hexLength = 128; return true; }
    return false;
}

[[nodiscard]] bool LooksLikeThreatLevel(const std::string& field) {
    return field == "Info" || field == "Low" || field == "Medium" ||
           field == "High" || field == "Critical";
}

struct WhitelistLine {
    ShadowStrike::Whitelist::HashAlgorithm algorithm{};
    std::string                            hash;
    std::wstring                           description;
};

// Parses one line. `error` is set with something a human can act on, because a
// content file that is quietly half-ignored is the failure mode this tool exists
// to prevent.
[[nodiscard]] bool ParseWhitelistLine(const std::string& raw,
                                      WhitelistLine& out,
                                      std::string& error) {
    std::string line = raw;
    if (const auto hash = line.find('#'); hash != std::string::npos) {
        line.erase(hash);
    }
    // Trim
    const auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    line.erase(line.begin(), std::find_if(line.begin(), line.end(), notSpace));
    line.erase(std::find_if(line.rbegin(), line.rend(), notSpace).base(), line.end());
    if (line.empty()) {
        return false;   // blank or comment-only: not an error, just nothing
    }

    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
        const std::size_t colon = line.find(':', start);
        if (colon == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, colon - start));
        start = colon + 1;
    }

    if (fields.size() < 2) {
        error = "expected TYPE:HASH[:DESCRIPTION]";
        return false;
    }

    // THE GUARD. A four-field line whose last field is a threat level is a
    // malware hash entry, which means a detection corpus has been placed in the
    // whitelist tree. Accepting it would make every listed sample invisible to
    // the engine - the single worst outcome this tool can produce - so it is a
    // hard error naming the likely mistake rather than a warning.
    if (fields.size() >= 4 && LooksLikeThreatLevel(fields.back())) {
        error = "line carries a threat level ('" + fields.back() +
                "'), so this is malware hash content in TYPE:HASH:NAME:LEVEL form. "
                "It belongs under content/hashes, not content/whitelist - "
                "whitelisting it would make those samples invisible to the engine";
        return false;
    }

    std::string type = fields[0];
    for (auto& c : type) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }

    std::size_t expectedHexLength = 0;
    if (!ResolveWhitelistHashType(type, out.algorithm, expectedHexLength)) {
        error = "unknown hash type '" + fields[0] + "' (expected MD5, SHA1, SHA256 or SHA512)";
        return false;
    }

    out.hash = fields[1];
    if (out.hash.size() != expectedHexLength) {
        error = type + " requires " + std::to_string(expectedHexLength) +
                " hex characters but this value has " + std::to_string(out.hash.size()) +
                " - a mismatched label would store a hash that can never match";
        return false;
    }
    for (char c : out.hash) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            error = "hash contains a non-hexadecimal character";
            return false;
        }
    }

    if (fields.size() >= 3 && !fields[2].empty()) {
        out.description = Widen(fields[2]);
    }
    return true;
}

// Builds whitelist.wdb from the collected inputs and proves it reopens.
//
// Reason is SystemFile for every entry: this path exists to ingest known-good
// operating-system and vendor corpora (the NIST NSRL being the motivating case,
// as it is public domain and carries no commercial restriction). A per-line
// reason override is deliberately not offered yet - there is no caller for it,
// and inventing one now would be a configuration surface with no consumer.
[[nodiscard]] bool BuildWhitelistDatabaseInner(const Options& opt) {
    namespace WL = ShadowStrike::Whitelist;

    std::error_code ec;
    if (fs::exists(opt.whitelistOutput, ec)) {
        if (!opt.overwrite) {
            Fail("whitelist output '%ls' already exists (use --overwrite)",
                 opt.whitelistOutput.c_str());
            return false;
        }
        fs::remove(opt.whitelistOutput, ec);
        if (ec) {
            Fail("cannot replace existing whitelist '%ls'", opt.whitelistOutput.c_str());
            return false;
        }
    }

    WL::WhitelistStore store;
    const auto created = store.Create(opt.whitelistOutput);
    if (!created.IsSuccess()) {
        Fail("cannot create whitelist database '%ls': %s",
             opt.whitelistOutput.c_str(), created.message.c_str());
        return false;
    }

    std::uint64_t added = 0;
    std::uint64_t rejected = 0;
    std::uint64_t duplicates = 0;

    for (const auto& file : opt.whitelistFiles) {
        std::ifstream in(file);
        if (!in) {
            Fail("whitelist: cannot open '%ls'", file.c_str());
            return false;
        }
        Info("  whitelist  : reading %ls", file.c_str());

        std::string raw;
        std::uint64_t lineNo = 0;
        while (std::getline(in, raw)) {
            ++lineNo;
            WhitelistLine parsed;
            std::string error;
            if (!ParseWhitelistLine(raw, parsed, error)) {
                if (!error.empty()) {
                    Fail("whitelist: %ls line %llu: %s",
                         file.c_str(), static_cast<unsigned long long>(lineNo), error.c_str());
                    ++rejected;
                }
                continue;
            }

            const auto res = store.AddHash(parsed.hash, parsed.algorithm,
                                           WL::WhitelistReason::SystemFile,
                                           parsed.description);
            if (res.IsSuccess()) {
                ++added;
            } else if (res.code == WL::WhitelistStoreError::DuplicateEntry) {
                ++duplicates;
            } else {
                Fail("whitelist: %ls line %llu: %s",
                     file.c_str(), static_cast<unsigned long long>(lineNo), res.message.c_str());
                ++rejected;
            }
        }
    }

    // A rejected line means content the operator believes is protecting them is
    // not in the database. Shipping that silently is how a whitelist ends up
    // trusting less than its author thinks, so the build fails.
    if (rejected > 0) {
        Fail("whitelist: %llu line(s) were rejected - refusing to write a database "
             "that silently omits content", static_cast<unsigned long long>(rejected));
        return false;
    }

    if (added == 0) {
        Fail("whitelist: no entries were accepted, so the database would grant "
             "nothing while appearing to exist - exactly the inert-module failure "
             "this tool refuses to produce");
        return false;
    }

    const auto indexed = store.RebuildIndices();
    if (!indexed.IsSuccess()) {
        Fail("whitelist: index rebuild failed: %s", indexed.message.c_str());
        return false;
    }

    const auto saved = store.Save();
    if (!saved.IsSuccess()) {
        Fail("whitelist: save failed: %s", saved.message.c_str());
        return false;
    }
    store.Close();

    Info("  whitelist  : %llu entr%s added, %llu duplicate(s) collapsed",
         static_cast<unsigned long long>(added), added == 1 ? "y" : "ies",
         static_cast<unsigned long long>(duplicates));

    if (!opt.verify) {
        return true;
    }

    // Reopen read-only through the same store the service uses. A whitelist that
    // writes but does not load is worse than none, because the engine would then
    // treat trust lookups as unavailable and silently fall back to full analysis.
    WL::WhitelistStore reopened;
    const auto loaded = reopened.Load(opt.whitelistOutput, /*readOnly=*/true);
    if (!loaded.IsSuccess()) {
        Fail("whitelist verification failed - the runtime store cannot open the "
             "database we just wrote: %s", loaded.message.c_str());
        return false;
    }
    const std::uint64_t reopenedCount = reopened.GetEntryCount();
    reopened.Close();

    if (reopenedCount != added) {
        Fail("whitelist verification failed - wrote %llu entries but the reopened "
             "database reports %llu",
             static_cast<unsigned long long>(added),
             static_cast<unsigned long long>(reopenedCount));
        return false;
    }
    Info("  verified   : whitelist reopened with %llu entr%s",
         static_cast<unsigned long long>(reopenedCount),
         reopenedCount == 1 ? "y" : "ies");
    return true;
}

// A failed whitelist build must leave nothing behind.
//
// WhitelistStore::Create allocates the database file up front, so every failure
// after that point - a rejected line, a failed index rebuild, a save error - was
// leaving a partially populated database on disk. That file is worse than no file
// at all: the next build would refuse to overwrite it without --overwrite, and
// anything that went looking for whitelist.wdb would find a store holding some
// unknown subset of the intended entries and treat it as authoritative. A
// whitelist that grants trust for reasons nobody can reconstruct is precisely the
// thing the store's own hardening checks exist to prevent.
//
// The inner function owns the store, so by the time it returns the mapping is
// released and the file can be removed.
[[nodiscard]] bool BuildWhitelistDatabase(const Options& opt) {
    if (BuildWhitelistDatabaseInner(opt)) {
        return true;
    }

    std::error_code ec;
    if (fs::remove(opt.whitelistOutput, ec)) {
        Info("  whitelist  : discarded the partial database at %ls",
             opt.whitelistOutput.c_str());
    } else if (fs::exists(opt.whitelistOutput, ec)) {
        Fail("whitelist: a partial database remains at '%ls' and could not be "
             "removed - delete it before relying on this build",
             opt.whitelistOutput.c_str());
    }
    return false;
}

// Reopens the finished database through the same store the service uses. This
// is the whole point: a database that compiles but does not load is worthless,
// and that is precisely the state the product shipped in. The field log's
// "HashStore init failed" / "PatternStore init failed" / "YaraStore init
// failed" are these very flags, so asserting them here tests the thing that
// actually broke rather than a proxy for it.
[[nodiscard]] bool VerifyOutput(const std::wstring& path,
                                bool expectHashes,
                                bool expectPatterns,
                                bool expectYara) {
    ShadowStrike::SignatureStore::SignatureStore store;

    const StoreError opened = store.Initialize(path, /*readOnly=*/true);
    if (!opened.IsSuccess()) {
        Fail("verification failed - the runtime store cannot open the database "
             "we just wrote: %s", Describe(opened).c_str());
        return false;
    }

    const auto status = store.GetStatus();
    Info("  verified   : hashStore=%s patternStore=%s yaraStore=%s",
         status.hashStoreReady    ? "ready" : "FAILED",
         status.patternStoreReady ? "ready" : "FAILED",
         status.yaraStoreReady    ? "ready" : "FAILED");

    bool ok = true;
    if (expectHashes && !status.hashStoreReady) {
        Fail("hashes were built but the runtime hash store will not open them");
        ok = false;
    }
    if (expectPatterns && !status.patternStoreReady) {
        Fail("patterns were built but the runtime pattern store will not open them");
        ok = false;
    }
    if (expectYara && !status.yaraStoreReady) {
        Fail("YARA rules were built but the runtime YARA store will not open them");
        ok = false;
    }

    if (ok && expectYara) {
        const auto yaraStats = store.GetYaraStatistics();
        Info("  yara rules : %llu in %llu namespace(s)",
             yaraStats.totalRules, yaraStats.totalNamespaces);
        if (yaraStats.totalRules == 0) {
            Fail("the YARA store opened but reports zero compiled rules");
            ok = false;
        }
    }
    return ok;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    Options opt;
    if (!ParseArgs(argc, argv, opt)) {
        return 1;
    }

    Info("phantom-sigbuild");
    Info("  output     : %ls", opt.output.c_str());

    BuildConfiguration cfg;
    cfg.outputPath          = opt.output;
    cfg.initialDatabaseSize = opt.sizeMb * 1024ull * 1024ull;
    cfg.overwriteExisting   = opt.overwrite;
    cfg.strictValidation    = true;   // a malformed signature is a build break

    if (!opt.quiet) {
        cfg.progressCallback = [](const std::string& stage, size_t cur, size_t total) {
            if (total > 0) {
                std::printf("  %-22s %zu/%zu\r", stage.c_str(), cur, total);
            } else {
                std::printf("  %-22s\r", stage.c_str());
            }
            std::fflush(stdout);
        };
        cfg.logCallback = [](const std::string& message) {
            std::printf("  . %s\n", message.c_str());
        };
    }

    SignatureBuilder builder;
    builder.SetConfiguration(cfg);

    // ---------------------------------------------------------------------
    // Import. Every failure is fatal: a partial content set that silently
    // drops half its input is worse than no content, because it looks fine.
    // ---------------------------------------------------------------------

    const auto importStep = [](const char* what, const std::wstring& from,
                               const StoreError& e) -> bool {
        if (!e.IsSuccess()) {
            Fail("%s failed for '%ls': %s", what, from.c_str(), Describe(e).c_str());
            return false;
        }
        Info("  imported   : %-11s %ls", what, from.c_str());
        return true;
    };

    for (const auto& f : opt.hashFiles) {
        if (!importStep("hashes", f, builder.ImportHashesFromFile(f))) { return 2; }
    }
    for (const auto& f : opt.hashCsvFiles) {
        if (!importStep("hashes-csv", f, builder.ImportHashesFromCsv(f))) { return 2; }
    }
    for (const auto& f : opt.patternFiles) {
        if (!importStep("patterns", f, builder.ImportPatternsFromFile(f))) { return 2; }
    }
    for (const auto& f : opt.yaraFiles) {
        if (!ImportYaraWithLicenseFilter(builder, f, opt)) { return 2; }
    }
    for (const auto& d : opt.yaraDirs) {
        if (!importStep("yara-dir", d, builder.ImportYaraRulesFromDirectory(d, opt.yaraNamespace))) { return 2; }
    }

    const size_t pendingHashes   = builder.GetPendingHashCount();
    const size_t pendingPatterns = builder.GetPendingPatternCount();
    const size_t pendingYara     = builder.GetPendingYaraRuleCount();

    Info("  pending    : hashes=%zu patterns=%zu yara=%zu",
         pendingHashes, pendingPatterns, pendingYara);

    if (pendingHashes == 0 && pendingPatterns == 0 && pendingYara == 0) {
        Fail("every import reported success yet nothing is pending - the input "
             "files parsed to zero signatures. Check the expected formats: "
             "hashes are TYPE:HASH:NAME:LEVEL, one per line.");
        return 2;
    }

    // ---------------------------------------------------------------------
    // Build
    // ---------------------------------------------------------------------

    // Build() runs the whole seven-stage pipeline - validation, deduplication,
    // optimization, index construction, serialization, integrity check - so
    // BuildIndices() must NOT be called again here.
    //
    // It was, and that was wrong in a way worth recording. Calling it after
    // Build() re-ran index construction against a database that had already been
    // serialized with its header written, and BuildHashIndex overwrites
    // m_statistics.hashIndexSize with a pre-serialization estimate. The file on
    // disk stayed correct, but the figures reported below disagreed with the
    // header - hash index 0.00 MB against a real 28672 bytes - which is exactly
    // the kind of misleading output that sends you looking in the wrong place.
    const StoreError built = builder.Build();
    if (!opt.quiet) {
        std::printf("\n");
    }
    if (!built.IsSuccess()) {
        Fail("build failed: %s", Describe(built).c_str());
        return 3;
    }

    const auto& st = builder.GetStatistics();
    Info("  built      : hashes=%llu patterns=%llu yara=%llu",
         st.totalHashesAdded, st.totalPatternsAdded, st.totalYaraRulesAdded);
    Info("  deduped    : %llu removed, %llu invalid skipped",
         st.duplicatesRemoved, st.invalidSignaturesSkipped);
    Info("  database   : %.2f MB (hash index %.2f MB, pattern index %.2f MB)",
         static_cast<double>(st.finalDatabaseSize) / (1024.0 * 1024.0),
         static_cast<double>(st.hashIndexSize)     / (1024.0 * 1024.0),
         static_cast<double>(st.patternIndexSize)  / (1024.0 * 1024.0));

    if (st.invalidSignaturesSkipped > 0 && cfg.strictValidation) {
        Fail("%llu signatures were skipped as invalid while strict validation "
             "was on - fix the input rather than shipping a partial set",
             st.invalidSignaturesSkipped);
        return 3;
    }

    // ---------------------------------------------------------------------
    // Verify through the runtime path
    // ---------------------------------------------------------------------

    if (opt.verify &&
        !VerifyOutput(opt.output,
                      pendingHashes   > 0,
                      pendingPatterns > 0,
                      pendingYara     > 0)) {
        return 4;
    }

    // ---------------------------------------------------------------------
    // Whitelist database
    //
    // Built after the signature database has verified, so a failure here cannot
    // be confused with a failure there. It is a separate output because it is a
    // separate store with the opposite meaning, and because the runtime applies
    // a different trust posture to it.
    // ---------------------------------------------------------------------
    if (!opt.whitelistOutput.empty() && !BuildWhitelistDatabase(opt)) {
        return 5;
    }

    Info("  OK");
    return 0;
}
