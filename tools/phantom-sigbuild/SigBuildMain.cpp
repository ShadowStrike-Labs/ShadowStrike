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
#include "RuleLicenseFilter.hpp"

#include <windows.h>

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
        "  --content <dir>      convention: <dir>/hashes, <dir>/patterns, <dir>/yara\n"
        "\n"
        "Options:\n"
        "  --overwrite          replace an existing database\n"
        "  --size-mb <n>        initial database size, default 64\n"
        "  --namespace <name>   YARA namespace, default \"default\"\n"
        "  --no-verify          skip reopening the output to prove it loads\n"
        "  --quiet              suppress per-stage progress\n"
        "\n"
        "Exit codes: 0 success, 1 usage, 2 import failed, 3 build failed,\n"
        "            4 output did not verify\n");
}

struct Options {
    std::wstring              output;
    std::vector<std::wstring> hashFiles;
    std::vector<std::wstring> hashCsvFiles;
    std::vector<std::wstring> patternFiles;
    std::vector<std::wstring> yaraFiles;
    std::vector<std::wstring> yaraDirs;
    std::string               yaraNamespace{ "default" };
    std::uint64_t             sizeMb{ 64 };
    bool                      overwrite{ false };
    bool                      verify{ true };
    std::wstring              attribution;   // empty => beside the output database
    bool                      quiet{ false };
};

// Expands --content into the individual input lists. Kept a convention rather
// than a manifest format so the content tree is self-describing on disk.
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

    collect(root / "hashes",   opt.hashFiles,    { L".txt", L".hashes" });
    collect(root / "hashes",   opt.hashCsvFiles, { L".csv" });
    collect(root / "patterns", opt.patternFiles, { L".txt", L".patterns" });
    collect(root / "yara",     opt.yaraFiles,    { L".yar", L".yara" });
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
    return true;
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

    Info("  OK");
    return 0;
}
