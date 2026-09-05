// ===========================================================================
// PolymorphicCodeScope_Tests.cpp
//
// PolymorphicDetector is an x86 code detector. Its junk-instruction table is
// x86 opcodes, DetectEngineInternal matches x86 engine stubs, and
// FindDecryptionLoopsInternal looks for x86 decryptor loops.
//
// AnalyzeFile used to read a file from offset 0 and pass the whole thing to
// AnalyzeInternal, whose parameter is named `code`, with no PE parse and no
// type check. Because x86 is a dense encoding in which nearly any byte
// sequence decodes, that turned every non-executable file on the machine into
// a source of "mutations" and "decryption loops" at a rate set by byte
// frequency rather than by intent.
//
// The 1.0.109 field run measured the result: fourteen detections, none of them
// real and none of them executable. Five Prefetch files, two scheduled-task XML
// files, MpCmdRun.log and Microsoft.LocalContent.db were reported
// Polymorphic.Generic or Polymorphic. Only blocked=0 kept it harmless.
//
// THESE TESTS PIN THE DISTINCTION THAT FIX RESTS ON, IN BOTH DIRECTIONS:
//   * a non-PE file must not yield a code verdict, and
//   * the same bytes handed to the code API must still yield one.
// The second is what stops this suite being satisfiable by weakening or
// deleting the detector, which is the outcome the project's detection-integrity
// rule forbids. A guard that only asserted "no detection on a data file" would
// pass just as happily if the detector were removed entirely.
// ===========================================================================

#include "pch.h"
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <Windows.h>

#include "../../../src/PhantomCore/Core/Engine/PolymorphicDetector.hpp"
#include "../../../src/PhantomCore/PEParser/PEParser.hpp"

using ShadowStrike::Core::Engine::PolyBufferKind;
using ShadowStrike::Core::Engine::PolymorphicDetector;
using ShadowStrike::Core::Engine::PolymorphicConfiguration;
using ShadowStrike::Core::Engine::PolyResult;

namespace {

// ---------------------------------------------------------------------------
// A buffer densely populated with the exact junk sequences the detector's own
// mutation table lists (PolymorphicDetector.cpp InitializeJunkPatterns):
// NOP, XCHG EAX/EAX, MOV EAX/EAX, MOV ECX/ECX, JMP $+0 and the multi-byte
// NOPs. Derived from that table rather than invented, so if the table changes
// this payload keeps describing the same thing.
//
// It deliberately does NOT begin with MZ, so it is not a PE. This is the shape
// of input that produced the field false positives.
// ---------------------------------------------------------------------------
std::vector<uint8_t> JunkDenseNonPeBuffer() {
    const std::vector<std::vector<uint8_t>> junk = {
        {0x90},
        {0x87, 0xC0},
        {0x8B, 0xC0},
        {0x8B, 0xC9},
        {0x8B, 0xD2},
        {0x8B, 0xDB},
        {0x8B, 0xED},
        {0x8B, 0xF6},
        {0x8B, 0xFF},
        {0xEB, 0x00},
        {0x0F, 0x1F, 0x00},
        {0x0F, 0x1F, 0x40, 0x00},
        {0x66, 0x90},
        {0x87, 0xC9},
        {0x87, 0xD2},
    };

    std::vector<uint8_t> out;
    // Not "MZ". Anything that cannot be mistaken for a PE header.
    const char tag[] = "SSDATA\x01\x02";
    out.insert(out.end(), tag, tag + sizeof(tag) - 1);

    for (int round = 0; round < 64; ++round) {
        for (const auto& j : junk) {
            out.insert(out.end(), j.begin(), j.end());
        }
    }
    return out;
}

// RAII temp file with a caller-supplied tag, so no two tests share a path.
// ScanEngine's result cache is keyed by path and content, and a suite whose
// tests all write the same bytes to the same name makes every test after the
// first vacuous - that defect was found by mutation proof in the archive
// dispatch suite and is not repeated here.
class TempBlob {
public:
    TempBlob(const std::string& tag, const std::vector<uint8_t>& bytes) {
        m_dir = std::filesystem::temp_directory_path() / "phantom-poly-scope";
        std::filesystem::create_directories(m_dir);
        m_path = m_dir / ("probe-" + tag + ".bin");

        std::ofstream f(m_path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        f.close();
    }

    ~TempBlob() {
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
    }

    TempBlob(const TempBlob&) = delete;
    TempBlob& operator=(const TempBlob&) = delete;

    [[nodiscard]] const std::filesystem::path& Path() const { return m_path; }

private:
    std::filesystem::path m_dir;
    std::filesystem::path m_path;
};

// The detector is a singleton shared with ScanEngine. Initialize is idempotent,
// and Shutdown is deliberately NOT called: other suites in this binary use the
// same instance, and tests/unit/scan_engine_teardown registers a global
// environment that requires the engine still up after every suite has run.
void EnsureDetectorReady() {
    auto& detector = PolymorphicDetector::Instance();
    if (!detector.IsInitialized()) {
        PolymorphicConfiguration config{};
        config.enabled = true;
        ASSERT_TRUE(detector.Initialize(config));
    }
    ASSERT_TRUE(detector.IsInitialized());
}

std::filesystem::path OwnModulePath() {
    wchar_t buf[MAX_PATH * 4] = {};
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) {
        return {};
    }
    return std::filesystem::path(buf);
}

} // namespace

// ---------------------------------------------------------------------------
// THE FIELD DEFECT. A file that is not machine code must not produce a code
// verdict, however x86-shaped its bytes happen to look.
// ---------------------------------------------------------------------------
TEST(PolymorphicCodeScopeTest, ADataFileIsNotJudgedAsCode) {
    ASSERT_NO_FATAL_FAILURE(EnsureDetectorReady());

    const TempBlob blob("datafile", JunkDenseNonPeBuffer());
    ASSERT_TRUE(std::filesystem::exists(blob.Path()));

    const PolyResult result = PolymorphicDetector::Instance().AnalyzeFile(blob.Path());

    EXPECT_FALSE(result.codeAnalysisPerformed)
        << "a file with no PE header was analysed as machine code";

    EXPECT_FALSE(result.isPolymorphic)
        << "a non-executable file was reported polymorphic - this is the 1.0.109 "
           "defect that flagged Prefetch files, task XML, a text log and a "
           "SQLite database while flagging nothing executable";

    EXPECT_TRUE(result.threatFamily.empty())
        << "a threat family was attributed to a file that was never analysed as code";
}

// ---------------------------------------------------------------------------
// THE ANTI-DELETION HALF, AND THE REASON THIS SUITE CANNOT BE SATISFIED BY
// WEAKENING THE DETECTOR. The same bytes, handed to the code API, must still be
// judged. If someone "fixes" a false positive by disabling the mutation
// detectors, this fails.
// ---------------------------------------------------------------------------
TEST(PolymorphicCodeScopeTest, TheSameBytesAsCodeAreStillJudged) {
    ASSERT_NO_FATAL_FAILURE(EnsureDetectorReady());

    const std::vector<uint8_t> bytes = JunkDenseNonPeBuffer();

    const PolyResult result = PolymorphicDetector::Instance().Analyze(bytes);

    EXPECT_TRUE(result.codeAnalysisPerformed)
        << "the code API refused to analyse a code buffer, so the fix for the "
           "file path has been applied to the wrong layer";

    EXPECT_FALSE(result.mutations.empty())
        << "a buffer built from the detector's own junk-instruction table "
           "produced no mutations, so the mutation detector has been weakened "
           "or the table it is derived from has changed";

    EXPECT_TRUE(result.isPolymorphic)
        << "junk-dense code is no longer recognised - detection capability was "
           "removed rather than scoped";
}

// ---------------------------------------------------------------------------
// The similarity half must survive for data files, because ScanEngine
// publishes result.fuzzyHash for every scanned file and a downstream consumer
// reads it. Scoping the code verdict must not cost the content hash.
// ---------------------------------------------------------------------------
TEST(PolymorphicCodeScopeTest, ADataFileStillYieldsItsSimilarityHash) {
    ASSERT_NO_FATAL_FAILURE(EnsureDetectorReady());

    const TempBlob blob("hashonly", JunkDenseNonPeBuffer());
    ASSERT_TRUE(std::filesystem::exists(blob.Path()));

    const PolyResult result = PolymorphicDetector::Instance().AnalyzeFile(blob.Path());

    EXPECT_FALSE(result.codeAnalysisPerformed);

    EXPECT_FALSE(result.fuzzyHash.empty() && result.tlshHash.empty())
        << "no similarity hash was produced for a data file, so scoping the code "
           "verdict has cost the content-similarity capability that ScanEngine "
           "publishes for every scanned file";
}

// ---------------------------------------------------------------------------
// The executable path must run ON THE CODE, not merely run.
//
// An earlier version of this test asserted only that code analysis happened.
// A mutation proof showed that assertion is satisfied by analysing .rdata:
// inverting the section test made the detector pick the first NON-executable
// section and the test still passed. So the region is derived here from the PE
// independently, with PEParser, and the detector is required to have chosen the
// same one. Deriving the expectation from the artifact rather than hardcoding an
// offset means this keeps working when the binary is rebuilt.
//
// This asserts WHERE analysis happened, not what it concluded. What a compiler
// emits into .text - alignment padding is multi-byte NOP, which is in the junk
// table - is not this suite's contract to pin.
// ---------------------------------------------------------------------------
TEST(PolymorphicCodeScopeTest, AnExecutableIsAnalysedAtItsCodeSection) {
    ASSERT_NO_FATAL_FAILURE(EnsureDetectorReady());

    const auto self = OwnModulePath();
    ASSERT_FALSE(self.empty());
    ASSERT_TRUE(std::filesystem::exists(self));

    // Independently determine where this PE's first usable executable section
    // begins, using the same parser the product uses but not the same code path.
    std::error_code ec;
    const auto fileSize = std::filesystem::file_size(self, ec);
    ASSERT_FALSE(ec);

    ShadowStrike::PEParser::PEParser parser;
    ShadowStrike::PEParser::PEInfo info;
    ASSERT_TRUE(parser.ParseFile(self.wstring(), info, nullptr))
        << "this test binary could not be parsed as a PE, so the expectation "
           "cannot be derived";

    uint64_t expectedOffset = 0;
    bool haveExpectation = false;
    for (const auto& sec : info.sections) {
        if (!sec.isExecutable || sec.rawSize == 0) {
            continue;
        }
        if (static_cast<uint64_t>(sec.rawAddress) >= fileSize) {
            continue;
        }
        const uint64_t avail = fileSize - sec.rawAddress;
        if (std::min<uint64_t>(sec.rawSize, avail) < 32) {
            continue;
        }
        expectedOffset = sec.rawAddress;
        haveExpectation = true;
        break;
    }
    ASSERT_TRUE(haveExpectation)
        << "this PE has no usable executable section, so there is nothing to pin";
    ASSERT_NE(expectedOffset, 0u)
        << "an executable section at offset 0 would make this assertion vacuous, "
           "because 0 is also what the opaque path reports";

    const PolyResult result = PolymorphicDetector::Instance().AnalyzeFile(self);

    EXPECT_TRUE(result.codeAnalysisPerformed)
        << "a real PE was not analysed as machine code, so the executable arm "
           "does not locate its code section and the fix has disabled analysis "
           "instead of scoping it";

    EXPECT_EQ(result.analyzedOffset, expectedOffset)
        << "the analysed region is not this PE's first executable section, so the "
           "detector is judging the wrong bytes - data analysed as code is the "
           "defect this suite exists to prevent";

    EXPECT_GT(result.analyzedSize, 0u);
    EXPECT_LT(static_cast<uint64_t>(result.analyzedSize), fileSize)
        << "the whole file was analysed rather than its code section";
}
