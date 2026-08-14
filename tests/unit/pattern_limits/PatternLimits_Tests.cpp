// ============================================================================
//  Compiled-pattern size limits
//
//  Covers the contract closed by task 64: ONE constant governs the longest
//  compiled pattern this build can compile, store and scan.
//
//  WHY THESE TESTS LOOK THE WAY THEY DO:
//
//  Five limits used to govern this one value independently - the format header
//  at 8192, a local copy in the builder's input validation at 8192 that measured
//  input CHARACTERS rather than compiled bytes, Boyer-Moore at 8192,
//  Aho-Corasick at 4096, and PatternStore's own MAX_COMPILED_PATTERN_SIZE at
//  256. The smallest decided what actually worked, and it was the one number
//  nobody advertised.
//
//  So the tests below deliberately do NOT assert against a literal. They assert
//  against SignatureStore::MAX_PATTERN_LENGTH and check the BOUNDARY on both
//  sides, which is the only way to catch a future edit that moves one of the
//  five numbers and not the others. Each matcher's own ceiling is checked at
//  compile time by a static_assert in its translation unit; there is no runtime
//  test for those because a failure is a build failure.
//
//  The wildcard test is the one that would have failed before this change for a
//  reason unrelated to the limits: the validator's size check added 2 per '?',
//  so a '??' wildcard - one byte - counted as two, and a wildcard-heavy pattern
//  was over-counted by up to 2x and refused for a size it would never compile to.
// ============================================================================

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

#include "src/PhantomCore/PatternStore/PatternStore.hpp"

using ShadowStrike::PatternStore::PatternCompiler;
using ShadowStrike::PatternStore::PatternStore;
using ShadowStrike::SignatureStore::MAX_PATTERN_LENGTH;
using ShadowStrike::SignatureStore::PatternMode;
using ShadowStrike::SignatureStore::ThreatLevel;

namespace {

    // Space-separated hex text for a pattern of `byteCount` bytes, with values that
    // vary so a matcher with broken skip tables cannot pass by coincidence.
    std::string HexTextOfLength(size_t byteCount) {
        std::string text;
        text.reserve(byteCount * 3);
        static const char* kHex = "0123456789ABCDEF";
        for (size_t i = 0; i < byteCount; ++i) {
            if (i > 0) {
                text.push_back(' ');
            }
            const auto value = static_cast<uint8_t>(((i * 7u) + 3u) % 251u);
            text.push_back(kHex[(value >> 4) & 0x0F]);
            text.push_back(kHex[value & 0x0F]);
        }
        return text;
    }

    // One fixed byte followed by `wildcardCount` '??' wildcards. Valid because at
    // least one position is fixed; a pattern of nothing but wildcards is refused
    // separately and for a different reason.
    std::string WildcardHeavyText(size_t wildcardCount) {
        std::string text = "5A";
        for (size_t i = 0; i < wildcardCount; ++i) {
            text += " ??";
        }
        return text;
    }

} // namespace

// ---------------------------------------------------------------------------
// The governing limit is the limit the compiler actually applies
// ---------------------------------------------------------------------------

TEST(PatternLimits, PatternAtTheGoverningLimitCompiles) {
    PatternMode mode{};
    std::vector<uint8_t> mask;

    const auto compiled =
        PatternCompiler::CompilePattern(HexTextOfLength(MAX_PATTERN_LENGTH), mode, mask);

    ASSERT_TRUE(compiled.has_value())
        << "a pattern of exactly MAX_PATTERN_LENGTH bytes must compile; if it does not, "
           "some other limit on the path is smaller than the governing one";
    EXPECT_EQ(compiled->size(), MAX_PATTERN_LENGTH);
    EXPECT_EQ(mask.size(), compiled->size());
}

TEST(PatternLimits, PatternOverTheGoverningLimitIsRefused) {
    PatternMode mode{};
    std::vector<uint8_t> mask;

    const auto compiled =
        PatternCompiler::CompilePattern(HexTextOfLength(MAX_PATTERN_LENGTH + 1), mode, mask);

    EXPECT_FALSE(compiled.has_value())
        << "one byte over the limit must be refused, not truncated - a truncated pattern "
           "is a different pattern that still reports success";
}

// The two halves of the compiler are a matched pair and the fuzz harness asserts
// they agree. A boundary is exactly where they are most likely to drift apart.
TEST(PatternLimits, ValidatorAndCompilerAgreeAtTheBoundary) {
    std::string error;

    const std::string atLimit = HexTextOfLength(MAX_PATTERN_LENGTH);
    const std::string overLimit = HexTextOfLength(MAX_PATTERN_LENGTH + 1);

    PatternMode mode{};
    std::vector<uint8_t> mask;

    const bool validatorAcceptsAtLimit = PatternCompiler::ValidatePattern(atLimit, error);
    const bool compilerAcceptsAtLimit =
        PatternCompiler::CompilePattern(atLimit, mode, mask).has_value();
    EXPECT_EQ(validatorAcceptsAtLimit, compilerAcceptsAtLimit);
    EXPECT_TRUE(validatorAcceptsAtLimit);

    const bool validatorAcceptsOver = PatternCompiler::ValidatePattern(overLimit, error);
    const bool compilerAcceptsOver =
        PatternCompiler::CompilePattern(overLimit, mode, mask).has_value();
    EXPECT_EQ(validatorAcceptsOver, compilerAcceptsOver);
    EXPECT_FALSE(validatorAcceptsOver);
    EXPECT_FALSE(error.empty()) << "a refusal must say why";
}

// ---------------------------------------------------------------------------
// A pattern longer than the old undocumented 256-byte ceiling
// ---------------------------------------------------------------------------

TEST(PatternLimits, PatternLongerThanTheOldCeilingCompilesToItsExactLength) {
    // 1024 was impossible before: MAX_COMPILED_PATTERN_SIZE was 256, so this
    // returned nullopt from a compiler whose caller reported the build as
    // successful and simply omitted the signature.
    constexpr size_t kLength = 1024;
    static_assert(kLength <= MAX_PATTERN_LENGTH,
        "this test is meaningless if the governing limit drops below it");

    PatternMode mode{};
    std::vector<uint8_t> mask;

    const auto compiled = PatternCompiler::CompilePattern(HexTextOfLength(kLength), mode, mask);

    ASSERT_TRUE(compiled.has_value());
    EXPECT_EQ(compiled->size(), kLength);
    EXPECT_EQ(mode, PatternMode::Exact);
    // Every position is fixed, so every mask byte must be 0xFF. A mask that
    // disagreed with the mode would make the pattern match more than it says.
    for (const uint8_t maskByte : mask) {
        EXPECT_EQ(maskByte, 0xFFu);
    }
}

// ---------------------------------------------------------------------------
// The wildcard over-count that caused false rejections
// ---------------------------------------------------------------------------

TEST(PatternLimits, WildcardHeavyPatternIsSizedByBytesNotByCharacters) {
    // 199 wildcards + 1 fixed byte = 200 bytes. The old size check added 2 per
    // '?' character, giving 2*200-1 = 399, which exceeded the old 256 ceiling -
    // so this pattern was refused as "too large (estimated 399 bytes)" while its
    // true compiled size was 200. The number in the message was one the compiler
    // could never produce.
    constexpr size_t kWildcards = 199;
    constexpr size_t kExpectedBytes = kWildcards + 1;

    std::string error;
    const std::string text = WildcardHeavyText(kWildcards);

    EXPECT_TRUE(PatternCompiler::ValidatePattern(text, error))
        << "validator refused a wildcard-heavy pattern: " << error;

    PatternMode mode{};
    std::vector<uint8_t> mask;
    const auto compiled = PatternCompiler::CompilePattern(text, mode, mask);

    ASSERT_TRUE(compiled.has_value());
    EXPECT_EQ(compiled->size(), kExpectedBytes)
        << "the compiled size is what the size check must be measured against";
    EXPECT_EQ(mode, PatternMode::Wildcard);

    // One fixed position, the rest wildcards - confirms the text was read as
    // intended rather than the wildcards collapsing into something else.
    size_t fixedPositions = 0;
    for (const uint8_t maskByte : mask) {
        if (maskByte == 0xFFu) {
            ++fixedPositions;
        }
    }
    EXPECT_EQ(fixedPositions, 1u);
}

// ---------------------------------------------------------------------------
// The observable consequence, through the public API only
// ---------------------------------------------------------------------------

TEST(PatternLimits, LongPatternAddedThroughTheStoreActuallyMatches) {
    // The compiler accepting a long pattern is necessary but not sufficient. The
    // automaton has its own ceiling, and a pattern accepted by the compiler and
    // refused by the automaton is stored, counted as loaded, and matched by
    // nothing - which looks exactly like a clean file. So this goes through
    // AddPattern and Scan and asserts a match BY NAME.
    const auto dbPath =
        std::filesystem::temp_directory_path() / "ss_pattern_limits_test.pdb";

    std::error_code ec;
    std::filesystem::remove(dbPath, ec);

    {
        PatternStore store;
        const auto created = store.CreateNew(dbPath.wstring(), 8ull * 1024 * 1024);
        ASSERT_TRUE(created.IsSuccess());

        constexpr size_t kLength = 1024;
        const std::string text = HexTextOfLength(kLength);
        ASSERT_TRUE(store.AddPattern(text, "LongPattern", ThreatLevel::Low).IsSuccess());

        // Rebuild the concrete bytes the same way the compiler does, then plant
        // them at a non-zero offset surrounded by filler so a matcher that only
        // ever reports offset 0 cannot pass.
        PatternMode mode{};
        std::vector<uint8_t> mask;
        const auto compiled = PatternCompiler::CompilePattern(text, mode, mask);
        ASSERT_TRUE(compiled.has_value());
        ASSERT_EQ(compiled->size(), kLength);

        std::vector<uint8_t> buffer(64, 0x41);
        buffer.insert(buffer.end(), compiled->begin(), compiled->end());
        buffer.insert(buffer.end(), 64, 0x42);

        ShadowStrike::SignatureStore::QueryOptions opts{};
        const auto hits = store.Scan(buffer, opts);

        bool matchedByName = false;
        for (const auto& hit : hits) {
            if (hit.signatureName == "LongPattern") {
                matchedByName = true;
            }
        }
        EXPECT_TRUE(matchedByName)
            << "a " << kLength << "-byte pattern was accepted by the store and then "
               "matched by nothing; check the automaton's own length ceiling";

        // And it must not match content that does not contain it.
        const std::vector<uint8_t> clean(buffer.size(), 0x43);
        EXPECT_TRUE(store.Scan(clean, opts).empty());
    }

    std::filesystem::remove(dbPath, ec);
}
