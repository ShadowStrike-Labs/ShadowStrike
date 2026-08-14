// ============================================================================
//  Masked pattern matching
//
//  Covers the capability closed by task 60: a pattern containing '??' wildcards
//  is compiled with a mask and actually scanned, by BoyerMooreMatcher, through
//  PatternStore's masked pass.
//
//  WHAT THESE TESTS ARE FOR, stated plainly, because the obvious tests here are
//  the useless ones:
//
//  A masked matcher has TWO failure modes and they are opposites. It can fail to
//  match content it describes (a miss), or it can match content it does not (a
//  false positive, which a mask makes easy to introduce - the degenerate matcher
//  that ignores its mask entirely and reports every offset passes any test that
//  only checks "did it find the thing"). So every positive assertion here is
//  paired with a negative one.
//
//  The third failure mode is specific to Boyer-Moore and is the reason the
//  OverShift tests exist: the algorithm's speed comes from SKIPPING positions it
//  has proven cannot match. If the skip tables are built from pattern bytes
//  without consulting the mask, they will happily skip over a position where a
//  wildcard would have matched. That produces a matcher which is correct on most
//  inputs and silently blind on others - the worst possible outcome, and one that
//  a test using a pattern without repeated bytes will never expose.
// ============================================================================

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "src/PhantomCore/PatternStore/PatternStore.hpp"

using ShadowStrike::PatternStore::BoyerMooreMatcher;
using ShadowStrike::PatternStore::PatternCompiler;
using ShadowStrike::SignatureStore::PatternMode;

namespace {

    // 0xFF = this position must match exactly, 0x00 = any byte matches.
    std::vector<size_t> FindAll(const std::vector<uint8_t>& pattern,
                                const std::vector<uint8_t>& mask,
                                const std::vector<uint8_t>& buffer) {
        const BoyerMooreMatcher matcher(pattern, mask);
        EXPECT_TRUE(matcher.IsValid());
        return matcher.Search(buffer);
    }

} // namespace

// ---------------------------------------------------------------------------
// The mask is honoured at all
// ---------------------------------------------------------------------------

TEST(MaskedPattern, ExactMaskBehavesAsExactMatch) {
    const std::vector<uint8_t> pattern{ 0x48, 0x8B, 0x05, 0xC3 };
    const std::vector<uint8_t> mask{ 0xFF, 0xFF, 0xFF, 0xFF };
    const std::vector<uint8_t> buffer{ 0x90, 0x48, 0x8B, 0x05, 0xC3, 0x90 };

    const auto hits = FindAll(pattern, mask, buffer);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], 1u);
}

TEST(MaskedPattern, WildcardPositionMatchesAnyByte) {
    // "48 8B ?? C3" - the stored byte at the wildcard is 0x00, deliberately not
    // the byte planted in the buffer, so a matcher comparing bytes literally
    // would miss and this test would fail rather than pass by coincidence.
    const std::vector<uint8_t> pattern{ 0x48, 0x8B, 0x00, 0xC3 };
    const std::vector<uint8_t> mask{ 0xFF, 0xFF, 0x00, 0xFF };

    for (const uint8_t wild : { uint8_t{0x00}, uint8_t{0x01}, uint8_t{0x5A},
                                uint8_t{0x8B}, uint8_t{0xFE}, uint8_t{0xFF} }) {
        const std::vector<uint8_t> buffer{ 0x11, 0x48, 0x8B, wild, 0xC3, 0x22 };
        const auto hits = FindAll(pattern, mask, buffer);
        ASSERT_EQ(hits.size(), 1u) << "wildcard byte 0x" << std::hex << int(wild);
        EXPECT_EQ(hits[0], 1u);
    }
}

TEST(MaskedPattern, FixedPositionStillConstrains) {
    // The paired negative: a mask with a wildcard must not make the FIXED
    // positions optional. A matcher that reported a hit here would be reporting
    // detections on content the signature does not describe.
    const std::vector<uint8_t> pattern{ 0x48, 0x8B, 0x00, 0xC3 };
    const std::vector<uint8_t> mask{ 0xFF, 0xFF, 0x00, 0xFF };

    const std::vector<uint8_t> wrongFirst{ 0x11, 0x49, 0x8B, 0x5A, 0xC3, 0x22 };
    EXPECT_TRUE(FindAll(pattern, mask, wrongFirst).empty());

    const std::vector<uint8_t> wrongMiddle{ 0x11, 0x48, 0x8C, 0x5A, 0xC3, 0x22 };
    EXPECT_TRUE(FindAll(pattern, mask, wrongMiddle).empty());

    const std::vector<uint8_t> wrongLast{ 0x11, 0x48, 0x8B, 0x5A, 0xC4, 0x22 };
    EXPECT_TRUE(FindAll(pattern, mask, wrongLast).empty());
}

TEST(MaskedPattern, AllWildcardMaskMatchesEveryOffset) {
    // Documents WHY phantom-sigbuild refuses an all-wildcard pattern rather than
    // relying on the matcher to be sensible about it: the matcher is behaving
    // correctly here, and correct behaviour for that input is a match at every
    // single offset. That is a guaranteed false positive on every file, so it has
    // to be refused where content is authored, not silently tolerated here.
    const std::vector<uint8_t> pattern{ 0x00, 0x00 };
    const std::vector<uint8_t> mask{ 0x00, 0x00 };
    const std::vector<uint8_t> buffer{ 0x11, 0x22, 0x33, 0x44 };

    const auto hits = FindAll(pattern, mask, buffer);
    EXPECT_EQ(hits.size(), 3u);
}

// ---------------------------------------------------------------------------
// Skip-table safety - the tests that catch a silently blind matcher
// ---------------------------------------------------------------------------

TEST(MaskedPattern, OverShiftDoesNotSkipAMatchAfterRepeatedBytes) {
    // Pattern "41 ?? 41 42" against a run of 0x41.
    //
    // The only match is at offset 1. Reaching it requires the matcher to advance
    // by exactly one position after failing at offset 0, which is precisely what
    // a mask-unaware bad-character table gets wrong: the wildcard at index 1
    // means EVERY byte value can legitimately appear there, so no shift computed
    // from pattern bytes alone is safe.
    const std::vector<uint8_t> pattern{ 0x41, 0x00, 0x41, 0x42 };
    const std::vector<uint8_t> mask{ 0xFF, 0x00, 0xFF, 0xFF };
    const std::vector<uint8_t> buffer{ 0x41, 0x41, 0x41, 0x41, 0x42 };

    const auto hits = FindAll(pattern, mask, buffer);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], 1u);
}

TEST(MaskedPattern, OverShiftDoesNotSkipWithWildcardAtTheEnd) {
    // A wildcard in the LAST position is the case the bad-character rule is most
    // exposed to, because that rule keys on the buffer byte aligned with the end
    // of the window. Matches at 0 and 2 must both be found.
    const std::vector<uint8_t> pattern{ 0x41, 0x42, 0x00 };
    const std::vector<uint8_t> mask{ 0xFF, 0xFF, 0x00 };
    const std::vector<uint8_t> buffer{ 0x41, 0x42, 0x41, 0x42, 0x99 };

    const auto hits = FindAll(pattern, mask, buffer);
    ASSERT_EQ(hits.size(), 2u);
    EXPECT_EQ(hits[0], 0u);
    EXPECT_EQ(hits[1], 2u);
}

TEST(MaskedPattern, OverlappingMatchesAreAllReported) {
    // Advance-by-one after a hit, not advance-by-length: a signature that occurs
    // twice with overlap occurs twice.
    const std::vector<uint8_t> pattern{ 0x41, 0x00, 0x41 };
    const std::vector<uint8_t> mask{ 0xFF, 0x00, 0xFF };
    const std::vector<uint8_t> buffer{ 0x41, 0x99, 0x41, 0x99, 0x41 };

    const auto hits = FindAll(pattern, mask, buffer);
    ASSERT_EQ(hits.size(), 2u);
    EXPECT_EQ(hits[0], 0u);
    EXPECT_EQ(hits[1], 2u);
}

TEST(MaskedPattern, PartialMaskConstrainsOnlyTheMaskedBits) {
    // A byte mask need not be all-or-nothing. 0xF0 constrains the high nibble
    // and leaves the low nibble free.
    const std::vector<uint8_t> pattern{ 0x40, 0xC3 };
    const std::vector<uint8_t> mask{ 0xF0, 0xFF };

    for (uint8_t low = 0x40; low <= 0x4F; ++low) {
        const std::vector<uint8_t> buffer{ 0x11, low, 0xC3, 0x22 };
        const auto hits = FindAll(pattern, mask, buffer);
        ASSERT_EQ(hits.size(), 1u) << "byte 0x" << std::hex << int(low);
    }

    // High nibble outside the mask must not match.
    const std::vector<uint8_t> wrong{ 0x11, 0x50, 0xC3, 0x22 };
    EXPECT_TRUE(FindAll(pattern, mask, wrong).empty());
}

// ---------------------------------------------------------------------------
// Matcher state
// ---------------------------------------------------------------------------

TEST(MaskedPattern, EmptyPatternProducesAnInvalidMatcher) {
    // IsValid exists so that a matcher which failed to build is distinguishable
    // from one that found nothing. Without it, BuildMaskedMatchers would store a
    // matcher that silently answers "no match" for every buffer.
    const BoyerMooreMatcher matcher(std::vector<uint8_t>{}, std::vector<uint8_t>{});
    EXPECT_FALSE(matcher.IsValid());
    EXPECT_TRUE(matcher.Search(std::vector<uint8_t>{ 0x41, 0x42 }).empty());
}

TEST(MaskedPattern, AbsentMaskIsTreatedAsFullyExact) {
    const std::vector<uint8_t> pattern{ 0x41, 0x42 };
    const BoyerMooreMatcher matcher(pattern);
    ASSERT_TRUE(matcher.IsValid());

    const std::vector<uint8_t> match{ 0x00, 0x41, 0x42 };
    EXPECT_EQ(matcher.Search(match).size(), 1u);

    const std::vector<uint8_t> noMatch{ 0x00, 0x41, 0x43 };
    EXPECT_TRUE(matcher.Search(noMatch).empty());
}

TEST(MaskedPattern, BufferShorterThanPatternCannotMatch) {
    const std::vector<uint8_t> pattern{ 0x41, 0x42, 0x43 };
    const std::vector<uint8_t> mask{ 0xFF, 0x00, 0xFF };
    const std::vector<uint8_t> buffer{ 0x41, 0x42 };

    EXPECT_TRUE(FindAll(pattern, mask, buffer).empty());
}

// ---------------------------------------------------------------------------
// Compiler: what a '??' in authored content becomes
// ---------------------------------------------------------------------------

TEST(MaskedPattern, WildcardTextCompilesToAMaskedPattern) {
    PatternMode mode = PatternMode::Exact;
    std::vector<uint8_t> mask;

    const auto compiled = PatternCompiler::CompilePattern("48 8B ?? C3", mode, mask);
    ASSERT_TRUE(compiled.has_value());

    EXPECT_EQ(mode, PatternMode::Wildcard);
    ASSERT_EQ(compiled->size(), 4u);
    ASSERT_EQ(mask.size(), 4u);

    EXPECT_EQ((*compiled)[0], 0x48);
    EXPECT_EQ((*compiled)[1], 0x8B);
    EXPECT_EQ((*compiled)[3], 0xC3);

    EXPECT_EQ(mask[0], 0xFF);
    EXPECT_EQ(mask[1], 0xFF);
    EXPECT_EQ(mask[2], 0x00);
    EXPECT_EQ(mask[3], 0xFF);
}

TEST(MaskedPattern, ExactTextCompilesWithAFullyExactMask) {
    PatternMode mode = PatternMode::Wildcard;
    std::vector<uint8_t> mask;

    const auto compiled = PatternCompiler::CompilePattern("48 8B 05 C3", mode, mask);
    ASSERT_TRUE(compiled.has_value());

    EXPECT_EQ(mode, PatternMode::Exact);
    ASSERT_EQ(mask.size(), 4u);
    for (const uint8_t m : mask) {
        EXPECT_EQ(m, 0xFF);
    }
}

// A compiled wildcard pattern must be matchable by the matcher the store builds
// for it. This is the end-to-end shape of task 60 at unit scale: compile the text
// an author writes, hand the result to the matcher the store would use, and
// require it to find a concrete instance.
TEST(MaskedPattern, CompiledWildcardPatternIsMatchedByTheStoresMatcher) {
    PatternMode mode = PatternMode::Exact;
    std::vector<uint8_t> mask;
    const auto compiled = PatternCompiler::CompilePattern("48 8B ?? C3", mode, mask);
    ASSERT_TRUE(compiled.has_value());
    ASSERT_EQ(mode, PatternMode::Wildcard);

    const BoyerMooreMatcher matcher(*compiled, mask);
    ASSERT_TRUE(matcher.IsValid());

    std::vector<uint8_t> buffer(64, 0x41);
    buffer.push_back(0x48);
    buffer.push_back(0x8B);
    buffer.push_back(0x7E);   // the wildcard position, deliberately not 0x00
    buffer.push_back(0xC3);
    buffer.insert(buffer.end(), 64, 0x42);

    const auto hits = matcher.Search(buffer);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], 64u);

    // Negative: destroy a fixed byte and the pattern must stop matching.
    buffer[65] = 0x8C;
    EXPECT_TRUE(matcher.Search(buffer).empty());
}
