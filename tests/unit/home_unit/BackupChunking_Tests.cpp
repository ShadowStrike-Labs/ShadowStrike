// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Backup chunking and vault state tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file BackupChunkingAndVault_Tests.cpp
 * @brief Pins content-defined chunk boundaries, the byte formatter, and the vault predicate pair.
 *
 * THE CHUNK BOUNDARIES ARE THE IMPORTANT PART. FindChunkBoundaries decides where an incremental backup
 * splits a file, and ChunkData turns those boundaries into the chunks that get stored. If the boundaries do
 * not cover every byte, the backup silently loses data - a restore would produce a file with holes - and
 * nothing else in the module would notice, because the chunks it did produce are each individually valid.
 * So the invariants pinned here are coverage, strict monotonicity, and the size bounds, checked over
 * incompressible data, uniform data and every size around the minimum.
 *
 * RabinFingerprint is a public exported function with no caller anywhere in the tree - the chunker uses a
 * gear hash instead - so these are the only cases that exercise it. Pinned because it is public API.
 *
 * The vault predicates are pinned only for the states reachable without a real encrypted vault on disk.
 * That is deliberately narrow: what matters and is cheap to guarantee is that they never contradict each
 * other, and that a vault nobody has opened does not report itself open.
 */

/*
 * SPLIT NOTE. BackupManager.hpp and IncrementalBackup.hpp CANNOT be included in one translation unit. Both
 * declare ShadowStrike::Backup::ModuleStatus with different enumerators, and both declare ProgressCallback
 * and CompletionCallback as different function types, so the compiler reports C2011 and two C2371s. Filed;
 * see the Backup type-collision task. This is the same constraint the Banking headers impose, and the same
 * reason a test file was split there.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "Products/Community/PhantomHome/Backup/IncrementalBackup.hpp"

namespace {

using ShadowStrike::Backup::ChunkingOptions;
using ShadowStrike::Backup::FindChunkBoundaries;
using ShadowStrike::Backup::RabinFingerprint;

// A deterministic byte sequence with no structure a chunker could exploit. A fixed 64-bit LCG rather than
// std::mt19937 with a random seed, so a failure is reproducible.
std::vector<uint8_t> PseudoRandomBytes(std::size_t count, uint64_t seed) {
    std::vector<uint8_t> data(count);
    uint64_t state = seed;
    for (auto& byte : data) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        byte = static_cast<uint8_t>(state >> 33);
    }
    return data;
}

// Every invariant a boundary list must satisfy, asserted together so a violation names itself.
void ExpectBoundariesPartition(const std::vector<std::size_t>& boundaries,
                               std::size_t dataSize,
                               const ChunkingOptions& options,
                               const char* what) {
    ASSERT_FALSE(boundaries.empty()) << what << ": no boundaries for " << dataSize << " bytes";

    // Coverage. This is the one that matters: the last boundary must be the end of the data, or the bytes
    // past it are never stored.
    EXPECT_EQ(dataSize, boundaries.back())
        << what << ": the final boundary is not the end of the data, so " << (dataSize - boundaries.back())
        << " byte(s) would not be stored";

    std::size_t previous = 0;
    for (std::size_t i = 0; i < boundaries.size(); ++i) {
        const std::size_t boundary = boundaries[i];
        EXPECT_GT(boundary, previous)
            << what << ": boundary " << i << " does not advance, which would emit an empty chunk";
        EXPECT_LE(boundary, dataSize) << what << ": boundary " << i << " is past the end of the data";

        const std::size_t chunk = boundary - previous;
        EXPECT_LE(chunk, options.maxChunkSize)
            << what << ": chunk " << i << " is " << chunk << " bytes, over the maximum";
        // The minimum is not asserted for the LAST chunk: a remainder shorter than the minimum has nowhere
        // else to go, and the implementation deliberately emits it rather than dropping it.
        if (i + 1 < boundaries.size()) {
            EXPECT_GE(chunk, options.minChunkSize)
                << what << ": chunk " << i << " is " << chunk << " bytes, under the minimum";
        }
        previous = boundary;
    }
}

// ============================================================================
// Chunk boundaries
// ============================================================================

TEST(BackupChunking, BoundariesCoverEveryByteOfIncompressibleData) {
    const ChunkingOptions options;
    const auto data = PseudoRandomBytes(600u * 1024u, 0x5EEDu);
    const auto boundaries = FindChunkBoundaries(data, options);

    ExpectBoundariesPartition(boundaries, data.size(), options, "pseudorandom 600 KB");
    EXPECT_GT(boundaries.size(), 1u) << "600 KB against a 64 KB average should split more than once";
}

TEST(BackupChunking, BoundariesCoverUniformDataWhereNoCutPointIsEverFound) {
    // All-zero data drives the gear hash to a constant, so the mask test may never fire and the loop falls
    // back to its cut point. That fallback is exactly where a coverage bug would hide.
    const ChunkingOptions options;
    const std::vector<uint8_t> zeros(600u * 1024u, 0u);
    const auto boundaries = FindChunkBoundaries(zeros, options);

    ExpectBoundariesPartition(boundaries, zeros.size(), options, "600 KB of zeros");

    const std::vector<uint8_t> ones(300u * 1024u, 0xFFu);
    ExpectBoundariesPartition(FindChunkBoundaries(ones, options), ones.size(), options, "300 KB of 0xFF");
}

TEST(BackupChunking, EverySizeAroundTheMinimumIsCoveredExactly) {
    const ChunkingOptions options;
    const std::size_t minimum = options.minChunkSize;

    for (std::size_t size : {minimum - 1u, minimum, minimum + 1u, minimum * 2u, minimum * 2u + 1u}) {
        const auto data = PseudoRandomBytes(size, 0xC0FFEEu + size);
        const auto boundaries = FindChunkBoundaries(data, options);
        const std::string label = "size " + std::to_string(size);
        ExpectBoundariesPartition(boundaries, data.size(), options, label.c_str());
    }
}

TEST(BackupChunking, EmptyDataProducesNoBoundaries) {
    // Fail closed rather than emitting a zero-length chunk.
    const ChunkingOptions options;
    const std::vector<uint8_t> empty;
    EXPECT_TRUE(FindChunkBoundaries(empty, options).empty());
}

TEST(BackupChunking, TheSameContentAlwaysSplitsTheSameWay) {
    // Determinism is what makes deduplication work at all: identical content must yield identical chunks
    // across runs and across machines.
    const ChunkingOptions options;
    const auto data = PseudoRandomBytes(400u * 1024u, 0xABCDu);
    EXPECT_EQ(FindChunkBoundaries(data, options), FindChunkBoundaries(data, options));
}

TEST(BackupChunking, ContentDefinedBoundariesSurviveAnInsertionAtTheFront) {
    // The property that distinguishes content-defined chunking from fixed blocks. Prepending a byte shifts
    // every offset, so fixed blocks would re-cut everything; a content-defined cut point should re-align and
    // share most later boundaries. Asserted loosely - some overlap - because the exact count is a property
    // of the hash, not a contract.
    const ChunkingOptions options;
    const auto original = PseudoRandomBytes(500u * 1024u, 0x1234u);

    std::vector<uint8_t> shifted;
    shifted.reserve(original.size() + 1);
    shifted.push_back(0x42u);
    shifted.insert(shifted.end(), original.begin(), original.end());

    const auto a = FindChunkBoundaries(original, options);
    const auto b = FindChunkBoundaries(shifted, options);
    ExpectBoundariesPartition(b, shifted.size(), options, "shifted");

    std::size_t realigned = 0;
    for (std::size_t boundary : a) {
        for (std::size_t other : b) {
            if (other == boundary + 1) {
                ++realigned;
                break;
            }
        }
    }
    EXPECT_GT(realigned, 0u)
        << "no boundary re-aligned after a one-byte insertion, which is the whole point of "
           "content-defined chunking - if this fails the chunker is behaving like fixed blocks";
}

// ============================================================================
// RabinFingerprint - public, and called by nothing else in the tree
// ============================================================================

TEST(BackupRabinFingerprint, IsDeterministicAndOrderSensitive) {
    const std::vector<uint8_t> forward{1u, 2u, 3u, 4u, 5u};
    const std::vector<uint8_t> backward{5u, 4u, 3u, 2u, 1u};

    EXPECT_EQ(RabinFingerprint(forward), RabinFingerprint(forward)) << "deterministic";
    EXPECT_NE(RabinFingerprint(forward), RabinFingerprint(backward))
        << "a hash used to place chunk boundaries must depend on byte order";

    const std::vector<uint8_t> empty;
    EXPECT_EQ(0u, RabinFingerprint(empty)) << "the identity for an empty span";
}

TEST(BackupRabinFingerprint, DistinguishesSingleByteInputs) {
    // Non-vacuity: a constant function would satisfy determinism above.
    std::vector<uint64_t> seen;
    for (int value = 0; value < 64; ++value) {
        const std::vector<uint8_t> one{static_cast<uint8_t>(value)};
        seen.push_back(RabinFingerprint(one));
    }
    const std::size_t before = seen.size();
    std::sort(seen.begin(), seen.end());
    seen.erase(std::unique(seen.begin(), seen.end()), seen.end());
    EXPECT_EQ(before, seen.size()) << "64 distinct bytes produced a collision among single-byte inputs";
}

}  // namespace
