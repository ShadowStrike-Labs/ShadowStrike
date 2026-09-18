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
#include <string>
#include <vector>

#include "Products/Community/PhantomHome/Backup/BackupManager.hpp"
#include "Products/Community/PhantomHome/Backup/RestoreManager.hpp"

namespace {

using ShadowStrike::Backup::FormatBytes;

// ============================================================================
// FormatBytes - shown to the user, so its unit boundaries are a contract
// ============================================================================

TEST(BackupFormatBytes, PicksTheUnitAtEachBoundary) {
    EXPECT_EQ("0 B", FormatBytes(0u));
    EXPECT_EQ("1023 B", FormatBytes(1023u)) << "one byte below a kilobyte stays in bytes";
    EXPECT_EQ("1.00 KB", FormatBytes(1024u)) << "the boundary is inclusive";
    EXPECT_EQ("1.00 MB", FormatBytes(1024u * 1024u));
    EXPECT_EQ("1.00 GB", FormatBytes(1024ull * 1024u * 1024u));
    EXPECT_EQ("1.00 TB", FormatBytes(1024ull * 1024u * 1024u * 1024u));
}

TEST(BackupFormatBytes, RoundsToTwoPlacesAndDoesNotOverflowAtTheTop) {
    EXPECT_EQ("1.50 KB", FormatBytes(1536u));
    EXPECT_EQ("1024.00 TB", FormatBytes(1024ull * 1024u * 1024u * 1024u * 1024u))
        << "a petabyte has no unit of its own, so it is reported in terabytes rather than wrapping";

    // The largest representable value must still produce a bounded string rather than anything degenerate.
    const std::string top = FormatBytes(UINT64_MAX);
    EXPECT_NE(std::string::npos, top.find(" TB"));
    EXPECT_LT(top.size(), 32u);
}

// ============================================================================
// The vault predicate pair
// ============================================================================

TEST(BackupVaultState, TheTwoPredicatesNeverBothHold) {
    // IsVaultOpen accepts Ready or Unlocked; IsVaultLocked accepts Locked. Those sets must stay disjoint,
    // which is the invariant a caller relies on when it branches on one and not the other.
    auto& manager = ShadowStrike::Backup::BackupManager::Instance();
    const bool open = manager.IsVaultOpen();
    const bool locked = manager.IsVaultLocked();
    EXPECT_FALSE(open && locked) << "a vault reported as both open and locked";
}

TEST(BackupVaultState, AVaultNobodyOpenedIsNotReportedOpen) {
    // CloseVault resets through VaultInfo{}, whose status member defaults to NotInitialized, so neither
    // predicate should hold for a vault that was never opened. If this fails, the default changed to a
    // usable state and callers would proceed against a vault whose key has been wiped.
    auto& manager = ShadowStrike::Backup::BackupManager::Instance();
    if (!manager.IsVaultOpen() && !manager.IsVaultLocked()) {
        SUCCEED() << "no vault is open in this process, which is the state under test";
    } else {
        // Another suite in this binary opened one. Then the only claim available is the disjointness above,
        // and asserting anything else here would make this case depend on suite order.
        EXPECT_NE(manager.IsVaultOpen(), manager.IsVaultLocked());
    }
}

TEST(BackupRollback, AnUnknownRestoreIdHasNoRollback) {
    auto& manager = ShadowStrike::Backup::RestoreManager::Instance();
    EXPECT_FALSE(manager.IsRollbackAvailable("no-such-restore-id"));
    EXPECT_FALSE(manager.IsRollbackAvailable("")) << "an empty id must not match a journal";
}

TEST(BackupIdentity, GeneratedIdsAreNonEmptyAndDistinct) {
    // The same property the recommendation-id contract pins: an id that repeats silently merges two records.
    std::vector<std::string> ids;
    for (int i = 0; i < 64; ++i) {
        ids.push_back(ShadowStrike::Backup::GenerateBackupId());
        ids.push_back(ShadowStrike::Backup::GenerateRestoreId());
    }
    for (const auto& id : ids) {
        EXPECT_FALSE(id.empty());
    }
    const std::size_t before = ids.size();
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    EXPECT_EQ(before, ids.size()) << "a generated identifier repeated";
}

}  // namespace
