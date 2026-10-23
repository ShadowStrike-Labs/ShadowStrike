/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/*
 * Every ShadowStrike::Backup header in ONE translation unit (task 302).
 *
 * BackupManager, BackupScheduler and IncrementalBackup each declared
 * ShadowStrike::Backup::ModuleStatus with different enumerators - value 4 was
 * Restoring in one and Paused in the other two - and BackupManager and
 * IncrementalBackup both declared ProgressCallback and CompletionCallback as
 * different function types. They are different state machines and different
 * events, so each now carries its module's name, as RestoreModuleStatus already
 * did. This file compiling IS the test.
 */

#include "pch.h"

#include <gtest/gtest.h>
#include <type_traits>

#include "Products/Community/PhantomHome/Backup/BackupManager.hpp"
#include "Products/Community/PhantomHome/Backup/BackupScheduler.hpp"
#include "Products/Community/PhantomHome/Backup/IncrementalBackup.hpp"
#include "Products/Community/PhantomHome/Backup/RestoreManager.hpp"

namespace Backup = ShadowStrike::Backup;

static_assert(!std::is_same_v<Backup::BackupProgressCallback, Backup::SyncProgressCallback>,
              "a backup progress event and a sync progress event are different callbacks");
static_assert(static_cast<int>(Backup::BackupModuleStatus::Restoring) == 4);
static_assert(static_cast<int>(Backup::SchedulerModuleStatus::Paused) == 4);
static_assert(static_cast<int>(Backup::IncrementalModuleStatus::Ready) == 2);

TEST(BackupHeaders, AllFourComposeInOneTranslationUnit) {
    SUCCEED() << "compiled with every Backup header included together";
}
