/**
 * ============================================================================
 * ShadowStrike Ransomware - VOLUME SNAPSHOT SERVICE (The Backupper)
 * ============================================================================
 *
 * @file VolumeSnapshotService.hpp
 * @brief Wrapper for the Windows VSS API.
 *
 * This module allows ShadowStrike to programmatically create and restore
 * shadow copies without relying on external tools.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Ransomware {

        class VolumeSnapshotService {
        public:
            static VolumeSnapshotService& Instance();

            /**
             * @brief Create a new snapshot of a drive.
             */
            bool CreateSnapshot(const std::wstring& driveLetter);

            /**
             * @brief List all current snapshots.
             */
            std::vector<std::wstring> EnumSnapshots();

        private:
            VolumeSnapshotService() = default;
        };

    } // namespace Ransomware
} // namespace ShadowStrike
