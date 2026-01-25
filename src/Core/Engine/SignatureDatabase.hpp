/**
 * ============================================================================
 * ShadowStrike Core Engine - SIGNATURE DATABASE (The Registry)
 * ============================================================================
 *
 * @file SignatureDatabase.hpp
 * @brief Logic for managing and querying the master signature collections.
 *
 * This module acts as a high-level manager for the `SignatureStore`. It handles
 * the loading of multiple database files and provides a unified query interface.
 *
 * Integrations:
 * - **SignatureStore**: The underlying memory-mapped storage.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../SignatureStore/SignatureStore.hpp"
#include <string>
#include <vector>
#include <memory>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            class SignatureDatabase {
            public:
                static SignatureDatabase& Instance();

                /**
                 * @brief Load all signature databases from a directory.
                 */
                bool LoadAll(const std::wstring& directoryPath);

                /**
                 * @brief Check if a database needs an update.
                 */
                bool NeedsUpdate(const std::string& dbName);

                /**
                 * @brief Get version info for a specific database.
                 */
                std::string GetDatabaseVersion(const std::string& dbName);

            private:
                SignatureDatabase() = default;
                std::unique_ptr<SignatureStore::SignatureStore> m_masterStore;
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike
