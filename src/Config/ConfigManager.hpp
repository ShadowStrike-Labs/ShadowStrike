/**
 * ============================================================================
 * ShadowStrike Configuration - CONFIG MANAGER (The Controller)
 * ============================================================================
 *
 * @file ConfigManager.hpp
 * @brief Unified interface for accessing all application settings.
 *
 * This module sits on top of the `Database::ConfigurationDB`. It provides a
 * type-safe way to get/set settings and handles hot-reloading notifications.
 *
 * Capabilities:
 * 1. Layered Config: Default -> Policy -> User.
 * 2. Encryption: Automatically encrypts sensitive fields via `CryptoManager`.
 * 3. Validation: Uses `ConfigurationDB` validation rules to prevent corrupt settings.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Database/ConfigurationDB.hpp"
#include <string>
#include <variant>

namespace ShadowStrike {
    namespace Config {

        class ConfigManager {
        public:
            static ConfigManager& Instance();

            /**
             * @brief Initialize the configuration system.
             */
            bool Initialize(const std::wstring& dbPath);

            /**
             * @brief Get a value with a default fallback.
             */
            template<typename T>
            T GetValue(const std::wstring& key, T defaultValue);

            /**
             * @brief Set a configuration value.
             */
            template<typename T>
            bool SetValue(const std::wstring& key, const T& value);

            /**
             * @brief Trigger a manual reload from disk.
             */
            void Reload();

        private:
            ConfigManager() = default;
        };

    } // namespace Config
} // namespace ShadowStrike
