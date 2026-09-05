/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModuleCatalog.hpp
 * @brief Authoritative UI-facing metadata catalog for every PhantomHome
 *        protection module.
 *
 * ViewModels and QML bindings query this catalog instead of the internal
 * HomeProductOrchestrator::ModuleDescriptor.  The catalog maps each module's
 * stable id (matching the orchestrator registration name exactly) to display
 * metadata: localisation key, icon, category, supported operating modes, and
 * optional QML detail-page route.
 *
 * Design:
 *   - Meyers' singleton; populated at construction; immutable thereafter.
 *   - No Qt dependency; safe to include from pure C++ service code.
 *   - The catalog entries carry a supportedModesMask that MUST agree with
 *     the wiring file's ModuleDescriptor::supportedModesMask.  Any drift is
 *     caught at integration test time.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::Home::UI {

/**
 * @brief High-level grouping shown in the UI navigation tree.
 *        Values are stable; do NOT renumber — they may be persisted
 *        by the UI layer.
 */
enum class ModuleCategory : std::uint8_t {
    RealtimeProtection    = 0,  ///< File AV, AMSI, real-time behaviour.
    BehavioralSecurity    = 1,  ///< PhantomSentry, ZeroTrustGuard.
    NetworkSecurity       = 2,  ///< NAB, DNS leak, IP leak, Wi-Fi checks.
    WebAndEmail           = 3,  ///< Web proxy, email, phishing, ad/tracker block.
    PrivacyProtection     = 4,  ///< Webcam, mic, location, cookie, cleaner.
    DataAndBackup         = 5,  ///< Backup, DLP.
    SpecializedProtection = 6,  ///< Banking, crypto miners, IoT, USB, game mode.
};

/**
 * @brief Single row in the module catalog.
 *
 * All string fields are immutable after construction.
 * supportedModesMask bits use the same encoding as ProtectionModeMask()
 * in HomeProductOrchestrator.hpp:
 *   bit 0 = Off, bit 1 = Passive, bit 2 = Balanced, bit 3 = Aggressive.
 */
struct CatalogEntry {
    /// Stable canonical id — MUST match the name used in RegisterModule().
    std::string id;

    /// Qt tr() localisation key for the module display name.
    std::string displayNameKey;

    /// Qt tr() localisation key for the module description.
    std::string descriptionKey;

    /// Icon identifier matching the QML Icons/ qmldir exports
    /// Lower-case, and it must match a file registered in assets.qrc under
    /// the /icons prefix (e.g. "shield", "lock", "eye", "globe", "archive").
    /// QRC LOOKUP IS CASE-SENSITIVE: capitalised ids here resolved to
    /// nothing at runtime and produced 3,600 of the 3,721 UI warnings in
    /// the 1.0.109 field run, one per delegate rebuild, with no icon drawn.
    std::string iconId;

    ModuleCategory category;

    /// Bitmask of ProtectionMode values this module supports, matching
    /// ModuleDescriptor::supportedModesMask in the wiring file.
    /// Bit encoding: Off=bit0, Passive=bit1, Balanced=bit2, Aggressive=bit3.
    std::uint8_t supportedModesMask;

    /// True for modules that are purely binary (on/off) with no graduated
    /// intensity — e.g. BackupManager, GameModeManager, PrivacyCleaner.
    bool binary;

    /// QML filename for the module detail page.  Empty string = no detail page.
    std::string detailPage;

    /// Reserved for future premium-tier gating.  Always false in Community.
    bool premium;
};

// ============================================================================
// ModuleCatalog
// ============================================================================

/**
 * @class ModuleCatalog
 * @brief Immutable, singleton catalog of all PhantomHome protection modules.
 *
 * Usage:
 *   auto& cat = ModuleCatalog::Instance();
 *   const CatalogEntry* e = cat.FindById("ZeroTrustGuard");
 */
class ModuleCatalog final {
public:
    [[nodiscard]] static const ModuleCatalog& Instance();

    ModuleCatalog(const ModuleCatalog&)            = delete;
    ModuleCatalog& operator=(const ModuleCatalog&) = delete;
    ModuleCatalog(ModuleCatalog&&)                 = delete;
    ModuleCatalog& operator=(ModuleCatalog&&)      = delete;

    /// All catalog entries in registration order.
    [[nodiscard]] std::span<const CatalogEntry> All() const noexcept;

    /// Lookup by stable module id.  Returns nullptr if not found.
    [[nodiscard]] const CatalogEntry* FindById(std::string_view id) const noexcept;

    /// All entries belonging to the given category.
    [[nodiscard]] std::vector<const CatalogEntry*> ByCategory(ModuleCategory cat) const;

private:
    ModuleCatalog();
    ~ModuleCatalog() = default;

    std::vector<CatalogEntry> m_entries;
};

// ============================================================================
// Free helper
// ============================================================================

/**
 * @brief Return the supportedModesMask for a module.
 *
 * Consults ModuleCatalog first.  Falls back to the orchestrator's registered
 * descriptor if the module is not in the catalog (e.g. internal or test
 * modules).  Returns 0 if the module is unknown in both.
 *
 * @param id  Stable module id (matches RegisterModule name).
 */
[[nodiscard]] std::uint8_t GetSupportedModesForId(std::string_view id) noexcept;

}  // namespace ShadowStrike::Products::Home::UI
