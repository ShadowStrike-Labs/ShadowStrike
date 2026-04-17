/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#pragma once

#include "Products/Community/PhantomEDR/AssetInventory/AssetTypes.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

class SoftwareInventoryImpl;

class SoftwareInventory final {
public:
    [[nodiscard]] static SoftwareInventory& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::vector<SoftwareInfo> EnumerateInstalledSoftware() const;
    [[nodiscard]] bool PersistInventory(std::string_view assetId, const std::vector<SoftwareInfo>& software);
    [[nodiscard]] std::vector<SoftwareInfo> GetInstalledSoftware(std::string_view assetId) const;
    [[nodiscard]] std::vector<SoftwareInfo> GetVersionChanges(std::string_view assetId) const;
    [[nodiscard]] std::vector<SoftwareInfo> ScanAndStore(std::string_view assetId);

private:
    SoftwareInventory();
    ~SoftwareInventory();
    SoftwareInventory(const SoftwareInventory&) = delete;
    SoftwareInventory& operator=(const SoftwareInventory&) = delete;
    SoftwareInventory(SoftwareInventory&&) = delete;
    SoftwareInventory& operator=(SoftwareInventory&&) = delete;

    std::unique_ptr<SoftwareInventoryImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
