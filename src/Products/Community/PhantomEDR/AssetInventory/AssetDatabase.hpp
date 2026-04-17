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
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

class AssetDatabaseImpl;

class AssetDatabase final {
public:
    [[nodiscard]] static AssetDatabase& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] bool UpsertAssetRecord(const AssetRecord& record);
    [[nodiscard]] std::optional<AssetRecord> GetAssetRecord(std::string_view assetId) const;
    [[nodiscard]] std::vector<AssetRecord> QueryAssetsByField(
        std::string_view fieldName,
        std::string_view value) const;
    [[nodiscard]] std::vector<PatchInfo> GetInstalledPatches(std::string_view assetId) const;
    [[nodiscard]] bool DeleteAssetRecord(std::string_view assetId);
    [[nodiscard]] std::wstring GetDatabasePath() const;

private:
    AssetDatabase();
    ~AssetDatabase();
    AssetDatabase(const AssetDatabase&) = delete;
    AssetDatabase& operator=(const AssetDatabase&) = delete;
    AssetDatabase(AssetDatabase&&) = delete;
    AssetDatabase& operator=(AssetDatabase&&) = delete;

    std::unique_ptr<AssetDatabaseImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
