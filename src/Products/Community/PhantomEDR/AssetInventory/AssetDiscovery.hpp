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

#include <chrono>
#include <memory>
#include <optional>

namespace ShadowStrike::Products::PhantomEDR::AssetInventory {

class AssetDiscoveryImpl;

class AssetDiscovery final {
public:
    [[nodiscard]] static AssetDiscovery& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::optional<AssetRecord> DiscoverNow();
    [[nodiscard]] std::optional<AssetRecord> GetCachedRecord() const;
    void SetRediscoveryInterval(std::chrono::minutes interval);
    [[nodiscard]] std::chrono::minutes GetRediscoveryInterval() const;

private:
    AssetDiscovery();
    ~AssetDiscovery();
    AssetDiscovery(const AssetDiscovery&) = delete;
    AssetDiscovery& operator=(const AssetDiscovery&) = delete;
    AssetDiscovery(AssetDiscovery&&) = delete;
    AssetDiscovery& operator=(AssetDiscovery&&) = delete;

    std::unique_ptr<AssetDiscoveryImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::AssetInventory
