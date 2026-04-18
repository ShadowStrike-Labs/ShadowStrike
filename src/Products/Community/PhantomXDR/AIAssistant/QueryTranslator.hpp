/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

#include "Products/Community/PhantomXDR/AIAssistant/AssistantTypes.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

class QueryTranslatorImpl;

class QueryTranslator final {
public:
    [[nodiscard]] static QueryTranslator& Instance();
    [[nodiscard]] static bool HasInstance() noexcept;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    [[nodiscard]] std::optional<HuntQuery> TranslateToSSQL(std::string_view naturalLanguage);
    [[nodiscard]] std::optional<HuntQuery> TranslateToKQL(std::string_view naturalLanguage);
    [[nodiscard]] std::optional<HuntQuery> TranslateToSigma(std::string_view naturalLanguage);
    [[nodiscard]] std::vector<HuntQuery>   GetTranslationHistory(uint32_t limit) const;

private:
    QueryTranslator();
    ~QueryTranslator();
    QueryTranslator(const QueryTranslator&) = delete;
    QueryTranslator& operator=(const QueryTranslator&) = delete;

    std::unique_ptr<QueryTranslatorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant
