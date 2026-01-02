/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - URL Pattern Matcher
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Aho-Corasick automaton for URL pattern matching
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {
    namespace ThreatIntel {

        // ============================================================================
        // AhoCorasickAutomaton Declaration
        // ============================================================================

        class AhoCorasickAutomaton {
        public:
            AhoCorasickAutomaton();
            ~AhoCorasickAutomaton();

            void AddPattern(std::string_view pattern, const IndexValue& value);
            void Build();

            [[nodiscard]] std::vector<IndexValue> Search(std::string_view text) const;
            [[nodiscard]] bool Contains(std::string_view pattern) const;
            void Remove(std::string_view pattern);
            void Clear() noexcept;

            [[nodiscard]] size_t GetPatternCount() const noexcept { return m_patternCount; }
            [[nodiscard]] bool IsBuilt() const noexcept { return m_built; }

        private:
            struct State;
            std::vector<std::unique_ptr<State>> m_states;
            size_t m_patternCount = 0;
            bool m_built = false;
            mutable std::shared_mutex m_mutex;
        };

        // ============================================================================
        // URLPatternMatcher Declaration
        // ============================================================================

        class URLPatternMatcher {
        public:
            URLPatternMatcher();
            ~URLPatternMatcher() = default;

            void AddPattern(std::string_view urlPattern, const IndexValue& value);
            void Build();

            [[nodiscard]] std::vector<IndexValue> Match(std::string_view url) const;
            [[nodiscard]] bool Contains(std::string_view pattern) const;
            void Remove(std::string_view pattern);
            void Clear() noexcept;

            [[nodiscard]] size_t GetPatternCount() const noexcept;

        private:
            AhoCorasickAutomaton m_automaton;
            std::vector<std::pair<std::string, IndexValue>> m_patterns;
            bool m_needsRebuild = false;
            mutable std::shared_mutex m_mutex;
        };

    } // namespace ThreatIntel
} // namespace ShadowStrike