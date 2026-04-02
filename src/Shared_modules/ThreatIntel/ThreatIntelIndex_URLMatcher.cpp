/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - URL Pattern Matcher Implementation
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 *
 * Enterprise-grade Aho-Corasick automaton for URL multi-pattern matching.
 * 
 * Performance Targets:
 * - Pattern addition: O(m) per pattern
 * - Automaton build: O(m) total for all patterns  
 * - Text search: O(n) + O(z) for output
 * - Memory: ~256 bytes per automaton state
 *
 * Thread Safety:
 * - Reader-writer lock for concurrent reads
 * - Build operation requires exclusive access
 *
 * ============================================================================
 */

#include "ThreatIntelIndex_Internal.hpp"
#include "ThreatIntelIndex_URLMatcher.hpp"

#include <algorithm>
#include <queue>
#include <unordered_map>
#include <unordered_set>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// CONSTANTS
// ============================================================================

// Note: CACHE_LINE_SIZE is defined in ThreatIntelFormat.hpp, using it from there
static constexpr size_t MAX_URL_PATTERN_LENGTH = 4096;
static constexpr size_t MAX_URL_SEARCH_LENGTH = 65536;
static constexpr size_t MAX_SEARCH_MATCHES = 10000;

// ============================================================================
// AhoCorasickAutomaton::State - Internal Structure Definition
// ============================================================================

/**
 * @brief Cache-aligned automaton state for optimal memory access
 */
struct alignas(CACHE_LINE_SIZE) AhoCorasickAutomaton::State {
    /// Transition table for ASCII characters (256 entries)
    /// Using int32_t for compact storage (-1 = no transition)
    std::array<int32_t, 256> transitions;
    
    /// Failure link - state to go on mismatch
    int32_t failureLink{ 0 };
    
    /// Dictionary suffix link - nearest state with output
    int32_t dictionarySuffixLink{ -1 };
    
    /// Pattern output (if terminal state)
    IndexValue output{};
    
    /// Is this a terminal state (pattern ends here)
    bool isTerminal{ false };
    
    /// Reserved for alignment
    uint8_t reserved[7]{};
    
    State() noexcept {
        transitions.fill(-1);
    }
};

// ============================================================================
// AHO-CORASICK AUTOMATON IMPLEMENTATION
// ============================================================================

AhoCorasickAutomaton::AhoCorasickAutomaton()
    : m_states()
    , m_patternCount(0)
    , m_built(false) {
    // Initialize with root state
    m_states.push_back(std::make_unique<State>());
}

AhoCorasickAutomaton::~AhoCorasickAutomaton() = default;

/**
 * @brief Add a pattern to the automaton
 * @param pattern URL pattern to add
 * @param value Index value for this pattern
 *
 * Note: After adding all patterns, call Build() to construct failure links
 */
void AhoCorasickAutomaton::AddPattern(std::string_view pattern, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (pattern.empty() || pattern.size() > MAX_URL_PATTERN_LENGTH) {
        return;
    }
    
    if (m_states.size() + pattern.size() > MAX_STATES) {
        return;
    }
    
    int32_t currentState = 0;
    
    // Build trie path for pattern
    for (size_t i = 0; i < pattern.size(); ++i) {
        const uint8_t c = static_cast<uint8_t>(pattern[i]);
        
        int32_t nextState = m_states[currentState]->transitions[c];
        
        if (nextState == -1) {
            // Create new state
            nextState = static_cast<int32_t>(m_states.size());
            m_states.push_back(std::make_unique<State>());
            m_states[currentState]->transitions[c] = nextState;
        }
        
        currentState = nextState;
    }
    
    // Mark terminal state and store output
    m_states[currentState]->isTerminal = true;
    m_states[currentState]->output = value;
    
    ++m_patternCount;
    m_built = false;
}

/**
 * @brief Full rebuild from a pattern list — clears all states and rebuilds from scratch.
 * This avoids the infinite-loop bug where filled shortcut transitions
 * are mistaken for real trie edges on subsequent Build() calls.
 */
void AhoCorasickAutomaton::RebuildFrom(
    const std::vector<std::pair<std::string, IndexValue>>& patterns)
{
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    m_states.clear();
    m_states.push_back(std::make_unique<State>());
    m_patternCount = 0;
    m_built = false;

    // Re-add all patterns (lock already held, call unlocked internals)
    for (const auto& [pat, val] : patterns) {
        if (pat.empty() || pat.size() > MAX_URL_PATTERN_LENGTH) continue;
        if (m_states.size() + pat.size() > MAX_STATES) break;

        int32_t cur = 0;
        for (size_t i = 0; i < pat.size(); ++i) {
            const uint8_t c = static_cast<uint8_t>(pat[i]);
            int32_t next = m_states[cur]->transitions[c];
            if (next == -1) {
                next = static_cast<int32_t>(m_states.size());
                m_states.push_back(std::make_unique<State>());
                m_states[cur]->transitions[c] = next;
            }
            cur = next;
        }
        m_states[cur]->isTerminal = true;
        m_states[cur]->output = val;
        ++m_patternCount;
    }

    // Now run BFS to build failure links (same logic as Build, but under same lock)
    if (m_states.size() <= 1) {
        m_built = true;
        return;
    }

    std::queue<int32_t> bfsQueue;

    for (int c = 0; c < 256; ++c) {
        const int32_t s = m_states[0]->transitions[c];
        if (s > 0) {
            m_states[s]->failureLink = 0;
            bfsQueue.push(s);
        } else if (s == -1) {
            m_states[0]->transitions[c] = 0;
        }
    }

    while (!bfsQueue.empty()) {
        const int32_t currentState = bfsQueue.front();
        bfsQueue.pop();

        for (int c = 0; c < 256; ++c) {
            const int32_t nextState = m_states[currentState]->transitions[c];

            if (nextState <= 0) {
                const int32_t failTrans = m_states[m_states[currentState]->failureLink]->transitions[c];
                m_states[currentState]->transitions[c] = (failTrans >= 0) ? failTrans : 0;
                continue;
            }

            bfsQueue.push(nextState);

            int32_t failState = m_states[currentState]->failureLink;
            while (failState > 0 && m_states[failState]->transitions[c] <= 0) {
                failState = m_states[failState]->failureLink;
            }

            const int32_t failTrans = m_states[failState]->transitions[c];
            m_states[nextState]->failureLink = (failTrans > 0 && failTrans != nextState) ? failTrans : 0;

            const int32_t fl = m_states[nextState]->failureLink;
            if (m_states[fl]->isTerminal) {
                m_states[nextState]->dictionarySuffixLink = fl;
            } else {
                m_states[nextState]->dictionarySuffixLink = m_states[fl]->dictionarySuffixLink;
            }
        }
    }

    m_built = true;
}

/**
 * @brief Build failure links and dictionary suffix links
 *
 * Must be called after adding all patterns and before searching.
 * Uses BFS to compute failure links in O(m) time.
 */
void AhoCorasickAutomaton::Build() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (m_built || m_states.size() <= 1) {
        return;
    }
    
    // BFS queue for level-order traversal
    std::queue<int32_t> bfsQueue;
    
    // Initialize depth-1 states (children of root)
    for (int c = 0; c < 256; ++c) {
        const int32_t s = m_states[0]->transitions[c];
        if (s > 0) {
            m_states[s]->failureLink = 0;
            bfsQueue.push(s);
        } else if (s == -1) {
            // Root loops to itself on missing transitions
            m_states[0]->transitions[c] = 0;
        }
    }
    
    // BFS to compute failure links
    while (!bfsQueue.empty()) {
        const int32_t currentState = bfsQueue.front();
        bfsQueue.pop();
        
        // Process each transition from current state
        for (int c = 0; c < 256; ++c) {
            const int32_t nextState = m_states[currentState]->transitions[c];
            
            if (nextState <= 0) {
                // No transition - use failure link's transition
                const int32_t failTrans = m_states[m_states[currentState]->failureLink]->transitions[c];
                m_states[currentState]->transitions[c] = (failTrans >= 0) ? failTrans : 0;
                continue;
            }
            
            bfsQueue.push(nextState);
            
            // Compute failure link - follow failure chain until valid transition
            int32_t failState = m_states[currentState]->failureLink;
            while (failState > 0 && m_states[failState]->transitions[c] <= 0) {
                failState = m_states[failState]->failureLink;
            }
            
            const int32_t failTrans = m_states[failState]->transitions[c];
            m_states[nextState]->failureLink = (failTrans > 0 && failTrans != nextState) ? failTrans : 0;
            
            // Compute dictionary suffix link (nearest ancestor with output)
            const int32_t fl = m_states[nextState]->failureLink;
            if (m_states[fl]->isTerminal) {
                m_states[nextState]->dictionarySuffixLink = fl;
            } else {
                m_states[nextState]->dictionarySuffixLink = m_states[fl]->dictionarySuffixLink;
            }
        }
    }
    
    m_built = true;
}

/**
 * @brief Search for all pattern matches in text
 * @param text Text to search
 * @return Vector of all matching IndexValues
 */
std::vector<IndexValue> AhoCorasickAutomaton::Search(std::string_view text) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    std::vector<IndexValue> matches;
    
    if (text.empty() || !m_built || text.size() > MAX_URL_SEARCH_LENGTH) {
        return matches;
    }
    
    matches.reserve(16);
    
    int32_t currentState = 0;
    
    for (size_t i = 0; i < text.size(); ++i) {
        const uint8_t c = static_cast<uint8_t>(text[i]);
        
        currentState = m_states[currentState]->transitions[c];
        
        if (m_states[currentState]->isTerminal) {
            matches.push_back(m_states[currentState]->output);
            if (matches.size() >= MAX_SEARCH_MATCHES) return matches;
        }
        
        int32_t dictSuffix = m_states[currentState]->dictionarySuffixLink;
        while (dictSuffix > 0) {
            if (m_states[dictSuffix]->isTerminal) {
                matches.push_back(m_states[dictSuffix]->output);
                if (matches.size() >= MAX_SEARCH_MATCHES) return matches;
            }
            dictSuffix = m_states[dictSuffix]->dictionarySuffixLink;
        }
    }
    
    return matches;
}

/**
 * @brief Check if a specific pattern exists
 */
bool AhoCorasickAutomaton::Contains(std::string_view pattern) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    if (pattern.empty()) {
        return false;
    }
    
    int32_t currentState = 0;
    
    for (size_t i = 0; i < pattern.size(); ++i) {
        const uint8_t c = static_cast<uint8_t>(pattern[i]);
        const int32_t nextState = m_states[currentState]->transitions[c];
        
        if (nextState <= 0) {
            return false;
        }
        
        currentState = nextState;
    }
    
    return m_states[currentState]->isTerminal;
}

void AhoCorasickAutomaton::Remove(std::string_view pattern) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (pattern.empty()) {
        return;
    }
    
    int32_t currentState = 0;
    
    for (size_t i = 0; i < pattern.size(); ++i) {
        const uint8_t c = static_cast<uint8_t>(pattern[i]);
        const int32_t nextState = m_states[currentState]->transitions[c];
        
        if (nextState <= 0) {
            return;  // Pattern not found
        }
        
        currentState = nextState;
    }
    
    if (m_states[currentState]->isTerminal) {
        m_states[currentState]->isTerminal = false;
        m_states[currentState]->output = {};
        --m_patternCount;
        m_built = false;  // Need rebuild for proper cleanup
    }
}

void AhoCorasickAutomaton::Clear() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    auto root = std::make_unique<State>();
    m_states.clear();
    m_states.push_back(std::move(root));
    m_patternCount = 0;
    m_built = false;
}

// ============================================================================
// URL PATTERN MATCHER IMPLEMENTATION
// ============================================================================

URLPatternMatcher::URLPatternMatcher()
    : m_automaton()
    , m_patterns()
    , m_needsRebuild(false) {
}

/**
 * @brief Add a URL pattern to the matcher
 * @param urlPattern URL pattern to add
 * @param value Index value for this pattern
 * @return true if added successfully
 */
bool URLPatternMatcher::AddPattern(std::string_view urlPattern, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (urlPattern.empty() || urlPattern.size() > MAX_URL_PATTERN_LENGTH) {
        return false;
    }
    
    // Check for duplicates (URL-8)
    for (auto& [existing, existingVal] : m_patterns) {
        if (existing == urlPattern) {
            existingVal = value;
            m_needsRebuild = true;
            return false;
        }
    }
    
    try {
        m_patterns.emplace_back(std::string(urlPattern), value);
        m_automaton.AddPattern(urlPattern, value);
        m_needsRebuild = true;
        
        return true;
    }
    catch (const std::bad_alloc&) {
        return false;
    }
}

void URLPatternMatcher::Build() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (m_needsRebuild || !m_automaton.IsBuilt()) {
        // Always do a full rebuild from m_patterns to avoid the
        // infinite-loop bug where filled shortcut transitions are
        // mistaken for real trie edges on subsequent Build() calls.
        m_automaton.RebuildFrom(m_patterns);
        m_needsRebuild = false;
    }
}

/**
 * @brief Insert URL pattern (alias for AddPattern)
 */
bool URLPatternMatcher::Insert(std::string_view urlPattern, const IndexValue& value) {
    return AddPattern(urlPattern, value);
}

/**
 * @brief Lookup a URL and return the first match
 * @param url URL to lookup
 * @param outValue Output parameter for result
 * @return true if found, false otherwise
 */
bool URLPatternMatcher::Lookup(std::string_view url, IndexValue& outValue) {
    if (url.empty() || url.size() > MAX_URL_SEARCH_LENGTH) {
        return false;
    }
    
    // Hold exclusive lock for the entire operation to avoid TOCTOU
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (m_needsRebuild || !m_automaton.IsBuilt()) {
        m_automaton.RebuildFrom(m_patterns);
        m_needsRebuild = false;
    }
    
    auto matches = m_automaton.Search(url);
    
    if (!matches.empty()) {
        outValue = matches.front();
        return true;
    }
    
    return false;
}

/**
 * @brief Match URL against all patterns
 * @param url URL to match
 * @return Vector of all matching IndexValues
 */
std::vector<IndexValue> URLPatternMatcher::Match(std::string_view url) {
    if (url.empty() || url.size() > MAX_URL_SEARCH_LENGTH) {
        return {};
    }
    
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (m_needsRebuild || !m_automaton.IsBuilt()) {
        m_automaton.RebuildFrom(m_patterns);
        m_needsRebuild = false;
    }
    
    return m_automaton.Search(url);
}

bool URLPatternMatcher::Contains(std::string_view pattern) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    // Use m_patterns as the authoritative membership check,
    // NOT the automaton (whose filled transitions cause false positives)
    return std::any_of(m_patterns.begin(), m_patterns.end(),
        [&pattern](const auto& p) { return p.first == pattern; });
}

bool URLPatternMatcher::Remove(std::string_view pattern) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (pattern.empty()) {
        return false;
    }
    
    // Check m_patterns (authoritative), not the automaton
    auto it = std::find_if(m_patterns.begin(), m_patterns.end(),
        [&pattern](const auto& p) { return p.first == pattern; });
    
    if (it == m_patterns.end()) {
        return false;
    }
    
    m_patterns.erase(it);
    m_needsRebuild = true;
    
    return true;
}

void URLPatternMatcher::Clear() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    m_automaton.Clear();
    m_patterns.clear();
    m_needsRebuild = false;
}

size_t URLPatternMatcher::GetPatternCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_automaton.GetPatternCount();
}

size_t URLPatternMatcher::GetStateCount() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    // Return actual number of states in the Aho-Corasick automaton
    // Each state represents a unique prefix seen during pattern addition
    return m_automaton.GetStateCount();
}

size_t URLPatternMatcher::GetMemoryUsage() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    // Pattern strings
    size_t patternBytes = 0;
    for (const auto& [pattern, value] : m_patterns) {
        patternBytes += pattern.capacity() + sizeof(IndexValue);
    }
    
    // Vector overhead
    patternBytes += m_patterns.capacity() * sizeof(std::pair<std::string, IndexValue>);
    
    // Automaton states (approximate)
    // Each state has 256 transitions (int32_t each) + failure link + output
    constexpr size_t APPROX_STATE_SIZE = 256 * sizeof(int32_t) + sizeof(int32_t) + sizeof(IndexValue) + sizeof(bool) + 7;
    const size_t automatonBytes = m_automaton.GetStateCount() * APPROX_STATE_SIZE;
    
    return patternBytes + automatonBytes;
}

} // namespace ThreatIntel
} // namespace ShadowStrike
