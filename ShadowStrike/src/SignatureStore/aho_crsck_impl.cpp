

#include "PatternStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"


#include <algorithm>
#include <queue>
#include <cctype>
#include <sstream>
#include <bit>
#include <iomanip>
#include <string>
#include <iostream>
#include <chrono>
#include <mutex>

namespace ShadowStrike {
namespace SignatureStore {



// ============================================================================
// AHO-CORASICK AUTOMATON IMPLEMENTATION
// ============================================================================

AhoCorasickAutomaton::~AhoCorasickAutomaton() {
    // Vector cleanup automatic
}

bool AhoCorasickAutomaton::AddPattern(
    std::span<const uint8_t> pattern,
    uint64_t patternId
) noexcept {
    if (m_compiled) {
        SS_LOG_ERROR(L"AhoCorasick", L"Cannot add pattern after compilation");
        return false;
    }

    if (pattern.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Empty pattern");
        return false;
    }
    
    // Security: Limit pattern length to prevent DoS
    constexpr size_t MAX_PATTERN_LENGTH = 4096;
    if (pattern.size() > MAX_PATTERN_LENGTH) {
        SS_LOG_ERROR(L"AhoCorasick", L"Pattern too long: %zu bytes (max %zu)", 
            pattern.size(), MAX_PATTERN_LENGTH);
        return false;
    }
    
    // Security: Limit total nodes to prevent memory exhaustion
    constexpr size_t MAX_TOTAL_NODES = 10'000'000; // 10M nodes max
    if (m_nodeCount >= MAX_TOTAL_NODES) {
        SS_LOG_ERROR(L"AhoCorasick", L"Node limit reached: %zu nodes", m_nodeCount);
        return false;
    }

    // Ensure root node exists
    if (m_nodes.empty()) {
        try {
            m_nodes.emplace_back(); // Root node
            m_nodeCount = 1;
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"AhoCorasick", L"Failed to allocate root node");
            return false;
        }
    }

    // Insert pattern into trie
    uint32_t currentNode = 0; // Root

    for (uint8_t byte : pattern) {
        // Bounds check before access
        if (currentNode >= m_nodes.size()) {
            SS_LOG_ERROR(L"AhoCorasick", L"Invalid node index during insertion");
            return false;
        }
        
        uint32_t& child = m_nodes[currentNode].children[byte];
        
        if (child == 0) {
            // Check node limit before creating new
            if (m_nodeCount >= MAX_TOTAL_NODES) {
                SS_LOG_ERROR(L"AhoCorasick", L"Node limit reached during pattern insertion");
                return false;
            }
            
            try {
                // Create new node with exception safety
                child = static_cast<uint32_t>(m_nodes.size());
                m_nodes.emplace_back();
                m_nodes.back().depth = m_nodes[currentNode].depth + 1;
                m_nodeCount++;
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"AhoCorasick", L"Memory allocation failed");
                child = 0; // Reset to invalid
                return false;
            }
        }

        currentNode = child;
    }

    // Mark as output node
    if (currentNode < m_nodes.size()) {
        try {
            m_nodes[currentNode].outputs.push_back(patternId);
            m_patternCount++;
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"AhoCorasick", L"Failed to add pattern output");
            return false;
        }
    }

    return true;
}

bool AhoCorasickAutomaton::Compile() noexcept {
    if (m_compiled) {
        SS_LOG_WARN(L"AhoCorasick", L"Already compiled");
        return true;
    }

    if (m_nodes.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"No patterns added");
        return false;
    }

    SS_LOG_INFO(L"AhoCorasick", L"Compiling automaton: %zu nodes, %zu patterns",
        m_nodeCount, m_patternCount);

    // Build failure links using BFS
    BuildFailureLinks();

    m_compiled = true;

    SS_LOG_INFO(L"AhoCorasick", L"Compilation complete");
    return true;
}

void AhoCorasickAutomaton::Clear() noexcept {
    m_nodes.clear();
    m_patternCount = 0;
    m_nodeCount = 0;
    m_compiled = false;
}

void AhoCorasickAutomaton::Search(
    std::span<const uint8_t> buffer,
    std::function<void(uint64_t patternId, size_t offset)> callback
) const noexcept {
    if (!m_compiled || !callback) {
        return;
    }

    // Safety check: ensure we have at least root node
    if (m_nodes.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Search called with empty automaton");
        return;
    }

    uint32_t currentNode = 0; // Start at root
    
    // Limit iterations to prevent infinite loops from corrupted failure links
    constexpr size_t MAX_FAILURE_CHAIN = 10000;

    for (size_t offset = 0; offset < buffer.size(); ++offset) {
        uint8_t byte = buffer[offset];

        // Follow failure links until we find a match or reach root
        // Added bounds check and iteration limit for safety
        size_t failureChainLen = 0;
        while (currentNode != 0 && 
               currentNode < m_nodes.size() && 
               m_nodes[currentNode].children[byte] == 0) {
            
            uint32_t nextNode = m_nodes[currentNode].failureLink;
            
            // Prevent infinite loop from corrupted failure links
            if (++failureChainLen > MAX_FAILURE_CHAIN) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Failure chain too long at offset %zu - possible corruption", offset);
                currentNode = 0; // Reset to root
                break;
            }
            
            // Bounds check on failure link
            if (nextNode >= m_nodes.size()) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid failure link %u at node %u", nextNode, currentNode);
                currentNode = 0;
                break;
            }
            
            currentNode = nextNode;
        }

        // Transition with bounds check
        if (currentNode < m_nodes.size()) {
            uint32_t nextNode = m_nodes[currentNode].children[byte];
            if (nextNode < m_nodes.size()) {
                currentNode = nextNode;
            } else if (nextNode != 0) {
                // Non-zero but out of bounds = corruption
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid child node %u for byte 0x%02X", nextNode, byte);
                currentNode = 0;
                continue;
            }
        }

        // Check for matches with bounds validation
        if (currentNode < m_nodes.size() && !m_nodes[currentNode].outputs.empty()) {
            for (uint64_t patternId : m_nodes[currentNode].outputs) {
                callback(patternId, offset);
            }
        }
    }
}

size_t AhoCorasickAutomaton::CountMatches(
    std::span<const uint8_t> buffer
) const noexcept {
    size_t count = 0;
    Search(buffer, [&count](uint64_t, size_t) { count++; });
    return count;
}

void AhoCorasickAutomaton::BuildFailureLinks() noexcept {
    std::queue<uint32_t> queue;

    // Initialize root's children failure links
    for (uint32_t child : m_nodes[0].children) {
        if (child != 0) {
            m_nodes[child].failureLink = 0; // Point to root
            queue.push(child);
        }
    }

    // BFS to build remaining failure links
    while (!queue.empty()) {
        uint32_t currentNode = queue.front();
        queue.pop();

        for (size_t byte = 0; byte < 256; ++byte) {
            uint32_t child = m_nodes[currentNode].children[byte];
            if (child == 0) continue;

            queue.push(child);

            // Find failure link
            uint32_t failNode = m_nodes[currentNode].failureLink;

            while (failNode != 0 && m_nodes[failNode].children[byte] == 0) {
                failNode = m_nodes[failNode].failureLink;
            }

            uint32_t failChild = m_nodes[failNode].children[byte];
            m_nodes[child].failureLink = (failChild != child) ? failChild : 0;

            // Merge outputs from failure link
            const auto& failOutputs = m_nodes[m_nodes[child].failureLink].outputs;
            m_nodes[child].outputs.insert(
                m_nodes[child].outputs.end(),
                failOutputs.begin(),
                failOutputs.end()
            );
        }
    }
}




    }
}
