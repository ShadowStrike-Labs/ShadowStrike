/**
 * @file aho_crsck_impl.cpp
 * @brief Aho-Corasick Multi-Pattern String Matching Automaton Implementation
 *
 * This file implements a high-performance Aho-Corasick automaton for
 * multi-pattern string matching used in malware signature detection.
 *
 * Architecture:
 * - Trie-based automaton with failure links for linear-time matching
 * - O(n + m + z) time complexity where n=text, m=patterns, z=matches
 * - Memory-efficient node representation with lazy allocation
 *
 * Security Features:
 * - Node count limits to prevent memory exhaustion DoS
 * - Pattern length limits to prevent excessive trie depth
 * - Failure chain iteration limits to detect corruption
 * - Comprehensive bounds checking on all node accesses
 * - Exception-safe pattern insertion
 *
 * Thread Safety:
 * - Automaton is immutable after compilation
 * - Search is thread-safe for concurrent reads
 * - Compilation must be single-threaded
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

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
#include <chrono>
#include <mutex>
#include <limits>
#include <stdexcept>

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// INTERNAL CONSTANTS AND HELPERS
// ============================================================================

namespace {

/// @brief Maximum pattern length for Aho-Corasick to prevent DoS via excessive trie depth
/// @note Uses local name to avoid conflict with SignatureFormat.hpp's MAX_PATTERN_LENGTH
constexpr size_t AC_MAX_PATTERN_LENGTH = 4096;

/// @brief Maximum total nodes to prevent memory exhaustion attacks
constexpr size_t MAX_TOTAL_NODES = 10'000'000;  // 10M nodes max (~2.5GB)

/// @brief Maximum failure link chain length (corruption detection)
constexpr size_t MAX_FAILURE_CHAIN = 10000;

/// @brief Maximum outputs per node (prevent memory attacks via duplicate patterns)
constexpr size_t MAX_OUTPUTS_PER_NODE = 10000;

/**
 * @brief Safely check if adding would overflow
 * @param a First value
 * @param b Second value
 * @param result Output sum (only valid if returns true)
 * @return True if addition is safe, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeAdd(T a, T b, T& result) noexcept {
    static_assert(std::is_unsigned_v<T>, "SafeAdd requires unsigned type");
    if (a > std::numeric_limits<T>::max() - b) {
        return false;
    }
    result = a + b;
    return true;
}

} // anonymous namespace

// ============================================================================
// AHO-CORASICK AUTOMATON IMPLEMENTATION
// ============================================================================

/**
 * @brief Destructor - releases all automaton resources
 * 
 * All memory is managed by std::vector, so cleanup is automatic.
 * No external resources (files, handles) are held.
 */
AhoCorasickAutomaton::~AhoCorasickAutomaton() {
    // Note: std::vector destructor handles node deallocation
    // Clear member state for defense-in-depth
    m_nodes.clear();
    m_patternCount = 0;
    m_nodeCount = 0;
    m_compiled = false;
}

/**
 * @brief Add a pattern to the automaton trie
 * @param pattern Binary pattern bytes to match
 * @param patternId Unique identifier returned on match
 * @return True if pattern was added successfully
 * 
 * Security:
 * - Pattern length is bounded to prevent excessive trie depth
 * - Node count is bounded to prevent memory exhaustion
 * - All allocations are exception-safe
 * 
 * Must be called before Compile(). Cannot add patterns after compilation.
 */
bool AhoCorasickAutomaton::AddPattern(
    std::span<const uint8_t> pattern,
    uint64_t patternId
) noexcept {
    // ========================================================================
    // STEP 1: PRE-CONDITION VALIDATION
    // ========================================================================
    
    if (m_compiled) {
        SS_LOG_ERROR(L"AhoCorasick", L"Cannot add pattern after compilation");
        return false;
    }

    if (pattern.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Empty pattern rejected");
        return false;
    }
    
    // Security: Limit pattern length to prevent DoS via excessive trie depth
    if (pattern.size() > AC_MAX_PATTERN_LENGTH) {
        SS_LOG_ERROR(L"AhoCorasick", L"Pattern too long: %zu bytes (max %zu)", 
            pattern.size(), AC_MAX_PATTERN_LENGTH);
        return false;
    }
    
    // Security: Limit total nodes to prevent memory exhaustion attacks
    if (m_nodeCount >= MAX_TOTAL_NODES) {
        SS_LOG_ERROR(L"AhoCorasick", L"Node limit reached: %zu nodes (max %zu)", 
            m_nodeCount, MAX_TOTAL_NODES);
        return false;
    }
    
    // ========================================================================
    // STEP 2: ENSURE ROOT NODE EXISTS
    // ========================================================================

    if (m_nodes.empty()) {
        try {
            m_nodes.emplace_back(); // Root node (index 0)
            m_nodeCount = 1;
        } catch (const std::bad_alloc&) {
            SS_LOG_ERROR(L"AhoCorasick", L"Failed to allocate root node - out of memory");
            return false;
        } catch (...) {
            SS_LOG_ERROR(L"AhoCorasick", L"Unexpected exception allocating root node");
            return false;
        }
    }
    
    // ========================================================================
    // STEP 3: INSERT PATTERN INTO TRIE
    // ========================================================================

    uint32_t currentNode = 0; // Start at root

    for (size_t i = 0; i < pattern.size(); ++i) {
        const uint8_t byte = pattern[i];
        
        // Bounds validation before every node access
        if (currentNode >= m_nodes.size()) {
            SS_LOG_ERROR(L"AhoCorasick", 
                L"Invalid node index %u during insertion (nodes: %zu)",
                currentNode, m_nodes.size());
            return false;
        }
        
        uint32_t& childRef = m_nodes[currentNode].children[byte];
        
        if (childRef == 0) {
            // Need to create new node
            
            // Check node limit before allocation
            if (m_nodeCount >= MAX_TOTAL_NODES) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Node limit reached during pattern insertion at byte %zu", i);
                return false;
            }
            
            // Check for overflow in node index (nodes.size() -> uint32_t)
            if (m_nodes.size() >= static_cast<size_t>(UINT32_MAX)) {
                SS_LOG_ERROR(L"AhoCorasick", L"Node index overflow");
                return false;
            }
            
            try {
                // Allocate new node with exception safety
                const uint32_t newNodeIndex = static_cast<uint32_t>(m_nodes.size());
                m_nodes.emplace_back();
                
                // Set depth with overflow protection
                const uint16_t parentDepth = m_nodes[currentNode].depth;
                if (parentDepth < UINT16_MAX) {
                    m_nodes.back().depth = parentDepth + 1;
                } else {
                    m_nodes.back().depth = UINT16_MAX; // Saturate at max
                }
                
                // Update child pointer and count AFTER successful allocation
                childRef = newNodeIndex;
                ++m_nodeCount;
                
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"AhoCorasick", L"Memory allocation failed at byte %zu", i);
                // childRef remains 0 (invalid) - safe state
                return false;
            } catch (...) {
                SS_LOG_ERROR(L"AhoCorasick", L"Unexpected exception during node allocation");
                return false;
            }
        }
        
        // Move to child node (re-read in case of reallocation)
        currentNode = m_nodes[currentNode].children[byte];
        
        // Validate the transition
        if (currentNode == 0 || currentNode >= m_nodes.size()) {
            SS_LOG_ERROR(L"AhoCorasick", 
                L"Invalid child node %u after insertion at byte %zu", currentNode, i);
            return false;
        }
    }
    
    // ========================================================================
    // STEP 4: MARK AS OUTPUT NODE
    // ========================================================================
    
    // Final bounds check
    if (currentNode >= m_nodes.size()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Invalid final node index %u", currentNode);
        return false;
    }
    
    // Security: Limit outputs per node to prevent memory attacks
    if (m_nodes[currentNode].outputs.size() >= MAX_OUTPUTS_PER_NODE) {
        SS_LOG_WARN(L"AhoCorasick", 
            L"Output limit reached for node %u - pattern may be duplicate", currentNode);
        // Still return success - pattern path exists, just limit outputs
        return true;
    }
    
    try {
        m_nodes[currentNode].outputs.push_back(patternId);
        ++m_patternCount;
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"AhoCorasick", L"Failed to add pattern output - out of memory");
        return false;
    } catch (...) {
        SS_LOG_ERROR(L"AhoCorasick", L"Unexpected exception adding pattern output");
        return false;
    }

    return true;
}

/**
 * @brief Compile the automaton by building failure links
 * @return True if compilation succeeded
 * 
 * After compilation:
 * - No more patterns can be added
 * - Search operations become available
 * - Automaton becomes effectively immutable (thread-safe reads)
 * 
 * Calling Compile() multiple times is safe but returns immediately.
 */
bool AhoCorasickAutomaton::Compile() noexcept {
    // ========================================================================
    // STEP 1: EARLY EXIT IF ALREADY COMPILED
    // ========================================================================
    
    if (m_compiled) {
        SS_LOG_WARN(L"AhoCorasick", L"Compile called on already-compiled automaton");
        return true;
    }
    
    // ========================================================================
    // STEP 2: VALIDATE STATE
    // ========================================================================

    if (m_nodes.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Cannot compile: no patterns added");
        return false;
    }
    
    // Sanity check: node count should match vector size
    if (m_nodeCount != m_nodes.size()) {
        SS_LOG_WARN(L"AhoCorasick", 
            L"Node count mismatch: m_nodeCount=%zu, m_nodes.size()=%zu - correcting",
            m_nodeCount, m_nodes.size());
        m_nodeCount = m_nodes.size();
    }
    
    // Validate we have at least a root node
    if (m_nodeCount == 0) {
        SS_LOG_ERROR(L"AhoCorasick", L"Cannot compile: no root node");
        return false;
    }

    SS_LOG_INFO(L"AhoCorasick", 
        L"Compiling automaton: %zu nodes, %zu patterns",
        m_nodeCount, m_patternCount);
    
    // ========================================================================
    // STEP 3: BUILD FAILURE LINKS
    // ========================================================================
    
    try {
        BuildFailureLinks();
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"AhoCorasick", 
            L"Exception during failure link construction: %S", ex.what());
        return false;
    } catch (...) {
        SS_LOG_ERROR(L"AhoCorasick", 
            L"Unknown exception during failure link construction");
        return false;
    }
    
    // ========================================================================
    // STEP 4: MARK AS COMPILED
    // ========================================================================

    m_compiled = true;

    SS_LOG_INFO(L"AhoCorasick", L"Compilation complete - automaton ready for search");
    return true;
}

/**
 * @brief Reset the automaton to initial empty state
 * 
 * Releases all memory and resets all counters.
 * After Clear(), new patterns can be added.
 * 
 * Thread-safety: NOT thread-safe. Ensure no concurrent Search() calls.
 */
void AhoCorasickAutomaton::Clear() noexcept {
    // Clear vector first (releases memory)
    m_nodes.clear();
    
    // Shrink to release reserved capacity
    m_nodes.shrink_to_fit();
    
    // Reset all counters to initial state
    m_patternCount = 0;
    m_nodeCount = 0;
    m_compiled = false;
    
    SS_LOG_DEBUG(L"AhoCorasick", L"Automaton cleared and reset");
}

/**
 * @brief Search for all patterns in the given buffer
 * @param buffer Input data to scan
 * @param callback Function called for each match (patternId, endOffset)
 * 
 * Performance:
 * - O(n + z) where n=buffer size, z=number of matches
 * - Single pass through buffer
 * - Lock-free (thread-safe for concurrent searches)
 * 
 * Security:
 * - Bounds checking on all node accesses
 * - Failure chain iteration limit (corruption detection)
 * - Callback exceptions are caught and logged
 * 
 * @note offset parameter in callback is the END position of match
 */
void AhoCorasickAutomaton::Search(
    std::span<const uint8_t> buffer,
    std::function<void(uint64_t patternId, size_t offset)> callback
) const noexcept {
    // ========================================================================
    // STEP 1: PRE-CONDITION VALIDATION
    // ========================================================================
    
    if (!m_compiled) {
        SS_LOG_ERROR(L"AhoCorasick", L"Search called on non-compiled automaton");
        return;
    }
    
    if (!callback) {
        SS_LOG_ERROR(L"AhoCorasick", L"Search called with null callback");
        return;
    }

    // Empty buffer is valid - just return with no matches
    if (buffer.empty()) {
        return;
    }

    // Safety check: ensure we have valid automaton state
    if (m_nodes.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"Search called with empty node array");
        return;
    }
    
    // ========================================================================
    // STEP 2: INITIALIZE STATE MACHINE
    // ========================================================================

    uint32_t currentNode = 0; // Start at root (index 0)
    
    // ========================================================================
    // STEP 3: PROCESS EACH BYTE IN BUFFER
    // ========================================================================

    for (size_t offset = 0; offset < buffer.size(); ++offset) {
        const uint8_t byte = buffer[offset];

        // ====================================================================
        // STEP 3a: FOLLOW FAILURE LINKS UNTIL MATCH OR ROOT
        // ====================================================================
        
        // Iteration limit to detect corrupted failure links (infinite loop)
        size_t failureChainLen = 0;
        
        while (currentNode != 0) {
            // Bounds check before every node access
            if (currentNode >= m_nodes.size()) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid node %u at offset %zu (nodes: %zu) - resetting to root",
                    currentNode, offset, m_nodes.size());
                currentNode = 0;
                break;
            }
            
            // Check if transition exists for this byte
            if (m_nodes[currentNode].children[byte] != 0) {
                break; // Found transition - exit failure chain loop
            }
            
            // Follow failure link
            const uint32_t nextNode = m_nodes[currentNode].failureLink;
            
            // Corruption detection: limit failure chain length
            if (++failureChainLen > MAX_FAILURE_CHAIN) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Failure chain exceeded %zu at offset %zu - possible corruption",
                    MAX_FAILURE_CHAIN, offset);
                currentNode = 0; // Reset to root as recovery
                break;
            }
            
            // Bounds check on failure link target
            if (nextNode != 0 && nextNode >= m_nodes.size()) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid failure link %u from node %u - resetting to root",
                    nextNode, currentNode);
                currentNode = 0;
                break;
            }
            
            currentNode = nextNode;
        }

        // ====================================================================
        // STEP 3b: PERFORM STATE TRANSITION
        // ====================================================================
        
        // Validate current node before transition
        if (currentNode >= m_nodes.size()) {
            currentNode = 0; // Reset to root
        }
        
        const uint32_t nextNode = m_nodes[currentNode].children[byte];
        
        if (nextNode != 0) {
            // Validate transition target
            if (nextNode >= m_nodes.size()) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid child node %u for byte 0x%02X at offset %zu",
                    nextNode, byte, offset);
                currentNode = 0; // Reset to root
                continue;
            }
            currentNode = nextNode;
        }
        // else: stay at current node (root has implicit self-loop for unmatched bytes)

        // ====================================================================
        // STEP 3c: REPORT MATCHES AT THIS POSITION
        // ====================================================================
        
        if (currentNode < m_nodes.size()) {
            const auto& outputs = m_nodes[currentNode].outputs;
            
            if (!outputs.empty()) {
                for (const uint64_t patternId : outputs) {
                    try {
                        callback(patternId, offset);
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(L"AhoCorasick", 
                            L"Callback threw exception at offset %zu: %S", offset, ex.what());
                        // Continue processing - don't let callback failure abort search
                    } catch (...) {
                        SS_LOG_ERROR(L"AhoCorasick", 
                            L"Callback threw unknown exception at offset %zu", offset);
                        // Continue processing
                    }
                }
            }
        }
    }
}

/**
 * @brief Count total number of pattern matches in buffer
 * @param buffer Input data to scan
 * @return Number of matches (may have duplicates if patterns overlap)
 * 
 * This is a convenience wrapper around Search().
 * For large buffers with many matches, count may saturate at SIZE_MAX.
 */
size_t AhoCorasickAutomaton::CountMatches(
    std::span<const uint8_t> buffer
) const noexcept {
    size_t count = 0;
    
    Search(buffer, [&count](uint64_t /*patternId*/, size_t /*offset*/) noexcept {
        // Overflow protection - saturate at max instead of wrapping
        if (count < SIZE_MAX) {
            ++count;
        }
    });
    
    return count;
}

/**
 * @brief Build failure links using breadth-first search
 * 
 * Failure links enable the automaton to efficiently backtrack when a
 * partial match fails, achieving O(n) matching instead of O(n*m).
 * 
 * Algorithm:
 * 1. Root's direct children have failure links pointing to root
 * 2. For each node, its failure link points to the longest proper
 *    suffix of its path that exists in the trie
 * 3. Output sets are merged along failure paths for dictionary suffix
 * 
 * This method should only be called from Compile() after validation.
 */
void AhoCorasickAutomaton::BuildFailureLinks() noexcept {
    // ========================================================================
    // STEP 1: VALIDATE PRE-CONDITIONS
    // ========================================================================
    
    if (m_nodes.empty()) {
        SS_LOG_ERROR(L"AhoCorasick", L"BuildFailureLinks called with empty nodes");
        return;
    }
    
    // ========================================================================
    // STEP 2: INITIALIZE BFS QUEUE WITH ROOT'S CHILDREN
    // ========================================================================
    
    std::queue<uint32_t> bfsQueue;

    // Initialize failure links for root's direct children (depth 1)
    // They all point back to root since no proper suffix exists
    for (size_t byte = 0; byte < 256; ++byte) {
        const uint32_t child = m_nodes[0].children[byte];
        
        if (child != 0) {
            // Bounds check before access
            if (child >= m_nodes.size()) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid root child %u for byte 0x%02zX", child, byte);
                continue;
            }
            
            m_nodes[child].failureLink = 0; // Point to root
            
            try {
                bfsQueue.push(child);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"AhoCorasick", L"BFS queue allocation failed");
                return;
            }
        }
    }
    
    // ========================================================================
    // STEP 3: BFS TO BUILD REMAINING FAILURE LINKS
    // ========================================================================
    
    // Iteration limit to prevent infinite loops from corrupted data
    size_t iterationCount = 0;
    const size_t maxIterations = m_nodes.size() * 256 + 1000; // Safety margin

    while (!bfsQueue.empty()) {
        // Corruption detection
        if (++iterationCount > maxIterations) {
            SS_LOG_ERROR(L"AhoCorasick", 
                L"BuildFailureLinks exceeded iteration limit %zu - aborting",
                maxIterations);
            return;
        }
        
        const uint32_t currentNode = bfsQueue.front();
        bfsQueue.pop();
        
        // Bounds validation
        if (currentNode >= m_nodes.size()) {
            SS_LOG_ERROR(L"AhoCorasick", 
                L"Invalid node %u in BFS queue (nodes: %zu)",
                currentNode, m_nodes.size());
            continue;
        }

        // Process all 256 possible byte transitions
        for (size_t byte = 0; byte < 256; ++byte) {
            const uint32_t child = m_nodes[currentNode].children[byte];
            
            // Skip non-existent children
            if (child == 0) {
                continue;
            }
            
            // Bounds check on child
            if (child >= m_nodes.size()) {
                SS_LOG_ERROR(L"AhoCorasick", 
                    L"Invalid child %u at node %u, byte 0x%02zX",
                    child, currentNode, byte);
                continue;
            }
            
            // Add child to BFS queue for processing
            try {
                bfsQueue.push(child);
            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"AhoCorasick", L"BFS queue push failed - out of memory");
                return;
            }

            // ================================================================
            // FIND FAILURE LINK FOR THIS CHILD
            // ================================================================
            
            // Start from parent's failure link
            uint32_t failNode = m_nodes[currentNode].failureLink;
            size_t failChainLen = 0;
            
            // Walk failure chain until we find a node with this byte transition
            // or reach root
            while (failNode != 0) {
                // Bounds check
                if (failNode >= m_nodes.size()) {
                    SS_LOG_ERROR(L"AhoCorasick", 
                        L"Invalid failure node %u during link construction", failNode);
                    failNode = 0;
                    break;
                }
                
                // Corruption detection
                if (++failChainLen > MAX_FAILURE_CHAIN) {
                    SS_LOG_ERROR(L"AhoCorasick", 
                        L"Failure chain limit exceeded at node %u", currentNode);
                    failNode = 0;
                    break;
                }
                
                // Check if this node has the byte transition we need
                if (m_nodes[failNode].children[byte] != 0) {
                    break;
                }
                
                failNode = m_nodes[failNode].failureLink;
            }

            // Get the target of the failure link
            const uint32_t failChild = m_nodes[failNode].children[byte];
            
            // Set failure link (avoid self-loops)
            if (failChild != 0 && failChild != child && failChild < m_nodes.size()) {
                m_nodes[child].failureLink = failChild;
            } else {
                m_nodes[child].failureLink = 0; // Point to root
            }

            // ================================================================
            // MERGE OUTPUTS FROM FAILURE LINK PATH
            // ================================================================
            
            // This enables matching of all patterns that end at this position,
            // including shorter patterns that are suffixes of longer ones
            
            const uint32_t childFailLink = m_nodes[child].failureLink;
            
            if (childFailLink != 0 && childFailLink < m_nodes.size()) {
                const auto& failOutputs = m_nodes[childFailLink].outputs;
                
                if (!failOutputs.empty()) {
                    try {
                        // Reserve to minimize reallocations
                        const size_t currentSize = m_nodes[child].outputs.size();
                        const size_t newSize = currentSize + failOutputs.size();
                        
                        // Limit outputs per node to prevent memory attacks
                        if (newSize > MAX_OUTPUTS_PER_NODE) {
                            SS_LOG_WARN(L"AhoCorasick", 
                                L"Output limit reached for node %u during merge", child);
                            // Only copy up to the limit
                            const size_t canAdd = MAX_OUTPUTS_PER_NODE - currentSize;
                            if (canAdd > 0) {
                                m_nodes[child].outputs.insert(
                                    m_nodes[child].outputs.end(),
                                    failOutputs.begin(),
                                    failOutputs.begin() + std::min(canAdd, failOutputs.size())
                                );
                            }
                        } else {
                            m_nodes[child].outputs.insert(
                                m_nodes[child].outputs.end(),
                                failOutputs.begin(),
                                failOutputs.end()
                            );
                        }
                    } catch (const std::bad_alloc&) {
                        SS_LOG_ERROR(L"AhoCorasick", 
                            L"Output merge failed at node %u - out of memory", child);
                        // Continue - partial outputs are still usable
                    }
                }
            }
        }
    }
    
    SS_LOG_DEBUG(L"AhoCorasick", 
        L"BuildFailureLinks complete: processed %zu iterations", iterationCount);
}

} // namespace SignatureStore
} // namespace ShadowStrike
