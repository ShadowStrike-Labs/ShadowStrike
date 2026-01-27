#pragma once

#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <cstdint>
#include <chrono>
#include <atomic>

#include "../Utils/ProcessUtils.hpp"

namespace ShadowStrike {
    namespace RealTime {

        /**
         * @brief Type of memory violation detected.
         */
        enum class MemoryViolationType {
            None,
            RWX_Page,           ///< Page with Read-Write-Execute permissions (often shellcode)
            Shellcode_Pattern,  ///< Known shellcode pattern (e.g., NOP sled, reverse shell)
            Module_Stomping,    ///< Module memory does not match disk (hollowing/stomping)
            ROP_Gadget,         ///< Suspicious return addresses on stack
            Heap_Spray,         ///< Repetitive patterns in heap
            Thread_Injection    ///< Thread start address in suspicious memory
        };

        /**
         * @brief Scan intensity mode.
         */
        enum class ScanMode {
            Fast,               ///< Check permissions (RWX) and headers only
            Deep,               ///< Full memory scan for patterns
            Heuristic           ///< Analyze behavior and stack traces
        };

        /**
         * @brief Details of a detected violation.
         */
        struct MemoryViolation {
            MemoryViolationType type = MemoryViolationType::None;
            uint64_t address = 0;
            size_t size = 0;
            std::vector<uint8_t> dump;  ///< First few bytes of the violation
            float confidence = 0.0f;    ///< 0.0 to 1.0
            std::string details;

            [[nodiscard]] std::string ToJson() const;
        };

        /**
         * @brief Result of a memory scan operation.
         */
        struct MemoryScanResult {
            Utils::ProcessUtils::ProcessId pid = 0;
            bool compromised = false;
            size_t pagesScanned = 0;
            std::vector<MemoryViolation> violations;
            std::chrono::microseconds scanDuration{ 0 };

            [[nodiscard]] std::string ToJson() const;
        };

        /**
         * @brief Memory Protection Engine.
         *
         * Detects memory-resident threats including:
         * - Shellcode injection
         * - Process Hollowing / Module Stomping
         * - ROP chains
         * - RWX memory hunting
         */
        class MemoryProtection final {
        public:
            /**
             * @brief Singleton Accessor.
             */
            [[nodiscard]] static MemoryProtection& Instance() noexcept;

            // Delete copy/move
            MemoryProtection(const MemoryProtection&) = delete;
            MemoryProtection& operator=(const MemoryProtection&) = delete;
            MemoryProtection(MemoryProtection&&) = delete;
            MemoryProtection& operator=(MemoryProtection&&) = delete;

            /**
             * @brief Scan a specific process for memory threats.
             * @param pid Process ID to scan.
             * @param mode Scan intensity.
             * @return Detailed scan result.
             */
            [[nodiscard]] MemoryScanResult ScanProcess(Utils::ProcessUtils::ProcessId pid, ScanMode mode = ScanMode::Fast);

            /**
             * @brief Add a process to the real-time monitoring list.
             * @param pid Process ID.
             * @return true if successfully added.
             */
            [[nodiscard]] bool MonitorProcess(Utils::ProcessUtils::ProcessId pid);

            /**
             * @brief Enable specific exploit mitigation flags for a process.
             * @param pid Process ID.
             * @param flags Protection flags (implementation dependent).
             * @return true on success.
             */
            [[nodiscard]] bool EnableExploitProtection(Utils::ProcessUtils::ProcessId pid, uint32_t flags);

            /**
             * @brief Quick check if a process is compromised.
             * @param pid Process ID.
             * @return true if threats were found.
             */
            [[nodiscard]] bool IsProcessCompromised(Utils::ProcessUtils::ProcessId pid);

            /**
             * @brief Run self-diagnostics.
             * @return true if the engine is functioning correctly.
             */
            [[nodiscard]] bool SelfTest();

            /**
             * @brief Get engine statistics in JSON format.
             */
            [[nodiscard]] std::string GetStatistics() const;

        private:
            MemoryProtection();
            ~MemoryProtection();

            class MemoryProtectionImpl;
            std::unique_ptr<MemoryProtectionImpl> m_impl;
        };

    } // namespace RealTime
} // namespace ShadowStrike
