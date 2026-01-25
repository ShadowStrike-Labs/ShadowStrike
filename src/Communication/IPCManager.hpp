/**
 * ============================================================================ 
 * ShadowStrike Communication Layer - IPC MANAGER (The Nervous System)
 * ============================================================================ 
 *
 * @file IPCManager.hpp
 * @brief Manages high-performance communication between User Mode and Kernel Mode.
 *
 * This module implements the bridge between the ShadowStrike Kernel Minifilter
 * Driver (Ring 0) and the User-Mode Service (Ring 3). It utilizes the
 * Windows Filter Communication Port API (FltMgr) for low-latency message passing.
 *
 * Architecture Position:
 * ----------------------
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                  Kernel Minifilter Driver                    │
 *   │            (Intercepts File I/O, Process Create)             │
 *   └──────────────────────────┬──────────────────────────────────┘
 *                              │ (FltSendMessage)
 *                              ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                     IPC MANAGER                              │ ◄── YOU ARE HERE
 *   │       (Worker Threads, Message Dispatcher, IOCP)             │
 *   └──────────────────────────┬──────────────────────────────────┘
 *                              │ (Callbacks)
 *                              ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                 RealTimeProtection Module                    │
 *   │           (Calls ScanEngine -> Returns Verdict)              │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * Protocol Protocol:
 * ------------------
 * The communication uses a strict command-response protocol.
 * 1. Kernel sends a MESSAGE (e.g., CMD_SCAN_FILE).
 * 2. IPCManager receives it in a worker thread.
 * 3. IPCManager dispatches it to a registered handler.
 * 4. Handler returns a verdict (e.g., ALLOW/BLOCK).
 * 5. IPCManager sends a REPLY back to the Kernel.
 *
 * Performance Requirements:
 * -------------------------
 * - Zero-Copy attempts where possible (using memory mapping for large buffers).
 * - Multi-threaded: Must handle 1000+ events/sec without blocking the OS.
 * - Robustness: Must handle driver disconnects/restarts gracefully.
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <span>
#include <variant>

// Windows Headers (Reduced to necessary types)
#include <windows.h>
#include <fltUser.h> // Filter Communication Port API

namespace ShadowStrike {
    namespace Communication {

        // ============================================================================ 
        // KERNEL <-> USER PROTOCOL DEFINITIONS
        // These structures must MATCH the Kernel Driver definitions EXACTLY.
        // ============================================================================ 

        // Port Name defined in the Driver
        constexpr const wchar_t* FILTER_PORT_NAME = L"\\ShadowStrikePort";

        /**
         * @enum CommandType
         * @brief Identifies the type of request from the Kernel.
         */
        enum class CommandType : uint32_t {
            None = 0,
            Handshake = 1,          ///< Driver connecting to Service
            ScanFile = 2,           ///< Pre-Create / Pre-Write scan request
            ProcessCreate = 3,      ///< PsSetCreateProcessNotifyRoutine notification
            ProcessTerminate = 4,   ///< Process termination
            ImageLoad = 5,          ///< DLL/Driver load
            RegistryOp = 6,         ///< Registry modification
            Heartbeat = 99          ///< Keep-alive
        };

        /**
         * @enum ScanVerdict
         * @brief The response sent back to the Kernel.
         */
        enum class KernelVerdict : uint32_t {
            Allow = 0,              ///< Allow the I/O operation
            Block = 1,              ///< Block with access denied
            Quarantine = 2,         ///< Block and trigger remediation
            Pending = 3             ///< (Async only) Hold I/O, will reply later
        };

        #pragma pack(push, 1)

        /**
         * @struct KernelRequestHeader
         * @brief Standard header for all messages from Kernel.
         */
        struct KernelRequestHeader {
            CommandType command;
            uint32_t processId;
            uint32_t threadId;
            uint64_t timestamp;     ///< KeQuerySystemTime
        };

        /**
         * @struct FileScanRequest
         * @brief Payload for CommandType::ScanFile
         */
        struct FileScanRequest {
            KernelRequestHeader header;
            uint32_t parentProcessId;
            uint32_t desiredAccess;
            uint16_t fileNameLength;
            wchar_t fileName[260];  ///< Fixed buffer for simplicity (Driver handles truncation) 
                                    ///< In production, use flexible array member with dynamic allocation
        };

        /**
         * @struct ProcessNotifyRequest
         * @brief Payload for CommandType::ProcessCreate
         */
        struct ProcessNotifyRequest {
            KernelRequestHeader header;
            uint32_t parentProcessId;
            uint32_t creatingThreadId;
            uint16_t imagePathLength;
            uint16_t commandLineLength;
            wchar_t imagePath[260];
            // Command line usually follows dynamically
        };

        /**
         * @struct KernelReply
         * @brief Standard response structure sent back to Kernel.
         */
        struct KernelReply {
            KernelVerdict verdict;
            uint32_t cacheDuration; ///< How long the kernel should cache this verdict (ms)
        };

        #pragma pack(pop)

        // ============================================================================ 
        // IPC MANAGER CLASS
        // ============================================================================ 

        /**
         * @class IPCManager
         * @brief Singleton managing the Filter Communication Port.
         */
        class IPCManager {
        public:
            // ======================================================================== 
            // LIFECYCLE
            // ======================================================================== 

            static IPCManager& Instance();

            /**
             * @brief Connects to the Kernel Driver Port.
             * @param workerThreadCount Number of threads polling for messages (default: 4-8).
             * @return True if connection successful.
             */
            bool Start(uint32_t workerThreadCount = std::thread::hardware_concurrency());

            /**
             * @brief Disconnects and stops worker threads.
             */
            void Stop();

            bool IsConnected() const { return m_connected.load(); }

            // ======================================================================== 
            // CALLBACK REGISTRATION
            // ======================================================================== 

            using FileScanCallback = std::function<KernelVerdict(const FileScanRequest&)>;
            using ProcessNotifyCallback = std::function<void(const ProcessNotifyRequest&)>;

            /**
             * @brief Registers the handler for File Scan requests.
             * This function is called on a worker thread and MUST be thread-safe.
             * It should generally map to ScanEngine::ScanFile.
             */
            void RegisterFileScanHandler(FileScanCallback handler);

            /**
             * @brief Registers the handler for Process Create notifications.
             */
            void RegisterProcessHandler(ProcessNotifyCallback handler);

        private:
            IPCManager();
            ~IPCManager();

            // Disable copy
            IPCManager(const IPCManager&) = delete;
            IPCManager& operator=(const IPCManager&) = delete;

            // ======================================================================== 
            // INTERNAL WORKER LOGIC
            // ======================================================================== 

            /**
             * @brief Main loop for worker threads.
             * Calls FilterGetMessage -> Dispatch -> FilterReplyMessage.
             */
            void WorkerRoutine();

            /**
             * @brief Dispatches a raw message buffer to the appropriate C++ handler.
             * @param buffer Raw data from kernel.
             * @param messageId Unique message ID from FltMgr (for replying).
             */
            void DispatchMessage(uint8_t* buffer, uint64_t messageId);

            // ======================================================================== 
            // MEMBERS
            // ======================================================================== 

            HANDLE m_hPort;                         ///< Handle to the Communication Port
            std::atomic<bool> m_connected{ false };
            std::atomic<bool> m_running{ false };   ///< Flag to control worker loops

            // Thread Pool
            std::vector<std::thread> m_workerThreads;

            // Handlers
            FileScanCallback m_fileScanHandler;
            ProcessNotifyCallback m_processHandler;
            std::mutex m_handlerMutex;

            // Buffer Configuration
            // FilterGetMessage requires a header (FILTER_MESSAGE_HEADER) + our payload
            static constexpr size_t MAX_MESSAGE_SIZE = 4096;
        };

    } // namespace Communication
} // namespace ShadowStrike
