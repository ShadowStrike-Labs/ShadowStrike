#pragma once
/**
 * @file Logger.hpp
 * @brief Thread-safe asynchronous logging system for ShadowStrike Security Suite.
 *
 * Provides enterprise-grade logging with:
 * - Asynchronous logging with configurable back-pressure policies
 * - Multiple output targets (console, file, Windows Event Log)
 * - Log rotation with configurable size and count limits
 * - JSON Lines output format support
 * - Source location tracking (file, line, function)
 * - Scoped logging with timing measurements
 * - Thread-safe singleton pattern
 *
 * @note Thread-safe for all public methods.
 * @warning Must call Initialize() before logging, or auto-init with console-only defaults.
 */

#include <atomic>
#include <cstdint>
#include <cstdarg>
#include <deque>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
// Prevent macro collision with Logger::WriteConsole method
#  ifdef WriteConsole
#    undef WriteConsole
#  endif
#  include <Windows.h>
// Re-undef after Windows.h inclusion in case it redefines
#  ifdef WriteConsole
#    undef WriteConsole
#  endif
#endif

namespace ShadowStrike {
	namespace Utils {

		// ============================================================================
		// Log Levels
		// ============================================================================

		/**
		 * @brief Severity levels for log messages.
		 *
		 * Ordered from least to most severe. Messages below the configured
		 * minimum level are discarded.
		 */
		enum class LogLevel : uint8_t {
			Trace = 0,  ///< Verbose debugging information
			Debug,      ///< Debug-level information
			Info,       ///< Informational messages
			Warn,       ///< Warning conditions
			Error,      ///< Error conditions
			Fatal       ///< Fatal/critical errors
		};

		// ============================================================================
		// Configuration
		// ============================================================================

		/**
		 * @brief Configuration options for the Logger.
		 */
		struct LoggerConfig {
			/// Maximum queue size for async logging
			size_t maxQueueSize = 1000;

			/// Policy when queue is full
			enum class BackPressurePolicy {
				Block,       ///< Block until space available
				DropOldest,  ///< Drop oldest messages
				DropNewest   ///< Drop newest messages
			} bpPolicy = BackPressurePolicy::DropOldest;

			bool async = true;              ///< Enable asynchronous logging
			bool toConsole = true;          ///< Output to console
			bool toFile = true;             ///< Output to file
			bool toEventLog = false;        ///< Output to Windows Event Log
			bool jsonLines = false;         ///< Use JSON Lines format
			bool useUtcTime = true;         ///< Use UTC timestamps
			bool includeSrcLocation = true; ///< Include source file/line/function
			bool includeProcThreadId = true;///< Include process/thread IDs

			std::wstring logDirectory = L"logs";          ///< Log file directory
			std::wstring baseFileName = L"ShadowStrike";  ///< Base log file name
			uint64_t maxFileSizeBytes = 10ULL * 1024ULL * 1024ULL;  ///< Max file size (10MB)
			size_t maxFileCount = 10;                     ///< Max rotated files to keep

			LogLevel minimalLevel = LogLevel::Info;       ///< Minimum level to log
			LogLevel flushLevel = LogLevel::Error;        ///< Level that triggers flush
			std::wstring eventLogSource = L"ShadowStrike";///< Windows Event Log source
		};

		/**
		 * @brief Source location information for wide-character strings.
		 */
		struct SourceLocationW {
			const wchar_t* file = nullptr;
			int line = 0;
			const wchar_t* function = nullptr;
		};

		// ============================================================================
		// Logger Class
		// ============================================================================

		/**
		 * @brief Thread-safe singleton logger with async support.
		 *
		 * The Logger provides a thread-safe logging facility with support for
		 * multiple output targets, log rotation, and configurable formatting.
		 *
		 * Usage:
		 * @code
		 *   LoggerConfig cfg;
		 *   cfg.toFile = true;
		 *   cfg.logDirectory = L"logs";
		 *   Logger::Instance().Initialize(cfg);
		 *
		 *   SS_LOG_INFO(L"MyCategory", L"Hello %ls", L"World");
		 *   SS_LOG_ERROR(L"MyCategory", L"Error code: %d", 42);
		 *
		 *   Logger::Instance().ShutDown();
		 * @endcode
		 *
		 * @note Call Initialize() before logging for configured behavior.
		 * @note Call ShutDown() before application exit to flush pending logs.
		 */
		class Logger {
		public:
			/**
			 * @brief Get the singleton Logger instance.
			 * @return Reference to the global Logger instance
			 */
			[[nodiscard]] static Logger& Instance();

			/**
			 * @brief Initialize the logger with configuration.
			 *
			 * Must be called before logging for configured behavior.
			 * If not called, logger auto-initializes with console-only defaults.
			 *
			 * @param cfg Logger configuration
			 */
			void Initialize(const LoggerConfig& cfg);

			/**
			 * @brief Shut down the logger and flush pending messages.
			 *
			 * Stops the async worker thread and writes remaining messages.
			 * Should be called before application exit.
			 */
			void ShutDown();

			/**
			 * @brief Check if logger is initialized.
			 * @return true if initialized, false otherwise
			 */
			[[nodiscard]] bool IsInitialized() const noexcept;

			/**
			 * @brief Set the minimum log level.
			 * @param level New minimum level
			 */
			void setMinimalLevel(LogLevel level) noexcept;

			/**
			 * @brief Check if a log level is enabled.
			 * @param level Level to check
			 * @return true if level would be logged
			 */
			[[nodiscard]] bool IsEnabled(LogLevel level) const noexcept;

			/**
			 * @brief Log a formatted message with source location.
			 */
			void LogEx(LogLevel level,
			           const wchar_t* category,
			           const wchar_t* file,
			           int line,
			           const wchar_t* function,
			           const wchar_t* format, ...);

			/**
			 * @brief Log a Windows error with context.
			 */
			void LogWinErrorEx(LogLevel level,
			                   const wchar_t* category,
			                   const wchar_t* file,
			                   int line,
			                   const wchar_t* function,
			                   DWORD errorCode,
			                   const wchar_t* contextFormat, ...);

			/**
			 * @brief Log a pre-formatted message.
			 */
			void LogMessage(LogLevel level,
			                const wchar_t* category,
			                const std::wstring& message,
			                const wchar_t* file = nullptr,
			                int line = 0,
			                const wchar_t* function = nullptr,
			                DWORD winError = 0);

			/**
			 * @brief Flush all pending log messages.
			 */
			void Flush();

			/**
			 * @brief Convert narrow string to wide string (thread-local buffer).
			 * @param s Narrow string to convert
			 * @return Wide string pointer (thread-local, do not store)
			 */
			[[nodiscard]] static const wchar_t* NarrowToWideTLS(const char* s);

			/**
			 * @brief Format a message with va_list.
			 * @param fmt Format string
			 * @param args Variable arguments
			 * @return Formatted string
			 */
			[[nodiscard]] static std::wstring FormatMessageV(const wchar_t* fmt, va_list args);

			/**
			 * @brief RAII scope logger for function entry/exit timing.
			 */
			class Scope {
			public:
				Scope(const wchar_t* category,
				      const wchar_t* file,
				      int line,
				      const wchar_t* function,
				      const wchar_t* messageOnEnter = L"Enter",
				      LogLevel level = LogLevel::Debug);
				~Scope();

				// Non-copyable, non-movable
				Scope(const Scope&) = delete;
				Scope& operator=(const Scope&) = delete;
				Scope(Scope&&) = delete;
				Scope& operator=(Scope&&) = delete;

			private:
				const wchar_t* m_category;
				const wchar_t* m_file;
				const wchar_t* m_function;
				int m_line;
#ifdef _WIN32
				LARGE_INTEGER m_start{};
				LARGE_INTEGER m_freq{};
#endif
				LogLevel m_level;
			};

			// Non-copyable singleton
			Logger(const Logger&) = delete;
			Logger& operator=(const Logger&) = delete;

		private:
			Logger();
			~Logger();

			// ========================================================================
			// Internal Types
			// ========================================================================

			/**
			 * @brief Internal log item structure.
			 */
			struct LogItem {
				LogLevel level = LogLevel::Info;
				std::wstring category;
				std::wstring message;
				std::wstring file;
				std::wstring function;
				int line = 0;
				uint32_t pid = 0;
				uint32_t tid = 0;
				uint64_t ts_100ns = 0;
				DWORD winError = 0;
			};

			// ========================================================================
			// Internal Methods
			// ========================================================================

			void EnsureInitialized();
			void WorkerLoop();
			void Enqueue(LogItem&& item);
			[[nodiscard]] bool Dequeue(LogItem& out);

			void WriteConsole(const LogItem& item);
			void WriteFile(const LogItem& item);
			void WriteEventLog(const LogItem& item);

			[[nodiscard]] std::wstring FormatPrefix(const LogItem& item) const;
			[[nodiscard]] std::wstring FormatAsJson(const LogItem& item) const;
			[[nodiscard]] static std::wstring EscapeJson(const std::wstring& s);

			void OpenLogFileIfNeeded();
			void RotateIfNeeded(size_t nextWriteBytes);
			void PerformRotation();
			void EnsureLogDirectory();
			[[nodiscard]] std::wstring CurrentLogPath() const;
			[[nodiscard]] std::wstring BaseLogPath() const;

			[[nodiscard]] static uint64_t NowAsFileTime100nsUTC();
			[[nodiscard]] static std::wstring FormatIso8601UTC(uint64_t filetime100ns);
			[[nodiscard]] static std::wstring FormatWinError(DWORD err);

			void OpenEventLog();
			void CloseEventLog();

			// ========================================================================
			// Member Variables
			// ========================================================================

			/// Flag indicating logger is accepting messages
			std::atomic<bool> m_accepting{ false };

			/// Flag to prevent recursive rotation
			std::atomic<bool> m_insideRotation{ false };

			/// Actual log file path after rotation
			std::wstring m_actualLogPath;

			/// Initialization state
			std::atomic<bool> m_initialized{ false };

			/// Current minimum log level
			std::atomic<LogLevel> m_minLevel{ LogLevel::Info };

			/// Logger configuration
			LoggerConfig m_cfg{};

			/// Mutex protecting configuration access
			mutable std::mutex m_cfgMutex;

			/// Log message queue for async mode
			std::deque<LogItem> m_queue;

			/// Mutex protecting queue access
			mutable std::mutex m_queueMutex;

			/// Condition variable for queue signaling
			std::condition_variable m_queueCv;

			/// Async worker thread
			std::thread m_worker;

			/// Stop flag for worker thread
			std::atomic<bool> m_stop{ false };

#ifdef _WIN32
			/// Log file handle
			HANDLE m_file{ INVALID_HANDLE_VALUE };

			/// Current log file size
			uint64_t m_currentSize{ 0 };

			/// Windows Event Log handle
			HANDLE m_eventSrc{ nullptr };

			/// Console output handle
			HANDLE m_console{ nullptr };
#endif
		};

	}  // namespace Utils
}  // namespace ShadowStrike

// ═══════════════════════════════════════════════════════════════════════════
// LOGGING MACROS
// ═══════════════════════════════════════════════════════════════════════════
//
// These macros provide convenient logging with automatic source location.
// They must be defined outside the namespace to work correctly with __FILE__
// and __FUNCTION__ macros.
//
// Usage:
//   SS_LOG_INFO(L"Category", L"Message with %d format", value);
//   SS_LOG_ERROR(L"Category", L"Error occurred: %ls", errorMsg);
//   SS_LOG_LAST_ERROR(L"Category", L"Win32 API failed");
//   SS_LOG_SCOPE(L"Category");  // Logs function entry/exit with timing
//
// ═══════════════════════════════════════════════════════════════════════════

/// @brief Log at TRACE level
#define SS_LOG_TRACE(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Trace)) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Trace, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief Log at DEBUG level
#define SS_LOG_DEBUG(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Debug)) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Debug, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief Log at INFO level
#define SS_LOG_INFO(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Info)) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Info, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief Log at WARN level
#define SS_LOG_WARN(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Warn)) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Warn, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief Log at ERROR level
#define SS_LOG_ERROR(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Error)) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Error, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief Log at FATAL level
#define SS_LOG_FATAL(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Fatal)) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Fatal, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief Log Windows GetLastError() with context message
#define SS_LOG_LAST_ERROR(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized() && _lg.IsEnabled(::ShadowStrike::Utils::LogLevel::Error)) { \
            _lg.LogWinErrorEx(::ShadowStrike::Utils::LogLevel::Error, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), \
                ::GetLastError(), (fmt), ##__VA_ARGS__); \
        } \
    } while(0)

/// @brief RAII scope logger - logs function entry and exit with timing
#define SS_LOG_SCOPE(category) \
    ::ShadowStrike::Utils::Logger::Scope _ss_scope_obj_##__LINE__( \
        (category), \
        ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), \
        __LINE__, \
        ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__))