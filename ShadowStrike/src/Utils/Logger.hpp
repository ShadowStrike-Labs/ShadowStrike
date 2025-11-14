#pragma once

#include<atomic>
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
#  define NOMINMAX
#undef WriteConsole
#  include <Windows.h>
#endif

namespace ShadowStrike {
	namespace Utils {
		enum class LogLevel : uint8_t
		{
			Trace = 0,
			Debug,
			Info,
			Warn,
			Error,
			Fatal
		};

		struct LoggerConfig {
			size_t   maxQueueSize = 1000;
			enum class BackPressurePolicy { Block, DropOldest, DropNewest } bpPolicy = BackPressurePolicy::DropOldest;
			bool        async = true;
			bool        toConsole = true;
			bool        toFile = true;
			bool        toEventLog = false;
			bool        jsonLines = false;
			bool        useUtcTime = true;
			bool        includeSrcLocation = true;
			bool        includeProcThreadId = true;

			std::wstring logDirectory = L"logs";
			std::wstring baseFileName = L"ShadowStrike";
			uint64_t     maxFileSizeBytes = 10ull * 1024ull * 1024ull;
			size_t       maxFileCount = 10;

			LogLevel     minimalLevel = LogLevel::Info;
			LogLevel     flushLevel = LogLevel::Error;
			std::wstring eventLogSource = L"ShadowStrike";
		};

		struct SourceLocationW {
			const wchar_t* file;
			int line;
			const wchar_t* function;
		};

		class Logger {
		public:
			static Logger& Instance();

			void Initialize(const LoggerConfig& cfg);
			void ShutDown();
			bool IsInitialized() const noexcept;

			void setMinimalLevel(LogLevel level) noexcept;
			bool IsEnabled(LogLevel level) const noexcept;

			void LogEx(LogLevel level,
				const wchar_t* category,
				const wchar_t* file,
				int line,
				const wchar_t* function,
				const wchar_t* format, ...);

			void LogWinErrorEx(LogLevel level,
				const wchar_t* category,
				const wchar_t* file,
				int line,
				const wchar_t* function,
				DWORD errorCode,
				const wchar_t* contextFormat, ...);

			void LogMessage(LogLevel level,
				const wchar_t* category,
				const std::wstring& message,
				const wchar_t* file = nullptr,
				int line = 0,
				const wchar_t* function = nullptr,
				DWORD winError = 0);

			void Flush();

			static const wchar_t* NarrowToWideTLS(const char* s);
			static std::wstring FormatMessageV(const wchar_t* fmt, va_list args);

			class Scope {
			public:
				Scope(const wchar_t* category,
					const wchar_t* file,
					int line,
					const wchar_t* function,
					const wchar_t* messageOnEnter = L"Enter",
					LogLevel level = LogLevel::Debug);
				~Scope();

				Scope(const Scope&) = delete;
				Scope& operator=(const Scope&) = delete;

			private:
				const wchar_t* m_category;
				const wchar_t* m_file;
				const wchar_t* m_function;
				int            m_line;
#ifdef _WIN32
				LARGE_INTEGER  m_start{};
				LARGE_INTEGER  m_freq{};
#endif
				LogLevel       m_level;
			};

			Logger(const Logger&) = delete;
			Logger& operator=(const Logger&) = delete;

		private:
			Logger();
			~Logger();

			struct LogItem
			{
				LogLevel          level;
				std::wstring      category;
				std::wstring      message;
				std::wstring      file;
				std::wstring      function;
				int               line = 0;
				uint32_t          pid = 0;
				uint32_t          tid = 0;
				uint64_t          ts_100ns = 0;
				DWORD             winError = 0;
			};

			void EnsureInitialized();
			void WorkerLoop();
			void Enqueue(LogItem&& item);
			bool Dequeue(LogItem& out);

			void WriteConsole(const LogItem& item);
			void WriteFile(const LogItem& item);
			void WriteEventLog(const LogItem& item);

			std::wstring FormatPrefix(const LogItem& item) const;
			std::wstring FormatAsJson(const LogItem& item) const;
			static std::wstring EscapeJson(const std::wstring& s);

			void OpenLogFileIfNeeded();
			void RotateIfNeeded(size_t nextWriteBytes);
			void PerformRotation();
			void EnsureLogDirectory();
			std::wstring CurrentLogPath() const;
			std::wstring BaseLogPath() const;

			static uint64_t NowAsFileTime100nsUTC();
			static std::wstring FormatIso8601UTC(uint64_t filetime100ns);
			static std::wstring FormatWinError(DWORD err);

			void OpenEventLog();
			void CloseEventLog();

			std::atomic<bool> m_accepting{ false };
			std::atomic<bool> m_insideRotation{ false };

			std::wstring m_actualLogPath;
			std::atomic<bool> m_initialized{ false };
			std::atomic<LogLevel> m_minLevel{ LogLevel::Info };
			LoggerConfig m_cfg{};
			std::mutex m_cfgmutex;

			std::deque<LogItem> m_queue;
			std::mutex m_queueMutex;
			std::condition_variable m_queueCv;

			std::thread m_worker;
			std::atomic<bool> m_stop{ false };

#ifdef _WIN32
			HANDLE m_file{ INVALID_HANDLE_VALUE };
			uint64_t m_currentSize{ 0 };
			HANDLE m_eventSrc{ nullptr };
			HANDLE m_console{ nullptr };
#endif
		};

	} // namespace Utils
} // namespace ShadowStrike

// ═══════════════════════════════════════════════════════════════════════════
// MACROS (OUTSIDE NAMESPACE - CRITICAL!)
// ═══════════════════════════════════════════════════════════════════════════

#define SS_LOG_TRACE(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Trace, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_DEBUG(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Debug, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_INFO(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Info, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_WARN(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Warn, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_ERROR(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Error, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_FATAL(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogEx(::ShadowStrike::Utils::LogLevel::Fatal, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_LAST_ERROR(category, fmt, ...) \
    do { \
        auto& _lg = ::ShadowStrike::Utils::Logger::Instance(); \
        if (_lg.IsInitialized()) { \
            _lg.LogWinErrorEx(::ShadowStrike::Utils::LogLevel::Error, (category), \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), __LINE__, \
                ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__), \
                ::GetLastError(), (fmt), __VA_ARGS__); \
        } \
    } while(0)

#define SS_LOG_SCOPE(category) \
    ::ShadowStrike::Utils::Logger::Scope _ss_scope_obj( \
        (category), \
        ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FILE__), \
        __LINE__, \
        ::ShadowStrike::Utils::Logger::NarrowToWideTLS(__FUNCTION__))