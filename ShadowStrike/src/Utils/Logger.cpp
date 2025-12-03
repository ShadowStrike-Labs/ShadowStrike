/**
 * @file Logger.cpp
 * @brief Implementation of the thread-safe asynchronous logging system.
 *
 * This file implements:
 * - Singleton logger with lazy initialization
 * - Async worker thread with queue-based message processing
 * - Log file rotation with configurable limits
 * - Multiple output targets (console, file, Windows Event Log)
 * - Source location tracking and timing measurements
 */

#include "Logger.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <chrono>
#include <limits>

#ifdef _WIN32
#  include <io.h>
#  include <Shlwapi.h>
#  pragma comment(lib, "Shlwapi.lib")
#endif

namespace ShadowStrike {
	namespace Utils {

		// ============================================================================
		// Helper Functions
		// ============================================================================

		/**
		 * @brief Convert log level to wide string representation.
		 * @param lv Log level
		 * @return Wide string name of the log level
		 */
		[[nodiscard]] static const wchar_t* LevelToW(LogLevel lv) noexcept {
			switch (lv) {
			case LogLevel::Trace: return L"TRACE";
			case LogLevel::Debug: return L"DEBUG";
			case LogLevel::Info:  return L"INFO";
			case LogLevel::Warn:  return L"WARN";
			case LogLevel::Error: return L"ERROR";
			case LogLevel::Fatal: return L"FATAL";
			default:              return L"UNKNOWN";
			}
		}

		// ============================================================================
		// Singleton Instance
		// ============================================================================

		Logger& Logger::Instance() {
			static Logger g_instance;
			return g_instance;
		}

		// ============================================================================
		// Constructor / Destructor
		// ============================================================================

		Logger::Logger() {
#ifdef _WIN32
			m_console = GetStdHandle(STD_OUTPUT_HANDLE);
			// Validate console handle
			if (m_console == INVALID_HANDLE_VALUE) {
				m_console = nullptr;
			}
#endif
		}

		Logger::~Logger() {
			ShutDown();
		}

		// ============================================================================
		// State Query Methods
		// ============================================================================

		bool Logger::IsEnabled(LogLevel level) const noexcept {
			const LogLevel minLevel = m_minLevel.load(std::memory_order_acquire);
			return static_cast<uint8_t>(level) >= static_cast<uint8_t>(minLevel);
		}

		bool Logger::IsInitialized() const noexcept {
			return m_initialized.load(std::memory_order_acquire);
		}

		void Logger::setMinimalLevel(LogLevel level) noexcept {
			m_minLevel.store(level, std::memory_order_release);
		}

		// ============================================================================
		// Initialization
		// ============================================================================

		void Logger::EnsureInitialized() {
			// Fast path - already initialized
			if (m_initialized.load(std::memory_order_acquire)) {
				return;
			}

			// Attempt to claim initialization
			bool expected = false;
			if (m_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				// We won the race - set up default console-only config
				LoggerConfig defaultCfg{};
				defaultCfg.async = false;
				defaultCfg.toFile = false;
				defaultCfg.toEventLog = false;
				defaultCfg.toConsole = true;

				{
					std::lock_guard<std::mutex> lk(m_cfgMutex);
					m_cfg = defaultCfg;
				}
				m_minLevel.store(defaultCfg.minimalLevel, std::memory_order_release);
				m_accepting.store(true, std::memory_order_release);
			}
		}

		void Logger::Initialize(const LoggerConfig& cfg) {
			// Only allow initialization once
			bool expected = false;
			if (!m_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				// Already initialized - ignore duplicate calls
				return;
			}

			// Store configuration
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				m_cfg = cfg;
			}
			m_minLevel.store(cfg.minimalLevel, std::memory_order_release);

			// Initialize output targets
			try {
#ifdef _WIN32
				if (cfg.toFile) {
					EnsureLogDirectory();
					OpenLogFileIfNeeded();
				}
				if (cfg.toEventLog) {
					OpenEventLog();
				}
#endif
			}
			catch (const std::exception& /*e*/) {
				// Disable failed outputs but continue
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				m_cfg.toFile = false;
				m_cfg.toEventLog = false;
				OutputDebugStringW(L"[Logger] File/EventLog initialization failed\n");
			}
			catch (...) {
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				m_cfg.toFile = false;
				m_cfg.toEventLog = false;
				OutputDebugStringW(L"[Logger] Unknown initialization error\n");
			}

			// Initialize async worker if enabled
			m_stop.store(false, std::memory_order_release);

			if (cfg.async) {
				try {
					m_worker = std::thread([this]() { WorkerLoop(); });
					// Brief wait to allow worker to start
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}
				catch (const std::exception& /*e*/) {
					std::lock_guard<std::mutex> lk(m_cfgMutex);
					m_cfg.async = false;
					OutputDebugStringW(L"[Logger] Async mode disabled - thread creation failed\n");
				}
				catch (...) {
					std::lock_guard<std::mutex> lk(m_cfgMutex);
					m_cfg.async = false;
					OutputDebugStringW(L"[Logger] Async mode disabled - unknown error\n");
				}
			}

			// Start accepting messages
			m_accepting.store(true, std::memory_order_release);
		}

		// ============================================================================
		// Shutdown
		// ============================================================================

		void Logger::ShutDown() {
			// Only allow shutdown once
			bool expected = true;
			if (!m_initialized.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
				return;  // Not initialized or already shut down
			}

			// Stop accepting new messages
			m_accepting.store(false, std::memory_order_release);

			// Signal worker thread to stop
			m_stop.store(true, std::memory_order_release);
			m_queueCv.notify_all();

			// Join worker thread with timeout
			if (m_worker.joinable()) {
				constexpr auto SHUTDOWN_TIMEOUT = std::chrono::seconds(5);
				const auto deadline = std::chrono::steady_clock::now() + SHUTDOWN_TIMEOUT;

				try {
					while (m_worker.joinable()) {
						if (std::chrono::steady_clock::now() > deadline) {
							// Timeout exceeded - force detach
							OutputDebugStringW(L"[Logger] Worker thread join timeout, forcing detach\n");
							m_worker.detach();
							break;
						}

						// Signal and wait briefly
						m_queueCv.notify_all();
						std::this_thread::sleep_for(std::chrono::milliseconds(50));

						// Attempt join
						try {
							m_worker.join();
							break;  // Success
						}
						catch (const std::system_error& /*e*/) {
							// Join failed, retry until timeout
						}
					}
				}
				catch (...) {
					// Emergency detach on any exception
					if (m_worker.joinable()) {
						m_worker.detach();
					}
				}
			}

			// Drain remaining queue items
			bool toConsoleCfg = false;
			bool toFileCfg = false;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				toConsoleCfg = m_cfg.toConsole;
				toFileCfg = m_cfg.toFile;
			}

			LogItem item;
			while (Dequeue(item)) {
				try {
					if (toConsoleCfg) WriteConsole(item);
					if (toFileCfg) WriteFile(item);
				}
				catch (...) {
					// Ignore errors during shutdown drain
				}
			}

			// Close file and event log handles
#ifdef _WIN32
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				if (m_file != nullptr && m_file != INVALID_HANDLE_VALUE) {
					FlushFileBuffers(m_file);
					CloseHandle(m_file);
					m_file = INVALID_HANDLE_VALUE;
				}
			}
			CloseEventLog();
#endif
		}

		// ============================================================================
		// Queue Operations
		// ============================================================================

		void Logger::Enqueue(LogItem&& item) {
			// Early exit checks with proper memory ordering
			if (!m_accepting.load(std::memory_order_acquire)) return;
			if (!IsInitialized()) return;
			if (!IsEnabled(item.level)) return;

			// Capture configuration atomically
			bool asyncCfg = false;
			bool toConsoleCfg = false;
			bool toFileCfg = false;
			bool toEventLogCfg = false;
			size_t maxQueueSz = 0;

			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				asyncCfg = m_cfg.async;
				toConsoleCfg = m_cfg.toConsole;
				toFileCfg = m_cfg.toFile;
				toEventLogCfg = m_cfg.toEventLog;
				maxQueueSz = m_cfg.maxQueueSize;
			}

			if (asyncCfg) {
				// Async mode: queue the item for worker thread
				std::lock_guard<std::mutex> lk(m_queueMutex);

				// Drop oldest if queue is full (bounded queue pattern)
				if (maxQueueSz > 0 && m_queue.size() >= maxQueueSz) {
					m_queue.pop_front();
				}

				m_queue.emplace_back(std::move(item));
				m_queueCv.notify_one();
			}
			else {
				// Sync mode: write directly
				try {
					if (toConsoleCfg) WriteConsole(item);
					if (toFileCfg) WriteFile(item);
					if (toEventLogCfg && item.level >= LogLevel::Warn) WriteEventLog(item);
				}
				catch (const std::exception& e) {
					// Use OutputDebugString to avoid recursive logging
					OutputDebugStringA("[Logger] Enqueue sync write exception: ");
					OutputDebugStringA(e.what());
					OutputDebugStringA("\n");
				}
				catch (...) {
					OutputDebugStringW(L"[Logger] Enqueue sync write unknown exception\n");
				}
			}
		}

		bool Logger::Dequeue(LogItem& out) {
			std::lock_guard<std::mutex> lk(m_queueMutex);
			if (m_queue.empty()) {
				return false;
			}
			out = std::move(m_queue.front());
			m_queue.pop_front();
			return true;
		}

		// ============================================================================
		// Worker Thread
		// ============================================================================

		void Logger::WorkerLoop() {
			while (!m_stop.load(std::memory_order_acquire)) {
				LogItem item;
				bool hasItem = false;

				// Wait for items or stop signal
				{
					std::unique_lock<std::mutex> lk(m_queueMutex);
					
					// Wait with timeout to allow periodic stop checks
					constexpr auto kWorkerWaitTimeout = std::chrono::seconds(1);
					m_queueCv.wait_for(lk, kWorkerWaitTimeout, [this]() {
						return m_stop.load(std::memory_order_acquire) || !m_queue.empty();
					});

					// Check stop condition with empty queue
					if (m_stop.load(std::memory_order_acquire) && m_queue.empty()) {
						break;
					}

					// Continue if spurious wakeup
					if (m_queue.empty()) {
						continue;
					}

					// Dequeue item
					item = std::move(m_queue.front());
					m_queue.pop_front();
					hasItem = true;
				}

				if (!hasItem) {
					continue;
				}

				// Get configuration for output targets
				bool toConsoleCfg = false;
				bool toFileCfg = false;
				bool toEventLogCfg = false;
				{
					std::lock_guard<std::mutex> lk(m_cfgMutex);
					toConsoleCfg = m_cfg.toConsole;
					toFileCfg = m_cfg.toFile;
					toEventLogCfg = m_cfg.toEventLog;
				}

				// Write to configured targets
				try {
					if (toConsoleCfg) WriteConsole(item);
					if (toFileCfg) WriteFile(item);
					if (toEventLogCfg && item.level >= LogLevel::Warn) WriteEventLog(item);
				}
				catch (const std::exception& e) {
					OutputDebugStringA("[Logger] WorkerLoop exception: ");
					OutputDebugStringA(e.what());
					OutputDebugStringA("\n");
				}
				catch (...) {
					OutputDebugStringW(L"[Logger] WorkerLoop unknown exception\n");
				}
			}
		}

		// ============================================================================
		// Logging Entry Points
		// ============================================================================

		void Logger::LogEx(LogLevel level, const wchar_t* category, const wchar_t* file,
			int line, const wchar_t* function, const wchar_t* format, ...) {
			if (!IsEnabled(level)) return;

			va_list args;
			va_start(args, format);
			std::wstring msg = FormatMessageV(format, args);
			va_end(args);

			LogMessage(level, category, msg, file, line, function, 0);
		}

		void Logger::LogWinErrorEx(LogLevel level, const wchar_t* category, const wchar_t* file,
			int line, const wchar_t* function, DWORD errorCode,
			const wchar_t* contextFormat, ...) {
			if (!IsEnabled(level)) return;

			va_list args;
			va_start(args, contextFormat);
			std::wstring context = FormatMessageV(contextFormat, args);
			va_end(args);

			std::wstring winErr = FormatWinError(errorCode);
			std::wstring combined = context + L": " + winErr;

			LogMessage(level, category, combined, file, line, function, errorCode);
		}

		void Logger::LogMessage(LogLevel level, const wchar_t* category, const std::wstring& message,
			const wchar_t* file, int line, const wchar_t* function, DWORD winError) {
			// Build log item with all metadata
			LogItem item{};
			item.level = level;
			item.category = (category != nullptr) ? category : L"";
			item.message = message;
			item.file = (file != nullptr) ? file : L"";
			item.function = (function != nullptr) ? function : L"";
			item.line = line;
#ifdef _WIN32
			item.pid = GetCurrentProcessId();
			item.tid = GetCurrentThreadId();
#endif
			item.ts_100ns = NowAsFileTime100nsUTC();
			item.winError = winError;

			Enqueue(std::move(item));

			// Auto-flush for high severity messages
			LogLevel flushLvl = LogLevel::Error;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				flushLvl = m_cfg.flushLevel;
			}

			if (static_cast<int>(level) >= static_cast<int>(flushLvl)) {
				Flush();
			}
		}

		// ============================================================================
		// Flush
		// ============================================================================

		void Logger::Flush() {
#ifdef _WIN32
			// Get current configuration
			bool asyncCfg = false;
			bool toConsoleCfg = false;
			bool toFileCfg = false;
			bool toEventLogCfg = false;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				asyncCfg = m_cfg.async;
				toConsoleCfg = m_cfg.toConsole;
				toFileCfg = m_cfg.toFile;
				toEventLogCfg = m_cfg.toEventLog;
			}

			if (asyncCfg) {
				// Wait for queue to drain with timeout
				constexpr auto FLUSH_TIMEOUT = std::chrono::seconds(5);
				const auto deadline = std::chrono::steady_clock::now() + FLUSH_TIMEOUT;
				
				while (std::chrono::steady_clock::now() < deadline) {
					{
						std::lock_guard<std::mutex> lk(m_queueMutex);
						if (m_queue.empty()) break;
					}
					m_queueCv.notify_all();
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}

				// Drain any remaining items directly
				LogItem x{};
				while (Dequeue(x)) {
					try {
						if (toConsoleCfg) WriteConsole(x);
						if (toFileCfg) WriteFile(x);
						if (toEventLogCfg && x.level >= LogLevel::Warn) WriteEventLog(x);
					}
					catch (const std::exception& e) {
						OutputDebugStringA("[Logger] Flush drain exception: ");
						OutputDebugStringA(e.what());
						OutputDebugStringA("\n");
					}
					catch (...) {
						OutputDebugStringW(L"[Logger] Flush drain unknown exception\n");
					}
				}
			}

			// Flush file buffers
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				if (m_file != nullptr && m_file != INVALID_HANDLE_VALUE) {
					FlushFileBuffers(m_file);
				}
			}
#endif
		}

		// ============================================================================
		// String Conversion Utilities
		// ============================================================================

		const wchar_t* Logger::NarrowToWideTLS(const char* s) {
#ifdef _WIN32
			thread_local std::wstring buff;
			
			// Null/empty check
			if (s == nullptr) {
				buff.clear();
				return buff.c_str();
			}

			const int len = static_cast<int>(strlen(s));
			if (len <= 0) {
				buff.clear();
				return buff.c_str();
			}

			// Safety limit to prevent DoS
			constexpr int MAX_INPUT_LEN = 100000;
			if (len > MAX_INPUT_LEN) {
				buff = L"[Too long]";
				return buff.c_str();
			}

			// Get required buffer size
			const int wlen = MultiByteToWideChar(CP_UTF8, 0, s, len, nullptr, 0);
			if (wlen <= 0) {
				buff.clear();
				return buff.c_str();
			}
			if (wlen > MAX_INPUT_LEN) {
				buff = L"[Too long]";
				return buff.c_str();
			}

			// Perform conversion
			buff.resize(static_cast<size_t>(wlen));
			if (MultiByteToWideChar(CP_UTF8, 0, s, len, buff.data(), wlen) <= 0) {
				buff.clear();
			}
			return buff.c_str();
#else
			static thread_local std::wstring buff;
			buff.clear();
			return buff.c_str();
#endif
		}

		// ============================================================================
		// Message Formatting
		// ============================================================================

		std::wstring Logger::FormatMessageV(const wchar_t* fmt, va_list args) {
			if (fmt == nullptr) {
				return L"";
			}

			// Initial buffer size
			std::wstring out;
			out.resize(512);

			// First attempt with small buffer
			va_list args_copy;
			va_copy(args_copy, args);
			const int needed = _vsnwprintf_s(out.data(), out.size(), _TRUNCATE, fmt, args_copy);
			va_end(args_copy);

			if (needed >= 0 && static_cast<size_t>(needed) < out.size()) {
				out.resize(static_cast<size_t>(needed));
				return out;
			}

			// Exponential growth for larger messages
			size_t cap = 1024;
			constexpr size_t MAX_CAP = 1u << 20;  // 1MB safety limit
			
			while (cap <= MAX_CAP) {
				out.resize(cap);

				va_copy(args_copy, args);
				const int n = _vsnwprintf_s(out.data(), out.size(), _TRUNCATE, fmt, args_copy);
				va_end(args_copy);

				if (n >= 0 && static_cast<size_t>(n) < out.size()) {
					out.resize(static_cast<size_t>(n));
					return out;
				}
				cap *= 2;
			}
			
			return L"[Logger] Message too large";
		}

		std::wstring Logger::FormatWinError(DWORD err) {
#ifdef _WIN32
			LPWSTR buf = nullptr;
			const DWORD n = FormatMessageW(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				nullptr,
				err,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				reinterpret_cast<LPWSTR>(&buf),
				0,
				nullptr);

			std::wstring out = L"WinError " + std::to_wstring(err);
			
			if (n > 0 && buf != nullptr) {
				// Trim trailing whitespace
				DWORD trimmed = n;
				while (trimmed > 0 && (buf[trimmed - 1] == L'\r' || 
									   buf[trimmed - 1] == L'\n' || 
									   buf[trimmed - 1] == L' ')) {
					--trimmed;
				}
				out.append(L": ");
				out.append(buf, static_cast<size_t>(trimmed));
				LocalFree(buf);
			}
			return out;
#else
			return L"";
#endif
		}

		// ============================================================================
		// Timestamp Utilities
		// ============================================================================

		uint64_t Logger::NowAsFileTime100nsUTC() {
#ifdef _WIN32
			FILETIME ft{};
			
			// Try high-precision timer first (Windows 8+)
			using GetPreciseFunc = VOID(WINAPI*)(LPFILETIME);
			static const GetPreciseFunc pGetPrecise = 
				reinterpret_cast<GetPreciseFunc>(
					GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetSystemTimePreciseAsFileTime"));
			
			if (pGetPrecise != nullptr) {
				pGetPrecise(&ft);
			}
			else {
				GetSystemTimeAsFileTime(&ft);
			}

			ULARGE_INTEGER uli{};
			uli.LowPart = ft.dwLowDateTime;
			uli.HighPart = ft.dwHighDateTime;
			return uli.QuadPart;
#else 
			return 0;
#endif
		}

		std::wstring Logger::FormatIso8601UTC(uint64_t filetime100ns) {
#ifdef _WIN32
			FILETIME ft{};
			ft.dwLowDateTime = static_cast<DWORD>(filetime100ns & 0xFFFFFFFFull);
			ft.dwHighDateTime = static_cast<DWORD>((filetime100ns >> 32) & 0xFFFFFFFFull);

			SYSTEMTIME st{};
			if (!FileTimeToSystemTime(&ft, &st)) {
				return L"[Invalid timestamp]";
			}

			wchar_t buf[40] = { 0 };
			_snwprintf_s(buf, _TRUNCATE, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
			return std::wstring(buf);
#else
			return L"";
#endif
		}

		// ============================================================================
		// JSON Utilities
		// ============================================================================

		std::wstring Logger::EscapeJson(const std::wstring& s) {
			std::wstring out;
			out.reserve(s.size() + 16);

			for (const wchar_t c : s) {
				switch (c) {
				case L'\\': out += L"\\\\"; break;
				case L'"':  out += L"\\\""; break;
				case L'\b': out += L"\\b";  break;
				case L'\f': out += L"\\f";  break;
				case L'\n': out += L"\\n";  break;
				case L'\r': out += L"\\r";  break;
				case L'\t': out += L"\\t";  break;
				default:
					if (c < 0x20) {
						// Escape control characters as Unicode
						wchar_t buf[7];
						_snwprintf_s(buf, _TRUNCATE, L"\\u%04x", static_cast<unsigned>(c));
						out += buf;
					}
					else {
						out += c;
					}
				}
			}
			return out;
		}

		// ============================================================================
		// Output Formatting
		// ============================================================================

		std::wstring Logger::FormatPrefix(const LogItem& item) const {
			const std::wstring ts = FormatIso8601UTC(item.ts_100ns);
			std::wstring s;
			s.reserve(128);
			s += ts;
			s += L" [";
			s += LevelToW(item.level);
			s += L"]";

			if (!item.category.empty()) {
				s += L" [";
				s += item.category;
				s += L"]";
			}

			// Get configuration for optional fields
			bool includeProcThreadIdCfg = false;
			bool includeSrcLocationCfg = false;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				includeProcThreadIdCfg = m_cfg.includeProcThreadId;
				includeSrcLocationCfg = m_cfg.includeSrcLocation;
			}

			// Process/Thread ID
			if (includeProcThreadIdCfg) {
				s += L" (";
				s += std::to_wstring(item.pid);
				s += L":";
				s += std::to_wstring(item.tid);
				s += L")";
			}

			// Source location
			if (includeSrcLocationCfg && !item.file.empty()) {
				s += L" ";
				s += item.file;
				s += L":";
				s += std::to_wstring(item.line);

				if (!item.function.empty()) {
					s += L" ";
					s += item.function;
				}
			}

			s += L" - ";
			return s;
		}

		std::wstring Logger::FormatAsJson(const LogItem& item) const {
			std::wstring s;
			s.reserve(128 + item.message.size());
			s += L"{\"ts\":\"";
			s += EscapeJson(FormatIso8601UTC(item.ts_100ns));
			s += L"\",\"lvl\":\"";
			s += LevelToW(item.level);
			s += L"\"";

			if (!item.category.empty()) {
				s += L",\"cat\":\"";
				s += EscapeJson(item.category);
				s += L"\"";
			}

			// Get configuration for optional fields
			bool includeProcThreadIdCfg = false;
			bool includeSrcLocationCfg = false;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				includeProcThreadIdCfg = m_cfg.includeProcThreadId;
				includeSrcLocationCfg = m_cfg.includeSrcLocation;
			}

			if (includeProcThreadIdCfg) {
				s += L",\"pid\":";
				s += std::to_wstring(item.pid);
				s += L",\"tid\":";
				s += std::to_wstring(item.tid);
			}

			if (includeSrcLocationCfg && !item.file.empty()) {
				s += L",\"file\":\"";
				s += EscapeJson(item.file);
				s += L"\",\"line\":";
				s += std::to_wstring(item.line);

				if (!item.function.empty()) {
					s += L",\"func\":\"";
					s += EscapeJson(item.function);
					s += L"\"";
				}
			}

			if (item.winError != 0) {
				s += L",\"winerr\":";
				s += std::to_wstring(item.winError);
			}

			s += L",\"msg\":\"";
			s += EscapeJson(item.message);
			s += L"\"}";
			return s;
		}

		// ============================================================================
		// Console Output
		// ============================================================================

		void Logger::WriteConsole(const LogItem& item) {
#ifdef _WIN32
			// Validate console handle
			if (m_console == nullptr || m_console == INVALID_HANDLE_VALUE) {
				return;
			}

			// Determine color based on log level
			WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
			switch (item.level) {
			case LogLevel::Trace: color = FOREGROUND_BLUE | FOREGROUND_GREEN; break;
			case LogLevel::Debug: color = FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
			case LogLevel::Info:  color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
			case LogLevel::Warn:  color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
			case LogLevel::Error: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
			case LogLevel::Fatal: color = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
			}

			// Save current console attributes
			CONSOLE_SCREEN_BUFFER_INFO csbi{};
			if (!GetConsoleScreenBufferInfo(m_console, &csbi)) {
				csbi.wAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
			}

			SetConsoleTextAttribute(m_console, color);

			// Get JSON format preference
			bool jsonLinesCfg = false;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				jsonLinesCfg = m_cfg.jsonLines;
			}

			std::wstring line = jsonLinesCfg ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
			line += L"\r\n";

			// Integer overflow check BEFORE cast
			constexpr size_t MAX_CONSOLE_WRITE = std::numeric_limits<DWORD>::max() / sizeof(wchar_t);
			if (line.size() > MAX_CONSOLE_WRITE) {
				line = L"[Logger] Message too large\r\n";
			}

			DWORD written = 0;
			::WriteConsoleW(m_console, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
			
			// Restore original console attributes
			SetConsoleTextAttribute(m_console, csbi.wAttributes);
#endif
		}

		// ============================================================================
		// File Output
		// ============================================================================

		void Logger::OpenLogFileIfNeeded() {
#ifdef _WIN32
			// Already have a valid handle
			if (m_file != nullptr && m_file != INVALID_HANDLE_VALUE) {
				return;
			}

			const std::wstring path = BaseLogPath();
			m_file = CreateFileW(
				path.c_str(),
				FILE_APPEND_DATA,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				nullptr);

			if (m_file == INVALID_HANDLE_VALUE) {
				// Retry once after brief delay
				std::this_thread::sleep_for(std::chrono::milliseconds(50));
				m_file = CreateFileW(
					path.c_str(),
					FILE_APPEND_DATA,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					nullptr,
					OPEN_ALWAYS,
					FILE_ATTRIBUTE_NORMAL,
					nullptr);
				
				if (m_file == INVALID_HANDLE_VALUE) {
					return;
				}
			}

			m_actualLogPath = path;
			
			// Get current file size
			LARGE_INTEGER size{};
			if (GetFileSizeEx(m_file, &size)) {
				m_currentSize = static_cast<uint64_t>(size.QuadPart);
			}
			else {
				m_currentSize = 0;
			}
#endif
		}

		void Logger::RotateIfNeeded(size_t nextWriteBytes) {
#ifdef _WIN32
			// Get configuration
			const bool toFileCfg = m_cfg.toFile;
			const uint64_t maxFileSizeBytesCfg = m_cfg.maxFileSizeBytes;

			if (!toFileCfg) return;
			if (m_file == nullptr || m_file == INVALID_HANDLE_VALUE) return;
			if (m_currentSize + nextWriteBytes <= maxFileSizeBytesCfg) return;

			PerformRotation();

			// Close and reopen file after rotation
			if (m_file != nullptr && m_file != INVALID_HANDLE_VALUE) {
				CloseHandle(m_file);
				m_file = INVALID_HANDLE_VALUE;
			}
			OpenLogFileIfNeeded();
#endif
		}

		// ============================================================================
		// File Rotation
		// ============================================================================

		void Logger::PerformRotation() {
#ifdef _WIN32
			// Prevent re-entry during rotation
			bool expected = false;
			if (!m_insideRotation.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				return;
			}

			// RAII guard to ensure flag is reset
			struct RotationGuard {
				std::atomic<bool>& flag;
				~RotationGuard() { flag.store(false, std::memory_order_release); }
			} guard{ m_insideRotation };

			try {
				// Flush and close current file
				if (m_file != nullptr && m_file != INVALID_HANDLE_VALUE) {
					::FlushFileBuffers(m_file);
					::CloseHandle(m_file);
					m_file = INVALID_HANDLE_VALUE;
				}

				const std::wstring base = BaseLogPath();
				const size_t maxFileCountCfg = m_cfg.maxFileCount;

				if (maxFileCountCfg > 1) {
					// Delete oldest file
					const std::wstring oldestFile = base + L"." + std::to_wstring(maxFileCountCfg);

					DWORD attrs = ::GetFileAttributesW(oldestFile.c_str());
					if (attrs != INVALID_FILE_ATTRIBUTES) {
						::SetFileAttributesW(oldestFile.c_str(), FILE_ATTRIBUTE_NORMAL);
						::DeleteFileW(oldestFile.c_str());
					}

					// Rotate files: .n-1 -> .n, .n-2 -> .n-1, etc.
					for (size_t idx = maxFileCountCfg - 1; idx >= 1; --idx) {
						const std::wstring srcFile = base + L"." + std::to_wstring(idx);
						const std::wstring dstFile = base + L"." + std::to_wstring(idx + 1);

						attrs = ::GetFileAttributesW(srcFile.c_str());
						if (attrs == INVALID_FILE_ATTRIBUTES) {
							if (idx == 1) break;
							continue;
						}

						attrs = ::GetFileAttributesW(dstFile.c_str());
						if (attrs != INVALID_FILE_ATTRIBUTES) {
							::SetFileAttributesW(dstFile.c_str(), FILE_ATTRIBUTE_NORMAL);
							::DeleteFileW(dstFile.c_str());
						}

						::MoveFileExW(srcFile.c_str(), dstFile.c_str(), 
							MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);

						if (idx == 1) break;
					}

					const std::wstring firstRotated = base + L".1";
					attrs = ::GetFileAttributesW(base.c_str());
					if (attrs != INVALID_FILE_ATTRIBUTES) {
						attrs = ::GetFileAttributesW(firstRotated.c_str());
						if (attrs != INVALID_FILE_ATTRIBUTES) {
							::SetFileAttributesW(firstRotated.c_str(), FILE_ATTRIBUTE_NORMAL);
							::DeleteFileW(firstRotated.c_str());
						}
						::MoveFileExW(base.c_str(), firstRotated.c_str(), 
							MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
					}
				}
				else {
					// Only one file allowed - just truncate
					const DWORD attrs = ::GetFileAttributesW(base.c_str());
					if (attrs != INVALID_FILE_ATTRIBUTES) {
						::SetFileAttributesW(base.c_str(), FILE_ATTRIBUTE_NORMAL);
						::DeleteFileW(base.c_str());
					}
				}

				m_currentSize = 0;
				m_actualLogPath.clear();
			}
			catch (const std::exception& e) {
				OutputDebugStringA("[Logger] Rotation failed: ");
				OutputDebugStringA(e.what());
				OutputDebugStringA("\n");
			}
			catch (...) {
				OutputDebugStringW(L"[Logger] Rotation failed with unknown exception\n");
			}
#endif
		}

		void Logger::EnsureLogDirectory() {
#ifdef _WIN32
			std::wstring logDirCfg;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				logDirCfg = m_cfg.logDirectory;
			}
			
			if (logDirCfg.empty()) {
				return;
			}

			const DWORD attrs = GetFileAttributesW(logDirCfg.c_str());
			if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
				return;  // Directory exists
			}
			
			CreateDirectoryW(logDirCfg.c_str(), nullptr);
#endif
		}

		std::wstring Logger::BaseLogPath() const {
#ifdef _WIN32
			// NOTE: Caller should lock m_cfgMutex OR accept potentially stale read
			std::wstring path = m_cfg.logDirectory;
			if (!path.empty()) {
				if (path.back() != L'\\' && path.back() != L'/') {
					path.push_back(L'\\');
				}
			}
			path += m_cfg.baseFileName;
			path += L".log";
			return path;
#else
			return L"ShadowStrike.log";
#endif
		}

		std::wstring Logger::CurrentLogPath() const {
			std::lock_guard<std::mutex> lk(m_cfgMutex);
			return m_actualLogPath.empty() ? BaseLogPath() : m_actualLogPath;
		}

		void Logger::WriteFile(const LogItem& item) {
#ifdef _WIN32
			std::lock_guard<std::mutex> lk(m_cfgMutex);
			
			OpenLogFileIfNeeded();
			if (m_file == nullptr || m_file == INVALID_HANDLE_VALUE) {
				return;
			}

			const bool jsonLinesCfg = m_cfg.jsonLines;
			std::wstring line = jsonLinesCfg ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
			line += L"\r\n";

			// Integer overflow check BEFORE calculation
			constexpr size_t MAX_FILE_WRITE = std::numeric_limits<DWORD>::max() / sizeof(wchar_t);
			if (line.size() > MAX_FILE_WRITE) {
				return;
			}

			const BYTE* data = reinterpret_cast<const BYTE*>(line.c_str());
			const DWORD bytesToWrite = static_cast<DWORD>(line.size() * sizeof(wchar_t));

			RotateIfNeeded(bytesToWrite);

			DWORD written = 0;
			if (!::WriteFile(m_file, data, bytesToWrite, &written, nullptr)) {
				// Write failed
				return;
			}
			m_currentSize += written;

			// Flush for high severity messages
			const LogLevel flushLevelCfg = m_cfg.flushLevel;
			if (static_cast<int>(item.level) >= static_cast<int>(flushLevelCfg)) {
				FlushFileBuffers(m_file);
			}
#endif
		}

		// ============================================================================
		// Windows Event Log
		// ============================================================================

		void Logger::OpenEventLog() {
#ifdef _WIN32
			if (m_eventSrc != nullptr) {
				return;
			}
			
			std::wstring eventLogSourceCfg;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				eventLogSourceCfg = m_cfg.eventLogSource;
			}
			m_eventSrc = RegisterEventSourceW(nullptr, eventLogSourceCfg.c_str());
#endif
		}

		void Logger::CloseEventLog() {
#ifdef _WIN32
			if (m_eventSrc != nullptr) {
				DeregisterEventSource(m_eventSrc);
				m_eventSrc = nullptr;
			}
#endif
		}

		void Logger::WriteEventLog(const LogItem& item) {
#ifdef _WIN32
			// Get configuration
			bool toEventLogCfg = false;
			bool jsonLinesCfg = false;
			{
				std::lock_guard<std::mutex> lk(m_cfgMutex);
				toEventLogCfg = m_cfg.toEventLog;
				jsonLinesCfg = m_cfg.jsonLines;
			}

			if (!toEventLogCfg) {
				return;
			}
			
			if (m_eventSrc == nullptr) {
				OpenEventLog();
			}
			if (m_eventSrc == nullptr) {
				return;
			}

			// Map log level to Windows event type
			WORD type = EVENTLOG_SUCCESS;
			switch (item.level) {
			case LogLevel::Warn:  type = EVENTLOG_WARNING_TYPE; break;
			case LogLevel::Error: type = EVENTLOG_ERROR_TYPE;   break;
			case LogLevel::Fatal: type = EVENTLOG_ERROR_TYPE;   break;
			default:              type = EVENTLOG_INFORMATION_TYPE; break;
			}

			const std::wstring payload = jsonLinesCfg ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
			const wchar_t* strings[1] = { payload.c_str() };
			::ReportEventW(m_eventSrc, type, 0, 0, nullptr, 1, 0, strings, nullptr);
#endif
		}

		// ============================================================================
		// Scope Timing (RAII)
		// ============================================================================

		Logger::Scope::Scope(const wchar_t* category, const wchar_t* file, int line,
			const wchar_t* function, const wchar_t* messageOnEnter, LogLevel level)
			: m_category((category != nullptr) ? category : L"")
			, m_file((file != nullptr) ? file : L"")
			, m_line(line)
			, m_function((function != nullptr) ? function : L"")
			, m_level(level)
		{
#ifdef _WIN32
			QueryPerformanceFrequency(&m_freq);
			QueryPerformanceCounter(&m_start);
#endif
			Logger::Instance().LogMessage(m_level, m_category, messageOnEnter, m_file, m_line, m_function, 0);
		}

		Logger::Scope::~Scope() {
#ifdef _WIN32
			LARGE_INTEGER end{};
			QueryPerformanceCounter(&end);

			// Guard against division by zero
			if (m_freq.QuadPart == 0) {
				Logger::Instance().LogMessage(m_level, m_category, L"Leave", m_file, m_line, m_function, 0);
				return;
			}

			// Calculate elapsed time in milliseconds
			const double ms = static_cast<double>(end.QuadPart - m_start.QuadPart) * 1000.0 / 
							  static_cast<double>(m_freq.QuadPart);
			
			wchar_t buf[64];
			_snwprintf_s(buf, _TRUNCATE, L"Leave (%.3f ms)", ms);
			Logger::Instance().LogMessage(m_level, m_category, buf, m_file, m_line, m_function, 0);
#endif
		}

	} // namespace Utils
} // namespace ShadowStrike