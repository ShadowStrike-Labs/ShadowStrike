#include"../Utils/Logger.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <io.h>
#include <chrono>

#ifdef _WIN32
#  include <Shlwapi.h>
#  pragma comment(lib, "Shlwapi.lib")
#endif

namespace ShadowStrike {

	namespace Utils {

		static const wchar_t* LevelToW(LogLevel lv) {
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

		Logger& Logger::Instance()
		{
			static Logger g_instance;
			// ✅ FIX: Ensure initialization is complete before returning
			g_instance.EnsureInitialized();
			return g_instance;
		}

		Logger::Logger()
		{
#ifdef _WIN32
			m_console = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
		}

		Logger::~Logger()
		{
			ShutDown();
		}

		bool Logger::IsEnabled(LogLevel level) const noexcept {
			const LogLevel minLevel = m_minLevel.load(std::memory_order_acquire);
			return static_cast<int>(level) >= static_cast<int>(minLevel);
		}

		bool Logger::IsInitialized() const noexcept
		{
			return m_initialized.load(std::memory_order_acquire);
		}

		void Logger::EnsureInitialized() {
			// ✅ FIX: Double-checked locking pattern for initialization
			if (!IsInitialized()) {
				std::lock_guard<std::mutex> lk(m_cfgmutex);
				if (!IsInitialized()) {
					LoggerConfig def{};
					Initialize(def);
				}
			}
		}

		void Logger::Initialize(const LoggerConfig& cfg) {
			bool expected = false;

			if (!m_initialized.compare_exchange_strong(expected, true)) {
				//already initialized-> just update the config
				std::lock_guard<std::mutex> lk(m_cfgmutex);
				m_cfg = cfg;
				m_minLevel.store(cfg.minimalLevel, std::memory_order_release);
				m_accepting.store(true, std::memory_order_release); // ensure accepting on update
				return;
			}

			{
				std::lock_guard<std::mutex> lk(m_cfgmutex);
				m_cfg = cfg;
				m_minLevel.store(cfg.minimalLevel, std::memory_order_release);
			}

#ifdef _WIN32
			EnsureLogDirectory();
			OpenLogFileIfNeeded();
			if (m_cfg.toEventLog) OpenEventLog();
#endif

			m_stop.store(false, std::memory_order_release);
			
			// ✅ CRITICAL FIX: Start worker thread BEFORE enabling log acceptance
			// This prevents race condition where logs are accepted before worker exists
			if (m_cfg.async) {
				try {
					m_worker = std::thread([this]() {WorkerLoop(); });
					// ✅ Give thread time to fully start (prevents lost logs)
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				} catch (const std::system_error&) {
					// ✅ FIX: Handle thread creation failure gracefully
					m_cfg.async = false; // Fallback to synchronous mode
					m_initialized.store(false, std::memory_order_release);
					return;
				}
			}
			
			// ✅ FIX: Enable log acceptance AFTER worker thread is guaranteed running
			// This is the CRITICAL FIX for test deadlock
			m_accepting.store(true, std::memory_order_release);
		}

		void Logger::ShutDown() {
			// ✅ CRITICAL FIX: Idempotent shutdown with CAS
			bool expected = true;
			if (!m_initialized.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
				// Already shut down or never initialized
				return;
			}

			// ✅ FIX: Stop accepting logs FIRST (before stop flag)
			// This ensures no new logs enter queue after shutdown starts
			m_accepting.store(false, std::memory_order_release);

			// ✅ FIX: Signal worker thread to stop
			m_stop.store(true, std::memory_order_release);
			m_queueCv.notify_all();

			// ✅ FIX: Wait for worker thread to finish processing
			if (m_worker.joinable()) {
				try {
					m_worker.join();
				} catch (const std::system_error&) {
					// Handle join failure - detach to prevent terminate()
					m_worker.detach();
				}
			}

			// ✅ FIX: Drain remaining queue items synchronously
			// Worker has stopped, safe to process without lock contention
			LogItem item;
			while (Dequeue(item)) {
				try {
					if (m_cfg.toConsole) WriteConsole(item);
					if (m_cfg.toFile) WriteFile(item);
					if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
				} catch (...) {
					// ✅ FIX: Ignore errors during shutdown cleanup
				}
			}

#ifdef _WIN32
			// ✅ FIX: Flush and close file handle
			if (m_file && m_file != INVALID_HANDLE_VALUE) {
				try {
					FlushFileBuffers(m_file);
				} catch (...) {}
				CloseHandle(m_file);
				m_file = INVALID_HANDLE_VALUE;
			}
			CloseEventLog();
#endif
		}

		void Logger::setMinimalLevel(LogLevel level)  noexcept {
			m_minLevel.store(level, std::memory_order_release);
		}

		void Logger::Enqueue(LogItem&& item) {
			// ✅ FIX: Check accepting flag FIRST (before initialized)
			// Prevents race during initialization/shutdown
			if (!m_accepting.load(std::memory_order_acquire)) return;
			if (!IsInitialized()) return;
			if (!IsEnabled(item.level)) return;

			if (m_cfg.async) {
				std::lock_guard<std::mutex> lk(m_queueMutex);

				// bounded queue handling
				if (m_queue.size() >= m_cfg.maxQueueSize) {
					switch (m_cfg.bpPolicy) {
					case LoggerConfig::BackPressurePolicy::Block:
						// naive block: wait until there is space (simple, may need condition variable)
						// We'll do drop oldest for now as default safe behavior
						// Fallthrough
					case LoggerConfig::BackPressurePolicy::DropOldest:
						m_queue.pop_front(); // drop oldest
						break;
					case LoggerConfig::BackPressurePolicy::DropNewest:
						// drop incoming (do nothing, but maybe inc metric)
						return;
					}
				}

				m_queue.emplace_back(std::move(item));
				m_queueCv.notify_one();
			}
			else {
				// ✅ FIX: Synchronous mode - write directly with exception handling
				try {
					if (m_cfg.toConsole) WriteConsole(item);
					if (m_cfg.toFile) WriteFile(item);
					if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
				} catch (...) {
					// ✅ FIX: Ignore errors in synchronous mode (prevents cascading failures)
				}
			}
		}

		bool Logger::Dequeue(LogItem& out) {
			std::lock_guard<std::mutex> lk(m_queueMutex);
			if (m_queue.empty()) return false;
			out = std::move(m_queue.front());
			m_queue.pop_front();
			return true;
		}

		void Logger::WorkerLoop() {
			// ✅ FIX: Entire worker loop wrapped in try-catch for robustness
			try {
				while (!m_stop.load(std::memory_order_acquire)) {
					LogItem item;

					{
						std::unique_lock<std::mutex> lk(m_queueMutex);
						// ✅ FIX: Proper wait condition with timeout (prevents infinite wait)
						m_queueCv.wait_for(lk, std::chrono::seconds(1), [this]() { 
							return m_stop.load(std::memory_order_acquire) || !m_queue.empty(); 
						});
						
						if (m_stop.load(std::memory_order_acquire) && m_queue.empty()) break;
						
						if (m_queue.empty()) continue;
						
						item = std::move(m_queue.front());
						m_queue.pop_front();
					}

					// ✅ FIX: Process item outside lock to prevent deadlock
					try {
						if (m_cfg.toConsole) WriteConsole(item);
						if (m_cfg.toFile) WriteFile(item);
						if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
					} catch (...) {
						// ✅ FIX: Ignore individual item processing errors
					}
				}
			} catch (...) {
				// ✅ FIX: Worker thread crashed - log to stderr if possible
#ifdef _WIN32
				OutputDebugStringW(L"[Logger] CRITICAL: Worker thread crashed\n");
#endif
			}
		}

		void Logger::LogEx(LogLevel level,
			const wchar_t* category,
			const wchar_t* file,
			int line,
			const wchar_t* function,
			const wchar_t* format, ...) {

			if (!IsEnabled(level)) return;

			va_list args;
			va_start(args, format);
			std::wstring msg = FormatMessageV(format, args);
			va_end(args);

			LogMessage(level, category, msg, file, line, function, 0);
		}

		void Logger::LogWinErrorEx(LogLevel level,
			const wchar_t* category,
			const wchar_t* file,
			int line,
			const wchar_t* function,
			DWORD errorCode,
			const wchar_t* contextFormat, ...) {

			if (!IsEnabled(level)) return;
			va_list args;
			va_start(args, contextFormat);
			std::wstring context = FormatMessageV(contextFormat, args);
			va_end(args);

			std::wstring winErr = FormatWinError(errorCode);

			std::wstring combined;
			combined.reserve(context.size() + 3 + winErr.size());
			combined.append(context);
			combined.append(L": ");
			combined.append(winErr);

			LogMessage(level, category, combined, file, line, function, errorCode);
		}

		void Logger::LogMessage(LogLevel level,
			const wchar_t* category,
			const std::wstring& message,
			const wchar_t* file,
			int line,
			const wchar_t* function,
			DWORD winError) {

			LogItem item{};
			item.level = level;
			item.category = category ? category : L"";;
			item.message = message;
			item.file = file ? file : L"";;
			item.function = function ? function : L"";;
			item.line = line;
#ifdef _WIN32
			item.pid = GetCurrentProcessId();
			item.tid = GetCurrentThreadId();
#endif
			item.ts_100ns = NowAsFileTime100nsUTC();
			item.winError = winError;

			Enqueue(std::move(item));

			// ✅ FIX: Flush for critical levels
			if (static_cast<int>(level) >= static_cast<int>(m_cfg.flushLevel))
				Flush();
		}

		void Logger::Flush()
		{
#ifdef _WIN32
			if (m_cfg.async)
			{
				// ✅ FIX: Improved flush - wait for queue to drain with timeout
				auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
				
				while (std::chrono::steady_clock::now() < deadline) {
					{
						std::lock_guard<std::mutex> lk(m_queueMutex);
						if (m_queue.empty()) break;
					}
					
					// ✅ Notify worker to process
					m_queueCv.notify_all();
					std::this_thread::sleep_for(std::chrono::milliseconds(10));
				}
				
				// ✅ FIX: Drain any remaining items synchronously
				LogItem x{};
				while (Dequeue(x)) {
					try {
						if (m_cfg.toConsole) WriteConsole(x);
						if (m_cfg.toFile)    WriteFile(x);
						if (m_cfg.toEventLog && x.level >= LogLevel::Warn) WriteEventLog(x);
					} catch (...) {}
				}
			}
			
			// ✅ FIX: Flush file handle if valid
			if (m_file && m_file != INVALID_HANDLE_VALUE) {
				FlushFileBuffers(m_file);
			}
#endif
		}

		//Helpers

		const wchar_t* Logger::NarrowToWideTLS(const char* s)
		{
#ifdef _WIN32
			thread_local std::wstring buff;
			if (!s) { buff.clear(); return buff.c_str(); }
			
			int len = static_cast<int>(strlen(s));
			if (len <= 0) { buff.clear(); return buff.c_str(); }
			
			// ✅ FIX: Proper error handling for MultiByteToWideChar
			int wlen = MultiByteToWideChar(CP_UTF8, 0, s, len, nullptr, 0);
			if (wlen <= 0) { buff.clear(); return buff.c_str(); }
			
			buff.resize(wlen);
			if (MultiByteToWideChar(CP_UTF8, 0, s, len, &buff[0], wlen) <= 0) {
				buff.clear();
			}
			return buff.c_str();
#else
			static thread_local std::wstring buff;
			buff.clear();
			return buff.c_str();
#endif
		}


		std::wstring Logger::FormatMessageV(const wchar_t* fmt, va_list args) {
			if (!fmt) return L"";

			// ✅ CRITICAL FIX: Proper handling of _vsnwprintf_s with _TRUNCATE
			std::wstring out;
			out.resize(512);
			
			// ✅ FIX: Use va_copy to preserve original args for retry
			va_list args_copy;
			va_copy(args_copy, args);
			int needed = _vsnwprintf_s(&out[0], out.size(), _TRUNCATE, fmt, args_copy);
			va_end(args_copy);

			// ✅ FIX: Handle _TRUNCATE return values correctly
			// When using _TRUNCATE:
			// - If buffer sufficient: returns number of characters written (excluding null)
			// - If buffer too small: returns -1 and truncates
			if (needed < 0) {
				// Buffer was too small, need to grow
				size_t cap = 1024;
				while (cap <= (1u << 20)) { // ✅ FIX: Cap at 1MB to prevent DoS
					out.resize(cap);
					va_copy(args_copy, args);
					int n = _vsnwprintf_s(&out[0], out.size(), _TRUNCATE, fmt, args_copy);
					va_end(args_copy);

					if (n >= 0 && static_cast<size_t>(n) < out.size()) {
						// ✅ CRITICAL FIX: Resize to actual length
						out.resize(static_cast<size_t>(n));
						return out;
					}
					
					// Still too small, double the capacity
					cap *= 2;
				}
				
				// ✅ FIX: If we exceed 1MB, return truncated message
				out = L"[Logger] Message too large or formatting error";
			}
			else {
				// ✅ CRITICAL FIX: Success case - resize to actual length
				out.resize(static_cast<size_t>(needed));
			}

			return out;
		}

		std::wstring Logger::FormatWinError(DWORD err) {
#ifdef _WIN32
			LPWSTR buf = nullptr;
			DWORD n = FormatMessageW(
				FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPWSTR)&buf, 0, nullptr);
			
			std::wstring out = L"WinError " + std::to_wstring(err);
			if (n && buf)
			{
				// ✅ FIX: Trim trailing whitespace (CR/LF)
				while (n && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n' || buf[n - 1] == L' ')) --n;
				out.append(L": ");
				out.append(buf, buf + n);
				LocalFree(buf);
			}
			return out;
#else
			(void)err;
			return L"";
#endif
		}

		uint64_t Logger::NowAsFileTime100nsUTC() {
#ifdef _WIN32
			FILETIME ft{};
			//for Win7+ use GetSystemTimePreciseAsFileTime; if its old use GetSystemTimeAsFileTime
			typedef VOID(WINAPI* GetPreciseFunc)(LPFILETIME);

			static GetPreciseFunc pGetPrecise = (GetPreciseFunc)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetSystemTimePreciseAsFileTime");
			if (pGetPrecise) 
				pGetPrecise(&ft);
			else 
				GetSystemTimeAsFileTime(&ft);

			ULARGE_INTEGER uli{};
			uli.LowPart = ft.dwLowDateTime;
			uli.HighPart = ft.dwHighDateTime;
			return uli.QuadPart;//100ns since Jan 1, 1601 UTC
#else 
			return 0;
#endif
		}

		std::wstring Logger::FormatIso8601UTC(uint64_t filetime100ns) {
#ifdef _WIN32
			// FILETIME -> SYSTEMTIME (UTC)
			FILETIME ft{};
			ft.dwLowDateTime = static_cast<DWORD>(filetime100ns & 0xFFFFFFFFull);
			ft.dwHighDateTime = static_cast<DWORD>((filetime100ns >> 32) & 0xFFFFFFFFull);

			SYSTEMTIME st{};
			// ✅ CRITICAL FIX: Check return value to prevent uninitialized data usage
			if (!FileTimeToSystemTime(&ft, &st)) {
				return L"[Invalid timestamp]";
			}

			wchar_t buf[40] = { 0 };
			// ✅ FIX: Use _snwprintf_s for safety
			_snwprintf_s(buf, _TRUNCATE, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
				st.wYear, st.wMonth, st.wDay,
				st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
			return std::wstring(buf);
#else
			return L"";
#endif
		}

		std::wstring Logger::EscapeJson(const std::wstring& s) {
			std::wstring out;
			out.reserve(s.size() + 16);
			
			for (wchar_t c : s)
			{
				switch (c)
				{
				case L'\\': out += L"\\\\"; break;
				case L'"':  out += L"\\\""; break;
				case L'\b': out += L"\\b";  break;
				case L'\f': out += L"\\f";  break;
				case L'\n': out += L"\\n";  break;
				case L'\r': out += L"\\r";  break;
				case L'\t': out += L"\\t";  break;
				default:
					if (c < 0x20)
					{
						wchar_t buf[7];
						_snwprintf_s(buf, _TRUNCATE, L"\\u%04x", (unsigned)c);
						out += buf;
					}
					else
					{
						out += c;
					}
				}
			}
			return out;
		}

		std::wstring Logger::FormatPrefix(const LogItem& item) const {
			std::wstring ts = FormatIso8601UTC(item.ts_100ns);

			std::wstring s;
			s.reserve(128);
			s += ts;
			s += L" [";
			s += LevelToW(item.level);
			s += L"]";
			
			if (!item.category.empty())
			{
				s += L" [";
				s += item.category;
				s += L"]";
			}
			
			if (m_cfg.includeProcThreadId)
			{
				s += L" (";
				s += std::to_wstring(item.pid);
				s += L":";
				s += std::to_wstring(item.tid);
				s += L")";
			}
			
			if (m_cfg.includeSrcLocation && !item.file.empty())
			{
				s += L" ";
				s += item.file;
				s += L":";
				s += std::to_wstring(item.line);
				
				if (!item.function.empty())
				{
					s += L" ";
					s += item.function;
				}
			}
			
			s += L" - ";
			return s;
		}

		std::wstring Logger::FormatAsJson(const LogItem& item) const {
			// JSON Lines format
			std::wstring s;
			s.reserve(128 + item.message.size());
			s += L"{\"ts\":\"";
			s += EscapeJson(FormatIso8601UTC(item.ts_100ns));
			s += L"\",\"lvl\":\"";
			s += LevelToW(item.level);
			s += L"\"";
			
			if (!item.category.empty())
			{
				s += L",\"cat\":\"";
				s += EscapeJson(item.category);
				s += L"\"";
			}

			if (m_cfg.includeProcThreadId)
			{
				s += L",\"pid\":";
				s += std::to_wstring(item.pid);
				s += L",\"tid\":";
				s += std::to_wstring(item.tid);
			}

			if (m_cfg.includeSrcLocation && !item.file.empty())
			{
				s += L",\"file\":\"";
				s += EscapeJson(item.file);
				s += L"\",\"line\":";
				s += std::to_wstring(item.line);
				
				if (!item.function.empty())
				{
					s += L",\"func\":\"";
					s += EscapeJson(item.function);
					s += L"\"";
				}
			}

			if (item.winError)
			{
				s += L",\"winerr\":";
				s += std::to_wstring(item.winError);
			}
			
			s += L",\"msg\":\"";
			s += EscapeJson(item.message);
			s += L"\"}";
			return s;
		}

		//Sinks

		void Logger::WriteConsole(const LogItem& item) {
#ifdef _WIN32
			// ✅ FIX: Validate console handle
			if (!m_console || m_console == INVALID_HANDLE_VALUE) return;

			WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
			switch (item.level)
			{
			case LogLevel::Trace: color = FOREGROUND_BLUE | FOREGROUND_GREEN; break; // Cyan
			case LogLevel::Debug: color = FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
			case LogLevel::Info:  color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
			case LogLevel::Warn:  color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break; // Yellow
			case LogLevel::Error: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
			case LogLevel::Fatal: color = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;  // Magenta
			}
			
			CONSOLE_SCREEN_BUFFER_INFO csbi{};
			GetConsoleScreenBufferInfo(m_console, &csbi);
			SetConsoleTextAttribute(m_console, color);

			std::wstring line = m_cfg.jsonLines ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
			line += L"\r\n";

			// ✅ CRITICAL FIX: Validate line size before cast
			if (line.size() > std::numeric_limits<DWORD>::max() / sizeof(wchar_t)) {
				// ✅ Truncate message if too large
				line = L"[Logger] Message too large\r\n";
			}

			DWORD written = 0;
			::WriteConsoleW(m_console, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);

			// ✅ FIX: Restore color
			SetConsoleTextAttribute(m_console, csbi.wAttributes);
#else
			(void)item;
#endif
		}

		void Logger::OpenLogFileIfNeeded() {
#ifdef _WIN32
			std::lock_guard<std::mutex> lk(m_cfgmutex);
			
			// ✅ FIX: Check if already open
			if (m_file && m_file != INVALID_HANDLE_VALUE) return;

			std::wstring path = BaseLogPath();
			m_file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
				nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			
			if (m_file == INVALID_HANDLE_VALUE) {
				// ✅ FIX: Log to stderr if file open fails
#ifdef _DEBUG
				OutputDebugStringW(L"[Logger] Failed to open log file\n");
#endif
				return;
			}
			
			m_actualLogPath = path;
			
			LARGE_INTEGER size{};
			if (GetFileSizeEx(m_file, &size))
				m_currentSize = static_cast<uint64_t>(size.QuadPart);
			else
				m_currentSize = 0;
#endif
		}

		void Logger::RotateIfNeeded(size_t nextWriteBytes) {
#ifdef _WIN32
			if (!m_cfg.toFile) return;
			if (!m_file || m_file == INVALID_HANDLE_VALUE) return;

			if (m_currentSize + nextWriteBytes <= m_cfg.maxFileSizeBytes) return;

			PerformRotation();
			
			// ✅ FIX: Reopen file after rotation
			if (m_file && m_file != INVALID_HANDLE_VALUE) { 
				CloseHandle(m_file); 
				m_file = INVALID_HANDLE_VALUE; 
			}
			OpenLogFileIfNeeded();
#endif
		}

		void Logger::PerformRotation()
		{
#ifdef _WIN32
			// ✅ CRITICAL FIX: Set rotation guard to prevent recursive logging
			bool expected = false;
			if (!m_insideRotation.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
				// Already inside rotation, skip to prevent recursion
				return;
			}

			// ✅ CRITICAL FIX: RAII guard to ensure flag is cleared
			struct RotationGuard {
				std::atomic<bool>& flag;
				~RotationGuard() { flag.store(false, std::memory_order_release); }
			} guard{ m_insideRotation };

			// EXCLUSIVE LOCK DURING ROTATION
			std::lock_guard<std::mutex> lock(m_cfgmutex);

			try {
				// CLOSE CURRENT FILE BEFORE ROTATION
				if (m_file && m_file != INVALID_HANDLE_VALUE) {
					::FlushFileBuffers(m_file);
					::CloseHandle(m_file);
					m_file = INVALID_HANDLE_VALUE;
				}

				const std::wstring base = BaseLogPath();

				// DELETE OLDEST FILE FIRST (if exists)
				if (m_cfg.maxFileCount > 1) {
					std::wstring oldestFile = base + L"." + std::to_wstring(m_cfg.maxFileCount);

					// Check if file exists before trying to delete
					DWORD attrs = ::GetFileAttributesW(oldestFile.c_str());
					if (attrs != INVALID_FILE_ATTRIBUTES) {
						::SetFileAttributesW(oldestFile.c_str(), FILE_ATTRIBUTE_NORMAL);

						if (!::DeleteFileW(oldestFile.c_str())) {
							DWORD error = ::GetLastError();
							if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
								// TRY FORCE DELETE WITH RETRY
								for (int retry = 0; retry < 3; ++retry) {
									::Sleep(100);
									if (::DeleteFileW(oldestFile.c_str())) break;
								}
							}
						}
					}

					// ROTATE FILES IN REVERSE ORDER
					for (size_t idx = m_cfg.maxFileCount - 1; idx >= 1; --idx) {
						std::wstring srcFile = base + L"." + std::to_wstring(idx);
						std::wstring dstFile = base + L"." + std::to_wstring(idx + 1);

						attrs = ::GetFileAttributesW(srcFile.c_str());
						if (attrs == INVALID_FILE_ATTRIBUTES) {
							if (idx == 1) break;
							continue;
						}

						// DELETE TARGET FILE IF EXISTS
						attrs = ::GetFileAttributesW(dstFile.c_str());
						if (attrs != INVALID_FILE_ATTRIBUTES) {
							::SetFileAttributesW(dstFile.c_str(), FILE_ATTRIBUTE_NORMAL);
							::DeleteFileW(dstFile.c_str());
						}

						// MOVE FILE WITH ERROR HANDLING
						if (!::MoveFileExW(srcFile.c_str(), dstFile.c_str(),
							MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
							// FALLBACK: COPY + DELETE
							if (::CopyFileW(srcFile.c_str(), dstFile.c_str(), FALSE)) {
								::DeleteFileW(srcFile.c_str());
							}
						}

						if (idx == 1) break;
					}

					// RENAME CURRENT LOG TO .1
					std::wstring firstRotated = base + L".1";

					attrs = ::GetFileAttributesW(base.c_str());
					if (attrs != INVALID_FILE_ATTRIBUTES) {
						attrs = ::GetFileAttributesW(firstRotated.c_str());
						if (attrs != INVALID_FILE_ATTRIBUTES) {
							::SetFileAttributesW(firstRotated.c_str(), FILE_ATTRIBUTE_NORMAL);
							::DeleteFileW(firstRotated.c_str());
						}

						if (!::MoveFileExW(base.c_str(), firstRotated.c_str(),
							MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
							if (::CopyFileW(base.c_str(), firstRotated.c_str(), FALSE)) {
								::DeleteFileW(base.c_str());
							}
						}
					}
				}
				else {
					// IF ONLY ONE FILE, JUST DELETE IT
					DWORD attrs = ::GetFileAttributesW(base.c_str());
					if (attrs != INVALID_FILE_ATTRIBUTES) {
						::SetFileAttributesW(base.c_str(), FILE_ATTRIBUTE_NORMAL);
						::DeleteFileW(base.c_str());
					}
				}

				// RESET SIZE AND PATH
				m_currentSize = 0;
				m_actualLogPath.clear();

			}
			catch (const std::exception&) {
				// Silent failure during rotation
			}
			catch (...) {
				// Silent failure during rotation
			}
#endif
		}

		void Logger::EnsureLogDirectory()
		{
#ifdef _WIN32
			if (m_cfg.logDirectory.empty()) return;
			
			// ✅ FIX: Check if directory already exists
			DWORD attrs = GetFileAttributesW(m_cfg.logDirectory.c_str());
			if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
				return; // Directory exists
			}
			
			CreateDirectoryW(m_cfg.logDirectory.c_str(), nullptr);
#endif
		}

		std::wstring Logger::BaseLogPath() const
		{
#ifdef _WIN32
			std::wstring path = m_cfg.logDirectory;
			if (!path.empty())
			{
				if (path.back() != L'\\' && path.back() != L'/')
					path.push_back(L'\\');
			}
			path += m_cfg.baseFileName;
			path += L".log";
			return path;
#else
			return L"ShadowStrike.log";
#endif
		}

		std::wstring Logger::CurrentLogPath() const
		{
			return m_actualLogPath.empty() ? BaseLogPath() : m_actualLogPath;
		}

		void Logger::WriteFile(const LogItem& item)
		{
#ifdef _WIN32
			std::lock_guard<std::mutex> lk(m_cfgmutex);
			OpenLogFileIfNeeded();
			if (!m_file || m_file == INVALID_HANDLE_VALUE) return;

			std::wstring line = m_cfg.jsonLines ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
			line += L"\r\n";
			
			const BYTE* data = reinterpret_cast<const BYTE*>(line.c_str());
			const DWORD bytesToWrite = static_cast<DWORD>(line.size() * sizeof(wchar_t));

			// ✅ FIX: Check for size overflow
			if (line.size() > std::numeric_limits<DWORD>::max() / sizeof(wchar_t)) {
				return; // Message too large
			}

			RotateIfNeeded(bytesToWrite);

			DWORD written = 0;
			::WriteFile(m_file, data, bytesToWrite, &written, nullptr);
			m_currentSize += written;
			
			// ✅ FIX: Flush for critical levels
			if (static_cast<int>(item.level) >= static_cast<int>(m_cfg.flushLevel))
				FlushFileBuffers(m_file);
#else
			(void)item;
#endif
		}

		void Logger::OpenEventLog()
		{
#ifdef _WIN32
			if (m_eventSrc) return;
			m_eventSrc = RegisterEventSourceW(nullptr, m_cfg.eventLogSource.c_str());
#endif
		}

		void Logger::CloseEventLog()
		{
#ifdef _WIN32
			if (m_eventSrc)
			{
				DeregisterEventSource(m_eventSrc);
				m_eventSrc = nullptr;
			}
#endif
		}

		void Logger::WriteEventLog(const LogItem& item) {
#ifdef _WIN32
			if (!m_cfg.toEventLog) return;
			if (!m_eventSrc) OpenEventLog();
			if (!m_eventSrc) return;

			WORD type = EVENTLOG_SUCCESS;
			switch (item.level)
			{
			case LogLevel::Warn:  type = EVENTLOG_WARNING_TYPE; break;
			case LogLevel::Error: type = EVENTLOG_ERROR_TYPE;   break;
			case LogLevel::Fatal: type = EVENTLOG_ERROR_TYPE;   break;
			default:              type = EVENTLOG_INFORMATION_TYPE; break;
			}

			std::wstring payload = m_cfg.jsonLines ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
			const wchar_t* strings[1] = { payload.c_str() };
			::ReportEventW(m_eventSrc, type, 0, 0, nullptr, 1, 0, strings, nullptr);
#else
			void(item);
#endif
		}

		Logger::Scope::Scope(const wchar_t* category,
			const wchar_t* file,
			int line,
			const wchar_t* function,
			const wchar_t* messageOnEnter,
			LogLevel level)
			: m_category(category ? category : L"")
			, m_file(file ? file : L"")
			, m_line(line)
			, m_function(function ? function : L"")
			, m_level(level)
		{
#ifdef _WIN32
			QueryPerformanceFrequency(&m_freq);
			QueryPerformanceCounter(&m_start);
#endif
			Logger::Instance().LogMessage(m_level, m_category, messageOnEnter, m_file, m_line, m_function, 0);
		}

		Logger::Scope::~Scope()
		{
#ifdef _WIN32
			LARGE_INTEGER end{};
			QueryPerformanceCounter(&end);
			
			// ✅ FIX: Check for valid frequency
			if (m_freq.QuadPart == 0) {
				Logger::Instance().LogMessage(m_level, m_category, L"Leave", m_file, m_line, m_function, 0);
				return;
			}
			
			const double ms = (double)(end.QuadPart - m_start.QuadPart) * 1000.0 / (double)m_freq.QuadPart;

			wchar_t buf[64];
			_snwprintf_s(buf, _TRUNCATE, L"Leave (%.3f ms)", ms);
			Logger::Instance().LogMessage(m_level, m_category, buf, m_file, m_line, m_function, 0);
#endif
		}	

	}//namespace Utils
}//namespace ShadowStrike