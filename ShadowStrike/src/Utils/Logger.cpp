
#include"../Utils/Logger.hpp"


#include <algorithm>
#include <cstdio>
#include <ctime>
#include <io.h>

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

			if (!IsInitialized()) {
				LoggerConfig def{};
				Initialize(def);
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
			m_accepting.store(true, std::memory_order_release); // start accepting logs

			if (m_cfg.async) {
				m_worker = std::thread([this]() {WorkerLoop(); });
			}
		}

		void Logger::ShutDown() {

			if (!IsInitialized()) return;

			m_accepting.store(false, std::memory_order_release);

			m_stop.store(true, std::memory_order_release);
			m_queueCv.notify_all();

			if (m_worker.joinable()) {
				m_worker.join();
			}
			LogItem item;

			while (Dequeue(item)) {
				if (m_cfg.toConsole) WriteConsole(item);
				if (m_cfg.toFile) WriteFile(item);
				if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
			}

#ifdef _WIN32
			if (m_file && m_file != INVALID_HANDLE_VALUE) {
				FlushFileBuffers(m_file);
				CloseHandle(m_file);
				m_file = INVALID_HANDLE_VALUE;
			}
			CloseEventLog();
#endif
			m_initialized.store(false, std::memory_order_release);
		}

		void Logger::setMinimalLevel(LogLevel level)  noexcept {
			m_minLevel.store(level, std::memory_order_release);
		}

		void Logger::Enqueue(LogItem&& item) {
			if (!IsInitialized()) return;               // guard
			if (!m_accepting.load(std::memory_order_acquire)) return; // no longer accepting
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
				if (m_cfg.toConsole) ShadowStrike::Utils::Logger::WriteConsole(item);
				if (m_cfg.toFile) WriteFile(item);
				if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
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

			while (!m_stop.load(std::memory_order_acquire)) {
				LogItem item;

				{
					std::unique_lock<std::mutex> lk(m_queueMutex);
					m_queueCv.wait(lk, [this]() { return m_stop.load(std::memory_order_acquire) || !m_queue.empty(); });
					if (m_stop.load(std::memory_order_acquire) && m_queue.empty()) break;
					item = std::move(m_queue.front());
					m_queue.pop_front();
				}

				if (m_cfg.toConsole) ShadowStrike::Utils::Logger::WriteConsole(item);
				if (m_cfg.toFile) WriteFile(item);
				if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
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
			item.category = category ? category : L"";
			item.message = message;
			item.file = file ? file : L"";
			item.function = function ? function : L"";
			item.line = line;
#ifdef _WIN32
			item.pid = GetCurrentProcessId();
			item.tid = GetCurrentThreadId();
#endif
			item.ts_100ns = NowAsFileTime100nsUTC();
			item.winError = winError;

			Enqueue(std::move(item));

			if (static_cast<int>(level) >= static_cast<int>(m_cfg.flushLevel))
				Flush();


		}

		void Logger::Flush()
		{
#ifdef _WIN32

			if (m_cfg.async)
			{
				//Wake up the worker and wait until the queue is empty
				for (;;)
				{
					LogItem x{};
					if (!Dequeue(x)) break;
					if (m_cfg.toConsole) WriteConsole(x);
					if (m_cfg.toFile)    WriteFile(x);
					if (m_cfg.toEventLog && x.level >= LogLevel::Warn) WriteEventLog(x);
				}
			}
			if (m_file && m_file != INVALID_HANDLE_VALUE)
				FlushFileBuffers(m_file);
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
			int wlen = MultiByteToWideChar(CP_ACP, 0, s, len, nullptr, 0);
			buff.resize(wlen);
			if (wlen > 0)
				MultiByteToWideChar(CP_ACP, 0, s, len, &buff[0], wlen);
			return buff.c_str();
#else
			static thread_local std::wstring buff;
			buff.clear();
			return buff.c_str();
#endif
		}


		std::wstring Logger::FormatMessageV(const wchar_t* fmt, va_list args) {

			if (!fmt) return L"";

			//first try 512 wchar
			std::wstring out;
			out.resize(512);
			va_list args_copy;
			va_copy(args_copy, args);
		     int needed = _vsnwprintf_s(&out[0], out.size(), _TRUNCATE, fmt, args_copy);
			va_end(args_copy);

			if (needed < 0) {

				//if we cannot calculate the length, increase it  section by section
				size_t cap = 1024;
				while (true) {
					out.resize(cap);
					va_copy(args_copy, args);
					int n = _vsnwprintf_s(&out[0], out.size(), _TRUNCATE, fmt, args_copy);
					va_end(args_copy);

					if (n >= 0 && static_cast<size_t>(n) < out.size()) {
						out.resize(static_cast<size_t>(n));
						break;
					}
					cap *= 2;
					if (cap > (1u << 20)) {//1M

						out = L"[Logger] formatting error or message too large";
						break;
					}
				}
				return out;
			}
			else {
				if (static_cast<size_t>(needed) < out.size()) {

					out.resize(static_cast<size_t>(needed) + 1);
					va_copy(args_copy, args);
					int n = _vsnwprintf_s(&out[0], out.size(),_TRUNCATE, fmt, args_copy);
					va_end(args_copy);
					if (n >= 0) {
						out.resize(static_cast<size_t>(n));
					}
					else {
						out.resize(static_cast<size_t>(needed));
					}
					return out;
				}
			}

			return out;
		}

			std::wstring Logger::FormatWinError(DWORD err) {

#ifdef _WIN32
				LPWSTR buf = nullptr;
				DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
					nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPWSTR)&buf, 0, nullptr);
				std::wstring out = L"WinError " + std::to_wstring(err);
				if (n && buf)
				{
					// Trim newline
					while (n && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n')) --n;
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
				FileTimeToSystemTime(&ft, &st);

				wchar_t buf[40] = { 0 };
				// yyyy-MM-ddTHH:mm:ss.mmmZ
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

				// JSON Lines
                // {"ts":"...","lvl":"INFO","cat":"Core","pid":1234,"tid":5678,"file":"...","line":42,"func":"...","msg":"...","winerr":5}
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

			void Logger::WriteConsoleW(const LogItem& item) {
#ifdef _WIN32
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

				DWORD bytesToWrite = static_cast<DWORD>(line.size() * sizeof(wchar_t));
				DWORD written = 0;
				::WriteConsoleW(m_console, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);

				// load the color back
				SetConsoleTextAttribute(m_console, csbi.wAttributes);
#else
				(void)item;
#endif
			}

			void Logger::OpenLogFileIfNeeded() {
#ifdef _WIN32
				std::lock_guard<std::mutex> lk(m_cfgmutex);
				if (m_file && m_file != INVALID_HANDLE_VALUE) return;

				std::wstring path = BaseLogPath(); // e.g. logs\ShadowStrike.log
				m_file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
					nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
				if (m_file != INVALID_HANDLE_VALUE) { m_actualLogPath = path; }
				if (m_file == INVALID_HANDLE_VALUE)
				{
					// File didnt open.
					return;
				}
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
				//Open the new file
				if (m_file && m_file != INVALID_HANDLE_VALUE) { CloseHandle(m_file); m_file = INVALID_HANDLE_VALUE; }
				OpenLogFileIfNeeded();
#endif
			}

			void Logger::PerformRotation()
			{
#ifdef _WIN32
				SS_LOG_INFO(L"Logger", L"Starting log file rotation");

				// EXCLUSIVE LOCK DURING ROTATION
				std::lock_guard<std::mutex> lock(m_cfgmutex);

				try {
					// CLOSE CURRENT FILE BEFORE ROTATION
					if (m_file && m_file != INVALID_HANDLE_VALUE) {
						::FlushFileBuffers(m_file);
						::CloseHandle(m_file);
						m_file = INVALID_HANDLE_VALUE;
					}

					const std::wstring base = BaseLogPath(); // logs\ShadowStrike.log

					// DELETE OLDEST FILE FIRST (if exists)
					if (m_cfg.maxFileCount > 1) {
						std::wstring oldestFile = base + L"." + std::to_wstring(m_cfg.maxFileCount);

						// Check if file exists before trying to delete
						DWORD attrs = ::GetFileAttributesW(oldestFile.c_str());
						if (attrs != INVALID_FILE_ATTRIBUTES) {
							// File exists, try to delete
							::SetFileAttributesW(oldestFile.c_str(), FILE_ATTRIBUTE_NORMAL); // Remove read-only

							if (!::DeleteFileW(oldestFile.c_str())) {
								DWORD error = ::GetLastError();
								if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
									SS_LOG_WARN(L"Logger",
										L"Failed to delete oldest log file: %ls (error %lu)",
										oldestFile.c_str(), error);

									// TRY FORCE DELETE WITH RETRY
									for (int retry = 0; retry < 3; ++retry) {
										::Sleep(100); // Wait 100ms
										if (::DeleteFileW(oldestFile.c_str())) {
											break;
										}
									}
								}
							}
						}

						// ROTATE FILES IN REVERSE ORDER (N-1 ... 1 -> N ... 2)
						for (size_t idx = m_cfg.maxFileCount - 1; idx >= 1; --idx) {
							std::wstring srcFile = base + L"." + std::to_wstring(idx);
							std::wstring dstFile = base + L"." + std::to_wstring(idx + 1);

							// Check if source file exists
							attrs = ::GetFileAttributesW(srcFile.c_str());
							if (attrs == INVALID_FILE_ATTRIBUTES) {
								// Source doesn't exist, skip
								if (idx == 1) break; // Prevent size_t underflow
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
								DWORD error = ::GetLastError();
								SS_LOG_WARN(L"Logger",
									L"Failed to rotate log file %ls to %ls (error %lu)",
									srcFile.c_str(), dstFile.c_str(), error);

								// FALLBACK: COPY + DELETE
								if (::CopyFileW(srcFile.c_str(), dstFile.c_str(), FALSE)) {
									::DeleteFileW(srcFile.c_str());
								}
							}

							if (idx == 1) break; // Prevent size_t underflow
						}

						// RENAME CURRENT LOG TO .1 (base -> .1)
						std::wstring firstRotated = base + L".1";

						// Check if current log exists
						attrs = ::GetFileAttributesW(base.c_str());
						if (attrs != INVALID_FILE_ATTRIBUTES) {
							// Delete target if exists
							attrs = ::GetFileAttributesW(firstRotated.c_str());
							if (attrs != INVALID_FILE_ATTRIBUTES) {
								::SetFileAttributesW(firstRotated.c_str(), FILE_ATTRIBUTE_NORMAL);
								::DeleteFileW(firstRotated.c_str());
							}

							if (!::MoveFileExW(base.c_str(), firstRotated.c_str(),
								MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
								DWORD error = ::GetLastError();
								SS_LOG_WARN(L"Logger",
									L"Failed to rotate current log to %ls (error %lu)",
									firstRotated.c_str(), error);

								// FALLBACK: COPY + DELETE
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
							if (!::DeleteFileW(base.c_str())) {
								DWORD error = ::GetLastError();
								SS_LOG_WARN(L"Logger",
									L"Failed to delete current log file: %ls (error %lu)",
									base.c_str(), error);
							}
						}
					}

					// RESET SIZE AND PATH
					m_currentSize = 0;
					m_actualLogPath.clear();

					// CREATE NEW LOG FILE (will be done by OpenLogFileIfNeeded)

				}
				catch (const std::exception& e) {
					SS_LOG_ERROR(L"Logger", L"Log rotation exception: %hs", e.what());
				}
				catch (...) {
					SS_LOG_ERROR(L"Logger", L"Log rotation unknown exception");
				}

				SS_LOG_INFO(L"Logger", L"Log file rotation completed");
#endif
			}
		

			void Logger::EnsureLogDirectory()
			{
#ifdef _WIN32
				
				if (m_cfg.logDirectory.empty()) return;
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
				//using base-path
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

				RotateIfNeeded(bytesToWrite);

				DWORD written = 0;
				::WriteFile(m_file, data, bytesToWrite, &written, nullptr);
				m_currentSize += written;
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
				const double ms = (double)(end.QuadPart - m_start.QuadPart) * 1000.0 / (double)m_freq.QuadPart;

				wchar_t buf[64];
				_snwprintf_s(buf, _TRUNCATE, L"Leave (%.3f ms)", ms);
				Logger::Instance().LogMessage(m_level, m_category, buf, m_file, m_line, m_function, 0);
#endif
			}	

	}//namespace Utils
}//namespace ShadowStrike