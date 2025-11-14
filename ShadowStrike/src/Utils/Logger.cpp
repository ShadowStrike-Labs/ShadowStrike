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

        Logger& Logger::Instance() {
            static Logger g_instance;
            return g_instance;
        }

        Logger::Logger() {
#ifdef _WIN32
            m_console = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
        }

        Logger::~Logger() {
            ShutDown();
        }

        bool Logger::IsEnabled(LogLevel level) const noexcept {
            const LogLevel minLevel = m_minLevel.load(std::memory_order_acquire);
            return static_cast<int>(level) >= static_cast<int>(minLevel);
        }

        bool Logger::IsInitialized() const noexcept {
            return m_initialized.load(std::memory_order_acquire);
        }

        void Logger::EnsureInitialized() {
            if (m_initialized.load(std::memory_order_acquire)) return;

            bool expected = false;
            if (m_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                LoggerConfig def{};
                def.async = false;
                def.toFile = false;
                def.toEventLog = false;
                def.toConsole = true;

                m_cfg = def;
                m_minLevel.store(def.minimalLevel, std::memory_order_release);
                m_accepting.store(true, std::memory_order_release);
            }
        }

        void Logger::Initialize(const LoggerConfig& cfg) {
            bool expected = false;
            if (!m_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                m_cfg = cfg;
                m_minLevel.store(cfg.minimalLevel, std::memory_order_release);
                return;
            }

            m_cfg = cfg;
            m_minLevel.store(cfg.minimalLevel, std::memory_order_release);

            try {
#ifdef _WIN32
                if (m_cfg.toFile) {
                    EnsureLogDirectory();
                    OpenLogFileIfNeeded();
                }
                if (m_cfg.toEventLog) {
                    OpenEventLog();
                }
#endif
            }
            catch (...) {
                m_cfg.toFile = false;
                m_cfg.toEventLog = false;
                OutputDebugStringW(L"[Logger] File init failed\n");
            }

            m_stop.store(false, std::memory_order_release);

            if (m_cfg.async) {
                try {
                    m_worker = std::thread([this]() { WorkerLoop(); });
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                catch (...) {
                    m_cfg.async = false;
                    OutputDebugStringW(L"[Logger] Async disabled\n");
                }
            }

            m_accepting.store(true, std::memory_order_release);
        }

        void Logger::ShutDown() {
            bool expected = true;
            if (!m_initialized.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
                return;
            }

            m_accepting.store(false, std::memory_order_release);
            m_stop.store(true, std::memory_order_release);
            m_queueCv.notify_all();

            if (m_worker.joinable()) {
                try {
                    m_worker.join();
                }
                catch (...) {
                    m_worker.detach();
                }
            }

            LogItem item;
            while (Dequeue(item)) {
                try {
                    if (m_cfg.toConsole) WriteConsole(item);
                    if (m_cfg.toFile) WriteFile(item);
                }
                catch (...) {}
            }

#ifdef _WIN32
            if (m_file && m_file != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(m_file);
                CloseHandle(m_file);
                m_file = INVALID_HANDLE_VALUE;
            }
            CloseEventLog();
#endif
        }

        void Logger::setMinimalLevel(LogLevel level) noexcept {
            m_minLevel.store(level, std::memory_order_release);
        }

        void Logger::Enqueue(LogItem&& item) {
            if (!m_accepting.load(std::memory_order_acquire)) return;
            if (!IsInitialized()) return;
            if (!IsEnabled(item.level)) return;

            if (m_cfg.async) {
                std::lock_guard<std::mutex> lk(m_queueMutex);
                if (m_queue.size() >= m_cfg.maxQueueSize) {
                    m_queue.pop_front();
                }
                m_queue.emplace_back(std::move(item));
                m_queueCv.notify_one();
            }
            else {
                try {
                    if (m_cfg.toConsole) WriteConsole(item);
                    if (m_cfg.toFile) WriteFile(item);
                    if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
                }
                catch (...) {}
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
                    m_queueCv.wait_for(lk, std::chrono::seconds(1), [this]() {
                        return m_stop.load(std::memory_order_acquire) || !m_queue.empty();
                        });

                    if (m_stop.load(std::memory_order_acquire) && m_queue.empty()) break;
                    if (m_queue.empty()) continue;

                    item = std::move(m_queue.front());
                    m_queue.pop_front();
                }

                try {
                    if (m_cfg.toConsole) WriteConsole(item);
                    if (m_cfg.toFile) WriteFile(item);
                    if (m_cfg.toEventLog && item.level >= LogLevel::Warn) WriteEventLog(item);
                }
                catch (...) {}
            }
        }

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

        void Logger::Flush() {
#ifdef _WIN32
            if (m_cfg.async) {
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
                while (std::chrono::steady_clock::now() < deadline) {
                    {
                        std::lock_guard<std::mutex> lk(m_queueMutex);
                        if (m_queue.empty()) break;
                    }
                    m_queueCv.notify_all();
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }

                LogItem x{};
                while (Dequeue(x)) {
                    try {
                        if (m_cfg.toConsole) WriteConsole(x);
                        if (m_cfg.toFile) WriteFile(x);
                        if (m_cfg.toEventLog && x.level >= LogLevel::Warn) WriteEventLog(x);
                    }
                    catch (...) {}
                }
            }

            if (m_file && m_file != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(m_file);
            }
#endif
        }

        const wchar_t* Logger::NarrowToWideTLS(const char* s) {
#ifdef _WIN32
            thread_local std::wstring buff;
            if (!s) { buff.clear(); return buff.c_str(); }

            int len = static_cast<int>(strlen(s));
            if (len <= 0) { buff.clear(); return buff.c_str(); }

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

            std::wstring out;
            out.resize(512);

            va_list args_copy;
            va_copy(args_copy, args);
            int needed = _vsnwprintf_s(&out[0], out.size(), _TRUNCATE, fmt, args_copy);
            va_end(args_copy);

            if (needed < 0) {
                size_t cap = 1024;
                while (cap <= (1u << 20)) {
                    out.resize(cap);
                    va_copy(args_copy, args);
                    int n = _vsnwprintf_s(&out[0], out.size(), _TRUNCATE, fmt, args_copy);
                    va_end(args_copy);

                    if (n >= 0 && static_cast<size_t>(n) < out.size()) {
                        out.resize(static_cast<size_t>(n));
                        return out;
                    }
                    cap *= 2;
                }
                out = L"[Logger] Message too large";
            }
            else {
                out.resize(static_cast<size_t>(needed));
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
            if (n && buf) {
                while (n && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n' || buf[n - 1] == L' ')) --n;
                out.append(L": ");
                out.append(buf, buf + n);
                LocalFree(buf);
            }
            return out;
#else
            return L"";
#endif
        }

        uint64_t Logger::NowAsFileTime100nsUTC() {
#ifdef _WIN32
            FILETIME ft{};
            typedef VOID(WINAPI* GetPreciseFunc)(LPFILETIME);
            static GetPreciseFunc pGetPrecise = (GetPreciseFunc)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetSystemTimePreciseAsFileTime");
            if (pGetPrecise)
                pGetPrecise(&ft);
            else
                GetSystemTimeAsFileTime(&ft);

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

        std::wstring Logger::EscapeJson(const std::wstring& s) {
            std::wstring out;
            out.reserve(s.size() + 16);

            for (wchar_t c : s) {
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
                        wchar_t buf[7];
                        _snwprintf_s(buf, _TRUNCATE, L"\\u%04x", (unsigned)c);
                        out += buf;
                    }
                    else {
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

            if (!item.category.empty()) {
                s += L" [";
                s += item.category;
                s += L"]";
            }

            if (m_cfg.includeProcThreadId) {
                s += L" (";
                s += std::to_wstring(item.pid);
                s += L":";
                s += std::to_wstring(item.tid);
                s += L")";
            }

            if (m_cfg.includeSrcLocation && !item.file.empty()) {
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

            if (m_cfg.includeProcThreadId) {
                s += L",\"pid\":";
                s += std::to_wstring(item.pid);
                s += L",\"tid\":";
                s += std::to_wstring(item.tid);
            }

            if (m_cfg.includeSrcLocation && !item.file.empty()) {
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

            if (item.winError) {
                s += L",\"winerr\":";
                s += std::to_wstring(item.winError);
            }

            s += L",\"msg\":\"";
            s += EscapeJson(item.message);
            s += L"\"}";
            return s;
        }

        void Logger::WriteConsole(const LogItem& item) {
#ifdef _WIN32
            if (!m_console || m_console == INVALID_HANDLE_VALUE) return;

            WORD color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            switch (item.level) {
            case LogLevel::Trace: color = FOREGROUND_BLUE | FOREGROUND_GREEN; break;
            case LogLevel::Debug: color = FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
            case LogLevel::Info:  color = FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
            case LogLevel::Warn:  color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY; break;
            case LogLevel::Error: color = FOREGROUND_RED | FOREGROUND_INTENSITY; break;
            case LogLevel::Fatal: color = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY; break;
            }

            CONSOLE_SCREEN_BUFFER_INFO csbi{};
            GetConsoleScreenBufferInfo(m_console, &csbi);
            SetConsoleTextAttribute(m_console, color);

            std::wstring line = m_cfg.jsonLines ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
            line += L"\r\n";

            if (line.size() > std::numeric_limits<DWORD>::max() / sizeof(wchar_t)) {
                line = L"[Logger] Message too large\r\n";
            }

            DWORD written = 0;
            ::WriteConsoleW(m_console, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
            SetConsoleTextAttribute(m_console, csbi.wAttributes);
#endif
        }

        void Logger::OpenLogFileIfNeeded() {
#ifdef _WIN32
            std::lock_guard<std::mutex> lk(m_cfgmutex);
            if (m_file && m_file != INVALID_HANDLE_VALUE) return;

            std::wstring path = BaseLogPath();
            m_file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (m_file == INVALID_HANDLE_VALUE) return;

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
            if (m_file && m_file != INVALID_HANDLE_VALUE) {
                CloseHandle(m_file);
                m_file = INVALID_HANDLE_VALUE;
            }
            OpenLogFileIfNeeded();
#endif
        }

        void Logger::PerformRotation() {
#ifdef _WIN32
            bool expected = false;
            if (!m_insideRotation.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                return;
            }

            struct RotationGuard {
                std::atomic<bool>& flag;
                ~RotationGuard() { flag.store(false, std::memory_order_release); }
            } guard{ m_insideRotation };

            std::lock_guard<std::mutex> lock(m_cfgmutex);

            try {
                if (m_file && m_file != INVALID_HANDLE_VALUE) {
                    ::FlushFileBuffers(m_file);
                    ::CloseHandle(m_file);
                    m_file = INVALID_HANDLE_VALUE;
                }

                const std::wstring base = BaseLogPath();

                if (m_cfg.maxFileCount > 1) {
                    std::wstring oldestFile = base + L"." + std::to_wstring(m_cfg.maxFileCount);
                    DWORD attrs = ::GetFileAttributesW(oldestFile.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES) {
                        ::SetFileAttributesW(oldestFile.c_str(), FILE_ATTRIBUTE_NORMAL);
                        ::DeleteFileW(oldestFile.c_str());
                    }

                    for (size_t idx = m_cfg.maxFileCount - 1; idx >= 1; --idx) {
                        std::wstring srcFile = base + L"." + std::to_wstring(idx);
                        std::wstring dstFile = base + L"." + std::to_wstring(idx + 1);

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

                        ::MoveFileExW(srcFile.c_str(), dstFile.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
                        if (idx == 1) break;
                    }

                    std::wstring firstRotated = base + L".1";
                    attrs = ::GetFileAttributesW(base.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES) {
                        attrs = ::GetFileAttributesW(firstRotated.c_str());
                        if (attrs != INVALID_FILE_ATTRIBUTES) {
                            ::SetFileAttributesW(firstRotated.c_str(), FILE_ATTRIBUTE_NORMAL);
                            ::DeleteFileW(firstRotated.c_str());
                        }
                        ::MoveFileExW(base.c_str(), firstRotated.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
                    }
                }
                else {
                    DWORD attrs = ::GetFileAttributesW(base.c_str());
                    if (attrs != INVALID_FILE_ATTRIBUTES) {
                        ::SetFileAttributesW(base.c_str(), FILE_ATTRIBUTE_NORMAL);
                        ::DeleteFileW(base.c_str());
                    }
                }

                m_currentSize = 0;
                m_actualLogPath.clear();
            }
            catch (...) {}
#endif
        }

        void Logger::EnsureLogDirectory() {
#ifdef _WIN32
            if (m_cfg.logDirectory.empty()) return;
            DWORD attrs = GetFileAttributesW(m_cfg.logDirectory.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                return;
            }
            CreateDirectoryW(m_cfg.logDirectory.c_str(), nullptr);
#endif
        }

        std::wstring Logger::BaseLogPath() const {
#ifdef _WIN32
            std::wstring path = m_cfg.logDirectory;
            if (!path.empty()) {
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

        std::wstring Logger::CurrentLogPath() const {
            return m_actualLogPath.empty() ? BaseLogPath() : m_actualLogPath;
        }

        void Logger::WriteFile(const LogItem& item) {
#ifdef _WIN32
            std::lock_guard<std::mutex> lk(m_cfgmutex);
            OpenLogFileIfNeeded();
            if (!m_file || m_file == INVALID_HANDLE_VALUE) return;

            std::wstring line = m_cfg.jsonLines ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
            line += L"\r\n";

            const BYTE* data = reinterpret_cast<const BYTE*>(line.c_str());
            const DWORD bytesToWrite = static_cast<DWORD>(line.size() * sizeof(wchar_t));

            if (line.size() > std::numeric_limits<DWORD>::max() / sizeof(wchar_t)) {
                return;
            }

            RotateIfNeeded(bytesToWrite);

            DWORD written = 0;
            ::WriteFile(m_file, data, bytesToWrite, &written, nullptr);
            m_currentSize += written;

            if (static_cast<int>(item.level) >= static_cast<int>(m_cfg.flushLevel))
                FlushFileBuffers(m_file);
#endif
        }

        void Logger::OpenEventLog() {
#ifdef _WIN32
            if (m_eventSrc) return;
            m_eventSrc = RegisterEventSourceW(nullptr, m_cfg.eventLogSource.c_str());
#endif
        }

        void Logger::CloseEventLog() {
#ifdef _WIN32
            if (m_eventSrc) {
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
            switch (item.level) {
            case LogLevel::Warn:  type = EVENTLOG_WARNING_TYPE; break;
            case LogLevel::Error: type = EVENTLOG_ERROR_TYPE;   break;
            case LogLevel::Fatal: type = EVENTLOG_ERROR_TYPE;   break;
            default:              type = EVENTLOG_INFORMATION_TYPE; break;
            }

            std::wstring payload = m_cfg.jsonLines ? FormatAsJson(item) : (FormatPrefix(item) + item.message);
            const wchar_t* strings[1] = { payload.c_str() };
            ::ReportEventW(m_eventSrc, type, 0, 0, nullptr, 1, 0, strings, nullptr);
#endif
        }

        Logger::Scope::Scope(const wchar_t* category, const wchar_t* file, int line,
            const wchar_t* function, const wchar_t* messageOnEnter, LogLevel level)
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

        Logger::Scope::~Scope() {
#ifdef _WIN32
            LARGE_INTEGER end{};
            QueryPerformanceCounter(&end);

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

    } // namespace Utils
} // namespace ShadowStrike