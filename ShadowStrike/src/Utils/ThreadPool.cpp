#if !defined(_X86_) && !defined(_AMD64_)
#ifdef _M_X64
#define _AMD64_
#elif defined(_M_IX86)
#define _X86_
#else
#error "Unknown architecture, please compile for x86 or x64"
#endif
#endif
#ifdef _DEBUG
#include <crtdbg.h>
#endif

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#endif // _WIN32

#include "ThreadPool.hpp"
#include "Logger.hpp"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <array>
#include <processthreadsapi.h>
#include <unordered_set>



// ETW Event Provider GUID 
#define INITGUID
#include <evntprov.h>
#include <evntrace.h>

//  ETW Provider GUID for shadowStrike thread pool
// {7A8F98C2-8740-49E5-B9F3-D418B78D25EB}
DEFINE_GUID(ShadowStrikeThreadPoolProvider,
    0x7a8f98c2, 0x8740, 0x49e5, 0xb9, 0xf3, 0xd4, 0x18, 0xb7, 0x8d, 0x25, 0xeb);



namespace ShadowStrike {
    namespace Utils {

        static void safe_close_handle(HANDLE h, bool enableLogging = false) {
            if (!h || h == INVALID_HANDLE_VALUE) return;
            HANDLE dup = nullptr;
            BOOL ok = ::DuplicateHandle(::GetCurrentProcess(), h,
                ::GetCurrentProcess(), &dup,
                0, FALSE, DUPLICATE_SAME_ACCESS);
            if (ok && dup) {
                ::CloseHandle(dup);
                ::CloseHandle(h);
                if (enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"CloseHandle OK %p", h);
                }
            }
            else {
                DWORD err = ::GetLastError();
                if (enableLogging) {
                    SS_LOG_WARN(L"ThreadPool", L"CloseHandle skipped (DuplicateHandle failed) %p err=%lu", h, err);
                }
            }
        }

        //ETW Level enumeration
        enum class EtwLevel : UCHAR {
            LogAlways = 0,
            Critical = 1,
            Error = 2,
            Warning = 3,
            Info = 4,
            Verbose = 5
        };

        //*** Global ETW event descriptors ***
        static const EVENT_DESCRIPTOR g_evt_ThreadPoolCreated = MAKE_EVT_DESCRIPTOR(ThreadPoolCreated, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_ThreadPoolDestroyed = MAKE_EVT_DESCRIPTOR(ThreadPoolDestroyed, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_TaskSubmitted = MAKE_EVT_DESCRIPTOR(ThreadPoolTaskSubmitted, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_TaskStarted = MAKE_EVT_DESCRIPTOR(ThreadPoolTaskStarted, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_TaskCompleted = MAKE_EVT_DESCRIPTOR(ThreadPoolTaskCompleted, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_ThreadCreated = MAKE_EVT_DESCRIPTOR(ThreadPoolThreadCreated, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_ThreadDestroyed = MAKE_EVT_DESCRIPTOR(ThreadPoolThreadDestroyed, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_Paused = MAKE_EVT_DESCRIPTOR(ThreadPoolPaused, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_Resumed = MAKE_EVT_DESCRIPTOR(ThreadPoolResumed, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_Resized = MAKE_EVT_DESCRIPTOR(ThreadPoolResized, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_GroupCreated = MAKE_EVT_DESCRIPTOR(ThreadPoolGroupCreated, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_GroupWaitComplete = MAKE_EVT_DESCRIPTOR(ThreadPoolGroupWaitComplete, EtwLevel::Info);
        static const EVENT_DESCRIPTOR g_evt_GroupCancelled = MAKE_EVT_DESCRIPTOR(ThreadPoolGroupCancelled, EtwLevel::Info);

        ThreadPool::ThreadPool(const ThreadPoolConfig& config)
            : m_config(config)
        {
            try {
                initialize();
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"ThreadPool", L"Initialization failed: %S", ex.what());
                m_shutdown.store(true, std::memory_order_release);
                throw std::exception("ThreadPool initialization failed");
            }
        }

        ThreadPool::ThreadPool(size_t threadCount, std::wstring poolName)
        {
            m_config = ThreadPoolConfig{};
            m_config.threadCount = threadCount;
            m_config.poolName = std::move(poolName);
            m_config.enableLogging = true;


            try {
                initialize();
            }
            catch (...) {
                SS_LOG_ERROR(L"ThreadPool", L"Initialization failed for pool %s", m_config.poolName.c_str());
                m_shutdown.store(true, std::memory_order_release);
                throw;
            }
        }

        ThreadPool::~ThreadPool()
        {
            try {
                // 1) Signal shutdown and wake waiters
                bool expected = false;
                if (m_shutdown.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    m_taskCv.notify_all();
                    m_waitAllCv.notify_all();
                }

                // 2) Snapshot thread containers under short lock (transfer ownership)
                std::vector<std::thread> localThreads;
                std::vector<HANDLE> localHandles;
                {
                    std::lock_guard<std::mutex> lk(m_threadContainerMutex);
                    localThreads = std::move(m_threads);
                    localHandles = std::move(m_threadHandles);
                    // members now empty
                }

                // Defensive: ensure handle vector at least as long as thread vector
                if (localHandles.size() < localThreads.size()) {
                    localHandles.resize(localThreads.size(), nullptr);
                }

                // 3) Try graceful shutdown with bounded total timeout
                auto shutdownStart = std::chrono::steady_clock::now();
                constexpr auto DESTRUCTOR_TIMEOUT = std::chrono::seconds(5);

                for (size_t i = 0; i < localThreads.size(); ++i) {
                    try {
                        std::thread& thread = localThreads[i];

                        // If not joinable, attempt safe handle close and continue
                        if (!thread.joinable()) {
                            HANDLE h = (i < localHandles.size()) ? localHandles[i] : nullptr;
                            if (h && h != INVALID_HANDLE_VALUE) {
                                HANDLE dup = nullptr;
                                if (::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                    ::CloseHandle(dup);
                                    ::CloseHandle(h);
                                }
                                localHandles[i] = nullptr;
                            }
                            continue;
                        }

                        // Compute remaining time
                        auto elapsed = std::chrono::steady_clock::now() - shutdownStart;
                        if (elapsed > DESTRUCTOR_TIMEOUT) {
                            // timed out -> detach + safe-close
                            try { thread.detach(); }
                            catch (...) {}
                            HANDLE h = (i < localHandles.size()) ? localHandles[i] : nullptr;
                            if (h && h != INVALID_HANDLE_VALUE) {
                                HANDLE dup = nullptr;
                                if (::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                    ::CloseHandle(dup);
                                    ::CloseHandle(h);
                                }
                                localHandles[i] = nullptr;
                            }
                            continue;
                        }

                        auto timeRemaining = DESTRUCTOR_TIMEOUT - elapsed;
                        auto ms64 = std::chrono::duration_cast<std::chrono::milliseconds>(timeRemaining).count();
                        DWORD waitMs = (ms64 <= 0) ? 0 : (ms64 >= static_cast<long long>(INFINITE) ? INFINITE : static_cast<DWORD>(ms64));

                        HANDLE h = (i < localHandles.size()) ? localHandles[i] : nullptr;
                        bool joined = false;

                        if (h && h != INVALID_HANDLE_VALUE) {
                            HANDLE dup = nullptr;
                            if (::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                DWORD r = ::WaitForSingleObject(dup, waitMs);
                                ::CloseHandle(dup);
                                if (r == WAIT_OBJECT_0) {
                                    try { if (thread.joinable()) thread.join(); }
                                    catch (...) {}
                                    // close original handle safely
                                    HANDLE orig = localHandles[i];
                                    if (orig && orig != INVALID_HANDLE_VALUE) {
                                        HANDLE dup2 = nullptr;
                                        if (::DuplicateHandle(::GetCurrentProcess(), orig, ::GetCurrentProcess(), &dup2, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                            ::CloseHandle(dup2);
                                            ::CloseHandle(orig);
                                        }
                                    }
                                    localHandles[i] = nullptr;
                                    joined = true;
                                }
                                else {
                                    try { thread.detach(); }
                                    catch (...) {}
                                    HANDLE orig = localHandles[i];
                                    if (orig && orig != INVALID_HANDLE_VALUE) {
                                        HANDLE dup2 = nullptr;
                                        if (::DuplicateHandle(::GetCurrentProcess(), orig, ::GetCurrentProcess(), &dup2, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                                            ::CloseHandle(dup2);
                                            ::CloseHandle(orig);
                                        }
                                    }
                                    localHandles[i] = nullptr;
                                }
                            }
                            else {
                                // DuplicateHandle failed -> avoid CloseHandle on possibly-invalid handle
                                localHandles[i] = nullptr;
                                auto joinStart = std::chrono::steady_clock::now();
                                auto maxWait = std::chrono::milliseconds(waitMs);
                                while (std::chrono::steady_clock::now() - joinStart < maxWait) {
                                    if (!thread.joinable()) break;
                                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                                }
                                if (!thread.joinable()) {
                                    try { if (thread.joinable()) thread.join(); }
                                    catch (...) {}
                                    joined = true;
                                }
                                else {
                                    try { thread.detach(); }
                                    catch (...) {}
                                }
                            }
                        }
                        else {
                            // No valid native handle: try brief join polling then detach
                            auto joinStart = std::chrono::steady_clock::now();
                            auto maxWait = std::chrono::milliseconds(waitMs);
                            while (std::chrono::steady_clock::now() - joinStart < maxWait) {
                                if (!thread.joinable()) break;
                                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                            }
                            if (!thread.joinable()) {
                                try { if (thread.joinable()) thread.join(); }
                                catch (...) {}
                                joined = true;
                            }
                            else {
                                try { thread.detach(); }
                                catch (...) {}
                            }
                        }
                    }
                    catch (...) {
                        // best-effort continue
                    }
                }

                // 4) Close any remaining handles
                for (size_t i = 0; i < localHandles.size(); ++i) {
                    HANDLE h = localHandles[i];
                    if (h && h != INVALID_HANDLE_VALUE) {
                        HANDLE dup = nullptr;
                        if (::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                            ::CloseHandle(dup);
                            ::CloseHandle(h);
                        }
                        localHandles[i] = nullptr;
                    }
                }

                // 5) Clear task queues under queue mutex
                {
                    std::lock_guard<std::mutex> lock(m_queueMutex);
                    m_criticalPriorityQueue.clear();
                    m_highPriorityQueue.clear();
                    m_normalPriorityQueue.clear();
                    m_lowPriorityQueue.clear();
                }

                // 6) Unregister ETW provider if set
                if (m_etwProvider != 0) {
                    EventUnregister(m_etwProvider);
                    m_etwProvider = 0;
                }
            }
            catch (...) {
                // never throw from destructor
            }
        }
        
        void ThreadPool::initialize()
        {
            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Initializing ThreadPool with %zu threads, name: %s",
                    m_config.threadCount, m_config.poolName.c_str());
            }

#ifdef _DEBUG
            // Enable CRT debug heap checks and break on corruption (heavy, only for debugging)
            int dbgFlags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
            dbgFlags |= _CRTDBG_ALLOC_MEM_DF;        // track allocations
            dbgFlags |= _CRTDBG_CHECK_ALWAYS_DF;     // check heap on every allocation/free (expensive)
            dbgFlags |= _CRTDBG_LEAK_CHECK_DF;       // leak check at exit
            _CrtSetDbgFlag(dbgFlags);

            
#endif
            if (m_config.enableProfiling) {
                try { registerETWProvider(); }
                catch (...) {
                    if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"ETW provider registration failed; continuing without ETW");
                }
            }

            // Compute thread count
            auto computeThreadCount = [&]() -> size_t {
                SYSTEM_INFO si;
                ::GetSystemInfo(&si);

                size_t count = m_config.threadCount;
                if (count == 0) {
                    size_t hwThreads = static_cast<size_t>(si.dwNumberOfProcessors);
                    count = (hwThreads == 0) ? 1 : std::max<size_t>(1, (hwThreads * 3) / 4);
                }

                switch (m_config.cpuSubsystem) {
                case CpuSubsystem::RealTime:
                    count = std::max<size_t>(1, count / 2);
                    break;
                case CpuSubsystem::Scanner:
                    count = std::max<size_t>(1, std::min(count + count / 2, count * 2));
                    break;
                default:
                    break;
                }

                size_t hwMax = static_cast<size_t>(si.dwNumberOfProcessors);
                if (hwMax == 0) hwMax = 1;
                return std::min(count, hwMax);
                };

            m_config.threadCount = computeThreadCount();
            m_startReady.store(false, std::memory_order_release);

            // prepare containers
            {
                std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                m_threads.clear();
                m_threadHandles.clear();
                m_threads.reserve(m_config.threadCount);
                m_threadHandles.reserve(m_config.threadCount);
            }

            size_t created = 0;
            try {
                for (size_t i = 0; i < m_config.threadCount; ++i) {
                    // create thread that waits on start CV
                    std::thread t([this, i]() noexcept {
                        try {
                            std::unique_lock<std::mutex> lk(m_startMutex);
                            m_startCv.wait(lk, [this]() {
                                return m_startReady.load(std::memory_order_acquire) || m_shutdown.load(std::memory_order_acquire);
                                });
                            if (m_shutdown.load(std::memory_order_acquire)) return;
                            workerThread(i);
                        }
                        catch (...) { /* swallow */ }
                        });

                    HANDLE th = t.native_handle();
                    if (!th || th == INVALID_HANDLE_VALUE) {
                        if (m_config.enableLogging) SS_LOG_ERROR(L"ThreadPool", L"Invalid thread handle for index %zu", i);
                        if (t.joinable()) { try { t.detach(); } catch (...) {} }
                        throw std::runtime_error("Failed to get thread handle");
                    }

                    // push thread+handle under container mutex
                    {
                        std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                        m_threads.push_back(std::move(t));
                        m_threadHandles.push_back(th);

                        // best-effort per-thread init while protected from races
                        size_t idx = m_threads.size() - 1;
                        if (!m_config.poolName.empty()) {
                            std::wstringstream ss;
                            ss << m_config.poolName << L"-" << idx;
                            try { setThreadName(th, ss.str()); }
                            catch (...) {}
                        }
                        if (m_config.setThreadPriority) {
                            ::SetThreadPriority(th, m_config.threadPriority);
                        }
                        if (m_config.bindToHardware) {
                            try { bindThreadToCore(idx); }
                            catch (...) {}
                        }
                    }

                    if (m_etwProvider != 0) {
                        ULONG idx = static_cast<ULONG>(i);
                        DWORD tid = ::GetThreadId(th);
                        EVENT_DATA_DESCRIPTOR d[2];
                        EventDataDescCreate(&d[0], &idx, sizeof(idx));
                        EventDataDescCreate(&d[1], &tid, sizeof(tid));
                        EventWrite(m_etwProvider, &g_evt_ThreadCreated, _countof(d), d);
                    }

                    ++created;
                }
            }
            catch (...) {
                // rollback: allow created threads to wake and exit, then detach/close
                m_shutdown.store(true, std::memory_order_release);
                {
                    std::lock_guard<std::mutex> lk(m_startMutex);
                    m_startReady.store(true, std::memory_order_release);
                }
                m_startCv.notify_all();
#ifndef NDEBUG
                try {
                    validateInternalState();
                }
                catch (const std::exception& ex) {
                    if (m_config.enableLogging) {
                        SS_LOG_ERROR(L"ThreadPool", L"Internal invariant failed: %hs", ex.what());
                    }
                    // debug: rethrow veya swallow tercihine göre
                    throw;
                }
#endif

                {
                    std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                    for (auto& th : m_threads) {
                        if (th.joinable()) {
                            try { th.detach(); }
                            catch (...) {}
                        }
                    }
                    for (HANDLE h : m_threadHandles) {
                        if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h);
                    }
                    m_threads.clear();
                    m_threadHandles.clear();
                }

                m_shutdown.store(false, std::memory_order_release);
                throw;
            }

            // start created threads
            {
                std::lock_guard<std::mutex> lk(m_startMutex);
                m_startReady.store(true, std::memory_order_release);
            }
            m_startCv.notify_all();

            if (m_etwProvider != 0) {
                std::wstring poolNameCopy = m_config.poolName;
                const wchar_t* namePtr = poolNameCopy.c_str();
                ULONG nameBytes = static_cast<ULONG>((poolNameCopy.length() + 1) * sizeof(wchar_t));
                ULONG threadCountUL = static_cast<ULONG>(m_config.threadCount);
                EVENT_DATA_DESCRIPTOR d[2];
                EventDataDescCreate(&d[0], namePtr, nameBytes);
                EventDataDescCreate(&d[1], &threadCountUL, sizeof(threadCountUL));
                EventWrite(m_etwProvider, &g_evt_ThreadPoolCreated, _countof(d), d);
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"ThreadPool initialized with %zu threads (created: %zu)",
                    m_config.threadCount, created);
            }
        }
    void ThreadPool::initializeThread(size_t threadIndex)
    {
        // Bounds check
        if (threadIndex >= m_threadHandles.size()) {
            if (m_config.enableLogging) {
                SS_LOG_ERROR(L"ThreadPool",
                    L"initializeThread: index %zu out of range (handles size: %zu)",
                    threadIndex, m_threadHandles.size());
            }
            return;
        }

        HANDLE threadHandle = m_threadHandles[threadIndex];

        // Handle validation
        if (!threadHandle || threadHandle == INVALID_HANDLE_VALUE) {
            if (m_config.enableLogging) {
                SS_LOG_ERROR(L"ThreadPool",
                    L"initializeThread: invalid handle for index %zu", threadIndex);
            }
            return;
        }

        // Set thread name (best-effort)
        if (!m_config.poolName.empty()) {
            std::wstringstream ss;
            ss << m_config.poolName << L"-" << threadIndex;
            try {
                setThreadName(threadHandle, ss.str());
            }
            catch (...) {
                // Avoid terminate; optional log
                if (m_config.enableLogging) {
                    SS_LOG_WARN(L"ThreadPool",
                        L"setThreadName threw for index %zu; continuing", threadIndex);
                }
            }
        }

        // Priority (check result)
        if (m_config.setThreadPriority) {
            if (!::SetThreadPriority(threadHandle, m_config.threadPriority)) {
                if (m_config.enableLogging) {
                    const DWORD err = ::GetLastError();
                    SS_LOG_WARN(L"ThreadPool",
                        L"SetThreadPriority failed for index %zu (err=%lu)",
                        threadIndex, err);
                }
            }
        }

        // Hardware affinity (best-effort)
        if (m_config.bindToHardware) {
            try {
                bindThreadToCore(threadIndex);
            }
            catch (...) {
                if (m_config.enableLogging) {
                    SS_LOG_WARN(L"ThreadPool",
                        L"bindThreadToCore threw for index %zu; continuing without affinity",
                        threadIndex);
                }
            }
        }

        // Informational stack size (configured value)
        if (m_config.threadStackSize > 0 && m_config.enableLogging) {
            SS_LOG_INFO(L"ThreadPool",
                L"Thread %zu configured (stack setting: %zu)",
                threadIndex, m_config.threadStackSize);
        }

        // ETW: thread created (guarded)
        if (m_etwProvider != 0) {
            ULONG idx = static_cast<ULONG>(threadIndex);
            DWORD tid = ::GetThreadId(threadHandle); // may return 0

            EVENT_DATA_DESCRIPTOR d[2];
            EventDataDescCreate(&d[0], &idx, sizeof(idx));
            EventDataDescCreate(&d[1], &tid, sizeof(tid));

            // EventWrite should not throw; still keep it isolated
            ULONG status = EventWrite(m_etwProvider, &g_evt_ThreadCreated, _countof(d), d);

            if (m_config.enableLogging) {
                if (tid == 0) {
                    SS_LOG_WARN(L"ThreadPool",
                        L"GetThreadId returned 0 for index %zu (event status=%lu)",
                        threadIndex, status);
                }
                else if (status != ERROR_SUCCESS) {
                    SS_LOG_WARN(L"ThreadPool",
                        L"EventWrite(g_evt_ThreadCreated) status=%lu for index %zu",
                        status, threadIndex);
                }
            }
        }
    }


    void ThreadPool::bindThreadToCore(size_t threadIndex)
    {
        // Bounds & handle validation
        if (threadIndex >= m_threadHandles.size()) {
            if (m_config.enableLogging) {
                SS_LOG_ERROR(L"ThreadPool",
                    L"bindThreadToCore: index %zu out of range (handles size: %zu)",
                    threadIndex, m_threadHandles.size());
            }
            return;
        }

        HANDLE threadHandle = m_threadHandles[threadIndex];
        if (!threadHandle || threadHandle == INVALID_HANDLE_VALUE) {
            if (m_config.enableLogging) {
                SS_LOG_ERROR(L"ThreadPool",
                    L"bindThreadToCore: invalid handle for index %zu", threadIndex);
            }
            return;
        }

        // Query system processor count (guard against 0)
        SYSTEM_INFO sysInfo;
        ::GetSystemInfo(&sysInfo);
        DWORD nprocs = sysInfo.dwNumberOfProcessors ? sysInfo.dwNumberOfProcessors : 1;

        // Bit width of affinity mask (63 on x64, 31 on x86)
        constexpr size_t MAX_CORE_INDEX = (sizeof(DWORD_PTR) * 8) - 1;

        // Base assignment
        size_t coreIndex = threadIndex % nprocs;

        // Subsystem-specific mapping
        switch (m_config.cpuSubsystem) {
        case CpuSubsystem::RealTime:
            coreIndex = 0;
            break;
        case CpuSubsystem::Scanner:
            coreIndex = (nprocs > 1) ? ((threadIndex % (nprocs - 1)) + 1) : 0; // avoid core 0
            break;
        case CpuSubsystem::NetworkMonitor:
            coreIndex = nprocs / 2; // middle core
            break;
        default:
            coreIndex = threadIndex % nprocs;
            break;
        }

        // Prevent shift overflow on large systems
        if (coreIndex > MAX_CORE_INDEX) {
            if (m_config.enableLogging) {
                SS_LOG_WARN(L"ThreadPool",
                    L"Core index %zu exceeds mask width %zu; wrapping",
                    coreIndex, MAX_CORE_INDEX);
            }
            coreIndex %= (MAX_CORE_INDEX + 1);
        }

        // Build affinity mask and set
        DWORD_PTR mask = (static_cast<DWORD_PTR>(1) << coreIndex);
        DWORD_PTR prev = ::SetThreadAffinityMask(threadHandle, mask);

        if (prev == 0) {
            if (m_config.enableLogging) {
                DWORD err = ::GetLastError();
                SS_LOG_WARN(L"ThreadPool",
                    L"SetThreadAffinityMask failed (thread %zu → core %zu), err=%lu",
                    threadIndex, coreIndex, err);
            }
            // Fallback: continue without affinity
            return;
        }

        if (m_config.enableLogging) {
            SS_LOG_INFO(L"ThreadPool", L"Thread %zu bound to core %zu", threadIndex, coreIndex);
        }
    }


        void ThreadPool::setThreadName(HANDLE threadHandle, const std::wstring& name) const {
            using SetThreadDescriptionFunc = HRESULT(WINAPI*)(HANDLE, PCWSTR);

            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (!kernel32) return;

            auto setThreadDescFunc = reinterpret_cast<SetThreadDescriptionFunc>(
                GetProcAddress(kernel32, "SetThreadDescription"));

            if (setThreadDescFunc) {
                setThreadDescFunc(threadHandle, name.c_str());
            }
        }

        void ThreadPool::workerThread(size_t threadIndex) {
            try {
                std::wstringstream threadName;
                threadName << m_config.poolName << L"-" << threadIndex;

                if (m_config.enableLogging) {
                    SS_LOG_DEBUG(L"ThreadPool", L"Thread %zu (%s) started", threadIndex, threadName.str().c_str());
                }

                while (true) {
                    Task task;
                    bool hasTask = false;

                    try {
                        std::unique_lock<std::mutex> lock(m_queueMutex);

                        // Safe predicate: swallow exceptions inside predicate to avoid leaking out of wait()
                        m_taskCv.wait(lock, [this]() noexcept -> bool {
                            try {
                                bool shuttingDown = m_shutdown.load(std::memory_order_acquire);
                                bool paused = m_paused.load(std::memory_order_acquire);
                                bool hasTasks = !m_criticalPriorityQueue.empty() ||
                                    !m_highPriorityQueue.empty() ||
                                    !m_normalPriorityQueue.empty() ||
                                    !m_lowPriorityQueue.empty();
                                return shuttingDown || (!paused && hasTasks);
                            }
                            catch (...) {
                                // If predicate throws for any reason, treat as "no work" so wait() continues
                                return false;
                            }
                            });

                        // After wake, re-evaluate under the lock
                        bool shuttingDown = m_shutdown.load(std::memory_order_acquire);
                        bool paused = m_paused.load(std::memory_order_acquire);
                        bool hasTasks = !m_criticalPriorityQueue.empty() ||
                            !m_highPriorityQueue.empty() ||
                            !m_normalPriorityQueue.empty() ||
                            !m_lowPriorityQueue.empty();

                        if (shuttingDown && !hasTasks) {
                            break;
                        }

                        if (paused || !hasTasks) {
                            // nothing to do, loop back to wait
                            continue;
                        }

                        // retrieve next task while still holding the queue lock
                        task = getNextTask();
                        hasTask = (task.function != nullptr);
                    }
                    catch (const std::exception& e) {
                        // Transient/handled exception in task retrieval; record at DEBUG and recover
                        if (m_config.enableLogging) {
                            SS_LOG_DEBUG(L"ThreadPool", L"Worker %zu: Exception in task retrieval (handled): %hs",
                                threadIndex, e.what());
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        continue;
                    }
                    catch (...) {
                        if (m_config.enableLogging) {
                            SS_LOG_DEBUG(L"ThreadPool", L"Worker %zu: Unknown exception in task retrieval (handled)",
                                threadIndex);
                        }
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        continue;
                    }

                    // Execute the task (outside the queue lock)
                    if (hasTask && task.function) {
                        auto startTime = std::chrono::steady_clock::now();

                        m_activeThreads.fetch_add(1, std::memory_order_release);
                        bool taskSucceeded = false;

                        try {
                            task.function();
                            taskSucceeded = true;
                        }
                        catch (const std::bad_alloc& e) {
                            if (m_config.enableLogging) {
                                SS_LOG_DEBUG(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw bad_alloc (out of memory): %hs",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id),
                                    e.what());
                            }
                        }
                        catch (const std::runtime_error& e) {
                            if (m_config.enableLogging) {
                                SS_LOG_DEBUG(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw runtime_error: %hs",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id),
                                    e.what());
                            }
                        }
                        catch (const std::exception& e) {
                            if (m_config.enableLogging) {
                                SS_LOG_DEBUG(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw exception: %hs",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id),
                                    e.what());
                            }
                        }
                        catch (...) {
                            if (m_config.enableLogging) {
                                SS_LOG_DEBUG(L"ThreadPool",
                                    L"Worker %zu: Task %llu threw unknown exception",
                                    threadIndex,
                                    static_cast<unsigned long long>(task.id));
                            }
                        }

                        auto endTime = std::chrono::steady_clock::now();
                        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

                        m_totalExecutionTimeMs.fetch_add(static_cast<uint64_t>(durationMs), std::memory_order_relaxed);
                        m_totalTasksProcessed.fetch_add(1, std::memory_order_relaxed);
                        m_activeThreads.fetch_sub(1, std::memory_order_release);

                        m_waitAllCv.notify_all();

                        if (m_etwProvider != 0) {
                            ULONGLONG taskId = static_cast<ULONGLONG>(task.id);
                            ULONG threadIdx = static_cast<ULONG>(threadIndex);
                            ULONGLONG durationUL = static_cast<ULONGLONG>(durationMs);

                            EVENT_DATA_DESCRIPTOR eventData[3];
                            EventDataDescCreate(&eventData[0], &taskId, sizeof(taskId));
                            EventDataDescCreate(&eventData[1], &threadIdx, sizeof(threadIdx));
                            EventDataDescCreate(&eventData[2], &durationUL, sizeof(durationUL));

                            EventWrite(m_etwProvider, &g_evt_TaskCompleted, _countof(eventData), eventData);
                        }

                        if (m_config.enableLogging &&
                            (durationMs > 1000 || task.priority == TaskPriority::Critical)) {
                            SS_LOG_DEBUG(L"ThreadPool",
                                L"Task %llu completed in %lld ms (priority: %d, success: %d)",
                                static_cast<unsigned long long>(task.id),
                                static_cast<long long>(durationMs),
                                static_cast<int>(task.priority),
                                taskSucceeded ? 1 : 0);
                        }

                        // Best-effort stats update
                        try { updateStatistics(); }
                        catch (...) {}
                    }
                }

                if (m_config.enableLogging) {
                    SS_LOG_DEBUG(L"ThreadPool", L"Thread %zu exiting normally", threadIndex);
                }

                if (m_etwProvider != 0) {
                    ULONG threadIdx = static_cast<ULONG>(threadIndex);
                    EVENT_DATA_DESCRIPTOR eventData[1];
                    EventDataDescCreate(&eventData[0], &threadIdx, sizeof(threadIdx));
                    EventWrite(m_etwProvider, &g_evt_ThreadDestroyed, _countof(eventData), eventData);
                }
            }
            catch (const std::exception& e) {
                if (m_config.enableLogging) {
                    SS_LOG_ERROR(L"ThreadPool", L"CRITICAL: Worker thread %zu crashed: %hs", threadIndex, e.what());
                }
                size_t activeCount = m_activeThreads.load(std::memory_order_acquire);
                if (activeCount > 0) m_activeThreads.fetch_sub(1, std::memory_order_release);
            }
            catch (...) {
                if (m_config.enableLogging) {
                    SS_LOG_ERROR(L"ThreadPool", L"CRITICAL: Worker thread %zu crashed with unknown exception", threadIndex);
                }
                size_t activeCount = m_activeThreads.load(std::memory_order_acquire);
                if (activeCount > 0) m_activeThreads.fetch_sub(1, std::memory_order_release);
            }
        }

        ThreadPool::Task ThreadPool::getNextTask()
        {
            // Debug-mode check: caller should hold m_queueMutex. If not, warn and try to recover.
#if defined(_DEBUG)
    // try to acquire; if we succeed, that means caller didn't hold it
            if (m_queueMutex.try_lock()) {
                // we unexpectedly acquired the lock -> caller did not hold it
                if (m_config.enableLogging) {
                    SS_LOG_WARN(L"ThreadPool", L"getNextTask called without owning m_queueMutex (recovering).");
                }
                // release and proceed to attempt safe path
                m_queueMutex.unlock();

                // Safe fallback: lock and pop
                std::lock_guard<std::mutex> guard(m_queueMutex);
                if (!m_criticalPriorityQueue.empty()) {
                    Task task = std::move(m_criticalPriorityQueue.front());
                    m_criticalPriorityQueue.pop_front();
                    return task;
                }
                if (!m_highPriorityQueue.empty()) {
                    Task task = std::move(m_highPriorityQueue.front());
                    m_highPriorityQueue.pop_front();
                    return task;
                }
                if (!m_normalPriorityQueue.empty()) {
                    Task task = std::move(m_normalPriorityQueue.front());
                    m_normalPriorityQueue.pop_front();
                    return task;
                }
                if (!m_lowPriorityQueue.empty()) {
                    Task task = std::move(m_lowPriorityQueue.front());
                    m_lowPriorityQueue.pop_front();
                    return task;
                }
                return Task(0, 0, TaskPriority::Normal, nullptr);
            }
#endif

            // Normal (expected) path: caller already holds the queue mutex
            if (!m_criticalPriorityQueue.empty()) {
                Task task = std::move(m_criticalPriorityQueue.front());
                m_criticalPriorityQueue.pop_front();
                return task;
            }

            if (!m_highPriorityQueue.empty()) {
                Task task = std::move(m_highPriorityQueue.front());
                m_highPriorityQueue.pop_front();
                return task;
            }

            if (!m_normalPriorityQueue.empty()) {
                Task task = std::move(m_normalPriorityQueue.front());
                m_normalPriorityQueue.pop_front();
                return task;
            }

            if (!m_lowPriorityQueue.empty()) {
                Task task = std::move(m_lowPriorityQueue.front());
                m_lowPriorityQueue.pop_front();
                return task;
            }

            return Task(0, 0, TaskPriority::Normal, nullptr);
        }
        void ThreadPool::registerETWProvider()
        {
            if (m_etwProvider == 0) {
                ULONG result = EventRegister(&ShadowStrikeThreadPoolProvider, nullptr, nullptr, &m_etwProvider);
                if (result != ERROR_SUCCESS) {
                    if (m_config.enableLogging) {
                        SS_LOG_WARN(L"ThreadPool", L"Failed to register ETW provider, error: %lu", result);
                    }
                    m_etwProvider = 0;
                }
                else if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ETW provider registered successfully");
                }
            }
        }

        void ThreadPool::unregisterETWProvider()
        {
            if (m_etwProvider != 0) {
                EventUnregister(m_etwProvider);
                m_etwProvider = 0;

                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ETW provider unregistered");
                }
            }
        }

        void ThreadPool::updateStatistics()
        {
            // Hold queue mutex (primary resource for queues/stats)
            std::lock_guard<std::mutex> lock(m_queueMutex);

            // Read queue-related counters safely (under queue mutex)
            size_t pendingHigh = m_criticalPriorityQueue.size() + m_highPriorityQueue.size();
            size_t pendingNormal = m_normalPriorityQueue.size();
            size_t pendingLow = m_lowPriorityQueue.size();

            // Try to read real thread count if we can quickly acquire container mutex.
            // We do NOT block waiting for the container mutex to avoid deadlocks with submit/resize paths
            size_t threadCount = 0;
            {
                std::unique_lock<std::mutex> tlk(m_threadContainerMutex, std::try_to_lock);
                if (tlk.owns_lock()) {
                    threadCount = m_threads.size();
                }
                else {
                    // fallback: use last-known config value (keeps us safe without blocking)
                    threadCount = m_config.threadCount;
                }
            }

            // Snapshot atomics under the queue lock (safe)
            size_t totalProcessed = static_cast<size_t>(m_totalTasksProcessed.load(std::memory_order_relaxed));
            size_t peak = static_cast<size_t>(m_peakQueueSize.load(std::memory_order_relaxed));
            uint64_t totalTime = m_totalExecutionTimeMs.load(std::memory_order_relaxed);
            size_t active = static_cast<size_t>(m_activeThreads.load(std::memory_order_relaxed));

            // Store into shared m_stats while still holding queue mutex
            m_stats.threadCount = threadCount;
            m_stats.activeThreads = active;
            m_stats.pendingHighPriorityTasks = pendingHigh;
            m_stats.pendingNormalTasks = pendingNormal;
            m_stats.pendingLowPriorityTasks = pendingLow;
            m_stats.totalTasksProcessed = totalProcessed;
            m_stats.peakQueueSize = peak;
            if (totalProcessed > 0) {
                m_stats.avgExecutionTimeMs = static_cast<double>(totalTime) / static_cast<double>(totalProcessed);
            }
            else {
                m_stats.avgExecutionTimeMs = 0.0;
            }

            size_t estimatedTaskSize = sizeof(Task) * 3;
            m_stats.memoryUsage = (pendingHigh + pendingNormal + pendingLow) * estimatedTaskSize;
        }
        ThreadPoolStatistics ThreadPool::getStatistics() const
        {
            ThreadPoolStatistics snapshot;

            // Acquire queue mutex first (protects queues and provides consistent snapshot)
            std::lock_guard<std::mutex> lock(m_queueMutex);

            // Snapshot queue-related sizes
            snapshot.pendingHighPriorityTasks = m_criticalPriorityQueue.size() + m_highPriorityQueue.size();
            snapshot.pendingNormalTasks = m_normalPriorityQueue.size();
            snapshot.pendingLowPriorityTasks = m_lowPriorityQueue.size();

            // Snapshot atomics
            snapshot.totalTasksProcessed = static_cast<size_t>(m_totalTasksProcessed.load(std::memory_order_acquire));
            snapshot.peakQueueSize = static_cast<size_t>(m_peakQueueSize.load(std::memory_order_acquire));
            snapshot.activeThreads = static_cast<size_t>(m_activeThreads.load(std::memory_order_acquire));

            // Try to obtain real thread count but don't block if container mutex is held elsewhere.
            {
                std::unique_lock<std::mutex> tlk(m_threadContainerMutex, std::try_to_lock);
                if (tlk.owns_lock()) {
                    snapshot.threadCount = m_threads.size();
                }
                else {
                    snapshot.threadCount = m_config.threadCount;
                }
            }

            // Compute avg time safely (atomic read)
            uint64_t totalTime = m_totalExecutionTimeMs.load(std::memory_order_acquire);
            if (snapshot.totalTasksProcessed > 0) {
                snapshot.avgExecutionTimeMs = static_cast<double>(totalTime) / static_cast<double>(snapshot.totalTasksProcessed);
            }
            else {
                snapshot.avgExecutionTimeMs = 0.0;
            }

            size_t estimatedTaskSize = sizeof(Task) * 3;
            snapshot.memoryUsage = (snapshot.pendingHighPriorityTasks + snapshot.pendingNormalTasks + snapshot.pendingLowPriorityTasks) * estimatedTaskSize;

            return snapshot;
        }
        size_t ThreadPool::activeThreadCount() const noexcept
        {
            return m_activeThreads.load(std::memory_order_relaxed);
        }

        size_t ThreadPool::queueSize() const noexcept
        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            return m_criticalPriorityQueue.size() + m_highPriorityQueue.size() + 
                   m_normalPriorityQueue.size() + m_lowPriorityQueue.size();
        }

        size_t ThreadPool::threadCount() const noexcept
        {
            std::lock_guard<std::mutex> lk(m_threadContainerMutex);
            return m_threads.size();
        }

        bool ThreadPool::isActive() const noexcept
        {
            return !m_shutdown.load(std::memory_order_relaxed);
        }

        bool ThreadPool::isPaused() const noexcept
        {
            return m_paused.load(std::memory_order_relaxed);
        }

        void ThreadPool::pause()
        {
            bool expected = false;
            if (m_paused.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
               
                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ThreadPool paused");
                }

                // Notify threads to re-check pause state
                m_taskCv.notify_all();

                // ETW event
                if (m_etwProvider != 0) {
                    EVENT_DATA_DESCRIPTOR eventData[1];
                    ULONG queueSz = static_cast<ULONG>(queueSize());
                    EventDataDescCreate(&eventData[0], &queueSz, sizeof(queueSz));

                    EventWrite(m_etwProvider, &g_evt_Paused, _countof(eventData), eventData);
                }
            }
        }

        void ThreadPool::resume()
        {
            bool expected = true;
            if (m_paused.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
                m_taskCv.notify_all();

                if (m_config.enableLogging) {
                    SS_LOG_INFO(L"ThreadPool", L"ThreadPool resumed");
                }

                if (m_etwProvider != 0) {
                    EventWrite(m_etwProvider, &g_evt_Resumed, 0, nullptr);
                }
            }
        }


        void ThreadPool::shutdown(bool wait)
        {
            bool expected = false;
            if (!m_shutdown.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
                if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"Shutdown already in progress");
                return;
            }

            if (m_config.enableLogging) SS_LOG_INFO(L"ThreadPool", L"ThreadPool shutting down (wait=%s)...", wait ? L"true" : L"false");

            // Wake up workers first so they can notice shutdown.
            m_taskCv.notify_all();
            m_waitAllCv.notify_all();

            std::vector<std::thread> localThreads;
            std::vector<HANDLE> localHandles;

            if (wait) {
                // Wait bounded for pending tasks to complete
                {
                    std::unique_lock<std::mutex> lock(m_queueMutex);
                    if (m_paused.load(std::memory_order_acquire)) {
                        m_paused.store(false, std::memory_order_release);
                        m_taskCv.notify_all();
                    }

                    constexpr auto WAIT_TASKS_TIMEOUT = std::chrono::seconds(5);
                    m_waitAllCv.wait_for(lock, WAIT_TASKS_TIMEOUT, [this]() {
                        return m_criticalPriorityQueue.empty() &&
                            m_highPriorityQueue.empty() &&
                            m_normalPriorityQueue.empty() &&
                            m_lowPriorityQueue.empty() &&
                            m_activeThreads.load(std::memory_order_acquire) == 0;
                        });
                }

                // Snapshot thread containers under container mutex (short lock)
                {
                    std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                    localThreads = std::move(m_threads);
                    localHandles = std::move(m_threadHandles);
                }

                if (localHandles.size() < localThreads.size()) {
                    localHandles.resize(localThreads.size(), nullptr);
                }

                // Join/detach logic: wait for OS thread termination using handles where available
                constexpr auto JOIN_TIMEOUT = std::chrono::seconds(5);
                auto deadline = std::chrono::steady_clock::now() + JOIN_TIMEOUT;

                for (size_t i = 0; i < localThreads.size(); ++i) {
                    auto& th = localThreads[i];

                    if (!th.joinable()) {
                        if (i < localHandles.size()) localHandles[i] = nullptr;
                        continue;
                    }

                    auto timeRemaining = deadline - std::chrono::steady_clock::now();
                    if (timeRemaining <= std::chrono::seconds(0)) {
                        if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"Thread %zu join timeout - detaching", i);
                        if (i < localHandles.size() && localHandles[i]) {
                            safe_close_handle(localHandles[i], m_config.enableLogging);
                            localHandles[i] = nullptr;
                        }
                        try { th.detach(); }
                        catch (...) {}
                        continue;
                    }

                    auto ms64 = std::chrono::duration_cast<std::chrono::milliseconds>(timeRemaining).count();
                    DWORD waitMs = (ms64 <= 0) ? 0 : (ms64 >= static_cast<long long>(INFINITE) ? INFINITE : static_cast<DWORD>(ms64));

                    if (i < localHandles.size() && localHandles[i]) {
                        DWORD r = ::WaitForSingleObject(localHandles[i], waitMs);
                        if (r == WAIT_OBJECT_0) {
                            try { if (th.joinable()) th.join(); }
                            catch (...) {}
                            if (i < localHandles.size()) localHandles[i] = nullptr;
                        }
                        else {
                            if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"Thread %zu did not exit in time, detaching", i);
                            try { if (th.joinable()) th.detach(); }
                            catch (...) {}
                            if (localHandles[i]) { safe_close_handle(localHandles[i], m_config.enableLogging); localHandles[i] = nullptr; }
                        }
                    }
                    else {
                        // fallback: poll join briefly then detach
                        auto joinStart = std::chrono::steady_clock::now();
                        auto maxWait = std::chrono::milliseconds(waitMs);
                        while (std::chrono::steady_clock::now() - joinStart < maxWait) {
                            if (!th.joinable()) break;
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                        if (th.joinable()) {
                            try { th.detach(); }
                            catch (...) {}
                        }
                    }
                }
            }
            else {
                // Fast non-wait shutdown: snapshot and detach/close immediately
                {
                    std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                    localThreads = std::move(m_threads);
                    localHandles = std::move(m_threadHandles);
                }

                for (size_t i = 0; i < localThreads.size(); ++i) {
                    try { if (localThreads[i].joinable()) localThreads[i].detach(); }
                    catch (...) {}
                    if (i < localHandles.size() && localHandles[i]) {
                        safe_close_handle(localHandles[i], m_config.enableLogging);
                        localHandles[i] = nullptr;
                    }
                }
            }

            // Close remaining handles conservative
            for (auto h : localHandles) {
                safe_close_handle(h, m_config.enableLogging);
            }

            // Ensure members are cleared under container lock
            {
                std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                m_threads.clear();
                m_threadHandles.clear();
            }

            // Clear queues under queue mutex
            {
                std::lock_guard<std::mutex> lk(m_queueMutex);
                m_criticalPriorityQueue.clear();
                m_highPriorityQueue.clear();
                m_normalPriorityQueue.clear();
                m_lowPriorityQueue.clear();
            }

            if (m_etwProvider != 0) {
                ULONG totalTasks = static_cast<ULONG>(m_totalTasksProcessed.load(std::memory_order_relaxed));
                EVENT_DATA_DESCRIPTOR eventData[1];
                EventDataDescCreate(&eventData[0], &totalTasks, sizeof(totalTasks));
                EventWrite(m_etwProvider, &g_evt_ThreadPoolDestroyed, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"ThreadPool shut down successfully, processed %llu tasks",
                    static_cast<unsigned long long>(m_totalTasksProcessed.load(std::memory_order_relaxed)));
            }
        }


        
        void ThreadPool::resize(size_t newThreadCount)
        {
            // Fast-path: nothing to do
            {
                std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                if (newThreadCount == 0 || newThreadCount == m_threads.size()) return;
            }

            if (m_shutdown.load(std::memory_order_acquire)) {
                if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"Cannot resize during shutdown");
                return;
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Resizing thread pool to %zu", newThreadCount);
            }

            // ---------- INCREASE ----------
            bool didIncrease = false;
            {
                std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                size_t oldCount = m_threads.size();
                if (newThreadCount > oldCount) {
                    size_t toAdd = newThreadCount - oldCount;
                    for (size_t k = 0; k < toAdd; ++k) {
                        size_t threadIndex = m_threads.size();

                        std::thread t([this, threadIndex]() noexcept {
                            try {
                                std::unique_lock<std::mutex> lk(m_startMutex);
                                m_startCv.wait(lk, [this]() {
                                    return m_startReady.load(std::memory_order_acquire) ||
                                        m_shutdown.load(std::memory_order_acquire);
                                    });
                                if (m_shutdown.load(std::memory_order_acquire)) return;
                                workerThread(threadIndex);
                            }
                            catch (...) { /* swallow */ }
                            });

                        HANDLE th = nullptr;
                        try { th = t.native_handle(); }
                        catch (...) { th = nullptr; }

                        if (!th || th == INVALID_HANDLE_VALUE) {
                            if (m_config.enableLogging) SS_LOG_ERROR(L"ThreadPool", L"Invalid handle for new thread %zu", threadIndex);
                            try { if (t.joinable()) t.detach(); }
                            catch (...) {}
                            continue;
                        }

                        m_threads.push_back(std::move(t));
                        m_threadHandles.push_back(th);

                        try { initializeThread(m_threads.size() - 1); }
                        catch (...) {}
                    }

                    {
                        std::lock_guard<std::mutex> ql(m_queueMutex);
                        m_config.threadCount = m_threads.size();
                    }

                    if (m_config.enableLogging) SS_LOG_INFO(L"ThreadPool", L"Added %zu threads", m_threads.size() - oldCount);
                    didIncrease = true;
                }
            } // unlock m_threadContainerMutex

            if (didIncrease) {
#ifndef NDEBUG
                try { validateInternalState(); }
                catch (...) { throw; }
#endif
                return;
            }

            // ---------- DECREASE ----------
            std::vector<std::thread> removedThreads;
            std::vector<HANDLE> removedHandles;

            {
                std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                size_t oldCount = m_threads.size();
                if (newThreadCount >= oldCount) return; // raced

                size_t toRemove = oldCount - newThreadCount;
                removedThreads.reserve(toRemove);
                removedHandles.reserve(toRemove);

                // remove from end (LIFO)
                for (size_t i = 0; i < toRemove; ++i) {
                    // defensive compute index
                    if (m_threads.empty()) {
                        removedThreads.emplace_back(); // placeholder
                        removedHandles.push_back(nullptr);
                        continue;
                    }

                    size_t idx = m_threads.size() - 1;

                    // move thread
                    try {
                        removedThreads.push_back(std::move(m_threads.back()));
                    }
                    catch (...) {
                        try { if (m_threads.back().joinable()) m_threads.back().detach(); }
                        catch (...) {}
                        removedThreads.emplace_back();
                    }

                    // move handle if available
                    if (idx < m_threadHandles.size()) {
                        removedHandles.push_back(m_threadHandles[idx]);
                        m_threadHandles[idx] = nullptr;
                        try { m_threadHandles.pop_back(); }
                        catch (...) {}
                    }
                    else {
                        removedHandles.push_back(nullptr);
                    }

                    // pop thread object
                    try { m_threads.pop_back(); }
                    catch (...) {}
                }

                // update config.threadCount under queue mutex
                {
                    std::lock_guard<std::mutex> ql(m_queueMutex);
                    m_config.threadCount = m_threads.size();
                }

                m_startCv.notify_all();
            } // unlock container mutex

            // Wait/join removed threads outside container lock
            constexpr DWORD JOIN_WAIT_MS = 1000;
            for (size_t i = 0; i < removedThreads.size(); ++i) {
                std::thread& t = removedThreads[i];
                HANDLE h = (i < removedHandles.size()) ? removedHandles[i] : nullptr;
                bool joined = false;

                if (h && h != INVALID_HANDLE_VALUE) {
                    DWORD r = ::WaitForSingleObject(h, JOIN_WAIT_MS);
                    if (r == WAIT_OBJECT_0) {
                        try { if (t.joinable()) t.join(); }
                        catch (...) {}
                        joined = true;
                    }
                    else {
                        if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"Thread did not exit within %u ms; will detach", JOIN_WAIT_MS);
                    }
                }
                else {
                    if (t.joinable()) {
                        auto start = std::chrono::steady_clock::now();
                        auto maxWait = std::chrono::milliseconds(JOIN_WAIT_MS);
                        while (std::chrono::steady_clock::now() - start < maxWait) {
                            if (!t.joinable()) break;
                            std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        }
                        if (!t.joinable()) {
                            try { if (t.joinable()) t.join(); }
                            catch (...) {}
                            joined = true;
                        }
                        else {
                            if (m_config.enableLogging) SS_LOG_WARN(L"ThreadPool", L"Thread still joinable after polling; will detach");
                        }
                    }
                    else {
                        joined = true;
                    }
                }

                if (!joined) {
                    try { if (t.joinable()) t.detach(); }
                    catch (...) {}
                }

                // close handle safely
                if (h && h != INVALID_HANDLE_VALUE) {
                    HANDLE dup = nullptr;
                    BOOL dupOk = ::DuplicateHandle(::GetCurrentProcess(), h, ::GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
                    if (dupOk) {
                        ::CloseHandle(dup);
                        ::CloseHandle(h);
                    }
                    else {
                        if (m_config.enableLogging) {
                            DWORD err = ::GetLastError();
                            SS_LOG_WARN(L"ThreadPool", L"CloseHandle skipped: DuplicateHandle failed (err=%lu) for handle %p", err, h);
                        }
                    }
                    if (i < removedHandles.size()) removedHandles[i] = nullptr;
                }
            }

            // release local removed vectors
            removedThreads.clear();
            removedHandles.clear();

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Resized down to %zu threads", m_threads.size());
            }

#ifndef NDEBUG
            try { validateInternalState(); }
            catch (...) { throw; }
#endif
        }


        TaskGroupId ThreadPool::createTaskGroup(const std::wstring& groupName)
        {
            std::lock_guard<std::mutex> lock(m_groupMutex);

            TaskGroupId groupId = m_nextGroupId.fetch_add(1, std::memory_order_relaxed);
            auto group = std::make_shared<TaskGroup>();
            group->name = groupName.empty() ? L"Group-" + std::to_wstring(groupId) : groupName;

            m_taskGroups[groupId] = group;

            // Make local copy to ensure pointer stays valid during ETW call
            std::wstring groupNameCopy = group->name;

            // ETW event
            if (m_etwProvider != 0) {
                EVENT_DATA_DESCRIPTOR eventData[2];
                ULONGLONG groupIdUL = static_cast<ULONGLONG>(groupId);
                
                // Use local copy pointer (guaranteed valid for this scope)
                const wchar_t* namePtr = groupNameCopy.c_str();
                ULONG nameBytes = static_cast<ULONG>((groupNameCopy.length() + 1) * sizeof(wchar_t));
                
                EventDataDescCreate(&eventData[0], &groupIdUL, sizeof(groupIdUL));
                EventDataDescCreate(&eventData[1], namePtr, nameBytes);
                EventWrite(m_etwProvider, &g_evt_GroupCreated, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_DEBUG(L"ThreadPool", L"Created task group %llu: %s",
                    static_cast<unsigned long long>(groupId), groupNameCopy.c_str());
            }

            return groupId;
        }

        std::optional<ThreadPool::TaskGroupInfo> ThreadPool::getTaskGroupInfo(TaskGroupId groupId) const
        {
            std::lock_guard<std::mutex> lock(m_groupMutex);

            auto it = m_taskGroups.find(groupId);
            if (it == m_taskGroups.end()) {
                return std::nullopt;
            }

            const auto& group = it->second;

            TaskGroupInfo info;
            info.id = groupId;
            info.name = group->name;
            info.pendingTasks = group->pendingTasks.load(std::memory_order_relaxed);
            info.completedTasks = group->completedTasks.load(std::memory_order_relaxed);
            info.isCancelled = group->isCancelled.load(std::memory_order_relaxed);

            return info;
        }

        void ThreadPool::waitForGroup(TaskGroupId groupId)
        {
            std::shared_ptr<TaskGroup> group;

            {
                std::lock_guard<std::mutex> lock(m_groupMutex);
                auto it = m_taskGroups.find(groupId);
                if (it == m_taskGroups.end()) {
                    throw std::invalid_argument("Invalid task group ID");
                }
                group = it->second;
            }

            
            // The pendingTasks counter is updated AFTER task execution in wrapper
            // This ensures we wait until ALL tasks complete (not just queued)
            
            // Wait on group's completion CV; use group's own mutex to avoid races
            std::unique_lock<std::mutex> lock(m_groupMutex);
            group->completionCv.wait(lock, [&group]() {
                // Wait until pendingTasks reaches zero
                // Wrapper decrements this AFTER task execution, then notifies
                return group->pendingTasks.load(std::memory_order_acquire) == 0;
            });

            // ETW event
            if (m_etwProvider != 0) {
                ULONGLONG groupIdUL = static_cast<ULONGLONG>(groupId);
                ULONG completed = static_cast<ULONG>(group->completedTasks.load(std::memory_order_relaxed));
                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], &groupIdUL, sizeof(groupIdUL));
                EventDataDescCreate(&eventData[1], &completed, sizeof(completed));
                EventWrite(m_etwProvider, &g_evt_GroupWaitComplete, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_DEBUG(L"ThreadPool", L"Completed waiting for task group %llu, completed tasks: %zu",
                    static_cast<unsigned long long>(groupId), group->completedTasks.load(std::memory_order_relaxed));
            }
        }

        void ThreadPool::cancelGroup(TaskGroupId groupId)
        {
            std::shared_ptr<TaskGroup> group;

            {
                std::lock_guard<std::mutex> lock(m_groupMutex);
                auto it = m_taskGroups.find(groupId);
                if (it == m_taskGroups.end()) {
                    throw std::invalid_argument("Invalid task group ID");
                }
                group = it->second;
            }

            group->isCancelled.store(true, std::memory_order_release);

            if (m_etwProvider != 0) {
                ULONGLONG groupIdUL = static_cast<ULONGLONG>(groupId);
                ULONG pending = static_cast<ULONG>(group->pendingTasks.load(std::memory_order_relaxed));
                EVENT_DATA_DESCRIPTOR eventData[2];
                EventDataDescCreate(&eventData[0], &groupIdUL, sizeof(groupIdUL));
                EventDataDescCreate(&eventData[1], &pending, sizeof(pending));
                EventWrite(m_etwProvider, &g_evt_GroupCancelled, _countof(eventData), eventData);
            }

            if (m_config.enableLogging) {
                SS_LOG_INFO(L"ThreadPool", L"Cancelled task group %llu, pending tasks: %zu",
                    static_cast<unsigned long long>(groupId), group->pendingTasks.load(std::memory_order_relaxed));
            }
        }
        void ThreadPool::waitForAll()
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            m_waitAllCv.wait(lock, [this]() {
                return (m_criticalPriorityQueue.empty() && m_highPriorityQueue.empty() &&
                    m_normalPriorityQueue.empty() && m_lowPriorityQueue.empty() &&
                    m_activeThreads.load(std::memory_order_acquire) == 0) ||
                    m_shutdown.load(std::memory_order_acquire);
                });

            if (m_config.enableLogging) {
                SS_LOG_DEBUG(L"ThreadPool", L"Completed waiting for all tasks");
            }
        }

        void ThreadPool::logThreadPoolEvent(const wchar_t* category, const wchar_t* format, ...)
        {
            if (!m_config.enableLogging) return;

            va_list args;
            va_start(args, format);
            std::wstring message = ShadowStrike::Utils::Logger::FormatMessageV(format, args);
            va_end(args);

            ShadowStrike::Utils::Logger::Instance().LogMessage(
                ShadowStrike::Utils::LogLevel::Debug,
                category,
                message
            );
        }


        void ThreadPool::validateInternalState() const
        {
#ifndef NDEBUG
            // Check that thread & handle vectors have same size
            {
                std::lock_guard<std::mutex> tlk(m_threadContainerMutex);
                if (m_threads.size() != m_threadHandles.size()) {
                    throw std::runtime_error("Invariant violated: m_threads.size() != m_threadHandles.size()");
                }
                // Optional: very cheap duplicate-handle check
                std::unordered_set<uintptr_t> seen;
                for (auto h : m_threadHandles) {
                    if (h && h != INVALID_HANDLE_VALUE) {
                        uintptr_t key = reinterpret_cast<uintptr_t>(h);
                        if (seen.find(key) != seen.end()) {
                            throw std::runtime_error("Invariant violated: duplicate native handle detected");
                        }
                        seen.insert(key);
                    }
                }
            }

            // Check queue sizes non-negative and peak not absurd
            {
                std::lock_guard<std::mutex> ql(m_queueMutex);
                size_t qsum = m_criticalPriorityQueue.size() + m_highPriorityQueue.size() +
                    m_normalPriorityQueue.size() + m_lowPriorityQueue.size();
                if (m_peakQueueSize.load(std::memory_order_relaxed) < qsum) {
                    // peak should not be less than current total (peak monotonic)
                    throw std::runtime_error("Invariant violated: peakQueueSize < current queue sum");
                }
#endif
            }
        }

    } // namespace Utils
} // namespace ShadowStrike
