
TO BUILD THE PROJECT COMPLETELY RUN THIS :   Bash(powershell.exe -Command "& 'C:\Program Files\Microsoft Visual
      Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe' C:\ShadowStrike\ShadowStrike\ShadowStrike.sln /p:Configuration=Debug /p:Platform=x64 /verbosity:minimal 2>&1")

 ShadowStrike NGAV - Enterprise C++ Implementation Agent Guide

     # 🛡️ ShadowStrike NGAV - C++ Implementation Standards

     **PROJECT CLASSIFICATION**: Enterprise-Grade NGAV (Next-Gen Antivirus)
     **TARGET COMPETITORS**: CrowdStrike Falcon, Kaspersky, BitDefender GravityZone
     **PRODUCTION STATUS**: Pre-Release Enterprise Product
     **CODE QUALITY TIER**: Mission-Critical (Used to protect enterprise endpoints globally)

     ---

     ## 🎯 PROJECT VISION

     ShadowStrike is building a **global, enterprise-class antivirus engine** to compete directly with CrowdStrike
   Falcon, Kaspersky, and BitDefender. This is not a hobby project - it's a billion-dollar vision implemented with
   enterprise-grade standards.

     Every line of code you write will be:
     - **Deployed to millions of endpoints** protecting businesses, hospitals, and critical infrastructure
     - **Subjected to rigorous security reviews** by enterprise security teams
     - **Expected to handle real-world threats** from advanced persistent threat (APT) groups
     - **Required to maintain 99.99% uptime** across diverse hardware configurations
     - **Audited for performance**, memory usage, and false positive rates

     Your .cpp implementations directly impact the security posture of Fortune 500 companies.

     ---

     ## 📊 PROJECT INFRASTRUCTURE - 233k+ Lines of Foundation Code

     The following production-grade infrastructure is ALREADY IMPLEMENTED and waiting for you to leverage:

     ### **Data Storage & Indexing**
     - `HashStore/` - Memory-mapped B+tree hash database (SSDeep, TLSH, SHA-256)
     - `PatternStore/` - Pattern/YARA signature indexing
     - `SignatureStore/` - Memory-mapped signature database with multi-threading
     - `ThreatIntel/` - Global threat intelligence with LRU caching and URL matching
     - `Whitelist/` - Hybrid model: memory-mapped files + heap trie indexing

     **Key Point**: These are NOT naive implementations. They use:
     - Memory-mapped I/O for sub-millisecond lookups
     - B+tree indices for O(log n) worst-case performance
     - LRU caches to reduce disk pressure
     - Lock-free data structures where possible
     - SIMD optimizations for pattern matching

     ### **Utility Foundation**
     - `Utils/Logger.hpp` - Structured logging with severity levels
     - `Utils/FileUtils.hpp` - Safe file operations with error handling
     - `Utils/CryptoUtils.hpp` - OpenSSL wrapper, encryption, hashing
     - `Utils/SystemUtils.hpp` - Windows system calls, performance monitoring
     - `Utils/NetworkUtils.hpp` - Winsock2 abstractions
     - `Utils/ProcessUtils.hpp` - Process enumeration, memory reading
     - `Utils/StringUtils.hpp` - UTF-8/UTF-16 conversions, sanitization
     - `Utils/XMLUtils.hpp` - Safe XML parsing (XPath injection protection)
     - `Utils/ThreadPool.hpp` - Managed thread pool with task queues
     - Plus 8 more utility modules

     **Your Responsibility**: Use these. Do NOT reinvent. Code reuse is not laziness - it's enterprise discipline.

     ---

     ## 🏗️ ARCHITECTURAL PATTERNS - MANDATORY

     ### **1. Singleton Pattern (Meyers' Singleton)**

     Every major module must implement this pattern:

     ```cpp
     // ✅ CORRECT - Thread-safe, exception-safe, ABI-stable
     class ScanEngine final {
     public:
         [[nodiscard]] static ScanEngine& Instance() noexcept {
             static ScanEngine instance;
             return instance;
         }

         // Deleted copy/move
         ScanEngine(const ScanEngine&) = delete;
         ScanEngine& operator=(const ScanEngine&) = delete;
         ScanEngine(ScanEngine&&) = delete;
         ScanEngine& operator=(ScanEngine&&) = delete;

     private:
         ScanEngine();  // Private constructor
         ~ScanEngine();
         static std::atomic<bool> s_instanceCreated;
     };

     // ❌ WRONG - Global pointer (thread-unsafe, ABI fragile)
     ScanEngine* g_scanEngine = nullptr;

     // ❌ WRONG - Double-checked locking (prone to bugs)
     if (!s_instance) {
         std::lock_guard lock(mutex);
         if (!s_instance) s_instance = new ScanEngine();
     }

   Why:

     - Thread-safe by design (no external locks needed)
     - Exception-safe (destructor called if exception during construction)
     - ABI-stable (no changes to layout across library versions)
     - Memory-safe (no manual allocation/deletion)

   2. PIMPL (Pointer to Implementation)

   Complex classes MUST use PIMPL to maintain ABI stability:

     // Header: Threat.hpp
     class ThreatDetector final {
     public:
         bool Analyze(const fs::path& filePath);
         std::optional<ThreatInfo> GetLastResult() const;

     private:
         std::unique_ptr<ThreatDetectorImpl> m_impl;  // ← All implementation hidden
     };

     // Implementation: Threat.cpp
     class ThreatDetectorImpl {
     public:
         bool Analyze(const fs::path& filePath);
         // Implementation details here
     private:
         // Private members - changes don't break ABI
         std::unordered_map<std::string, CachedResult> m_cache;
         // etc.
     };

   Why:

     - Adding new member variables doesn't change header size
     - Clients don't need to recompile when adding implementation details
     - Enterprise software evolves - this pattern makes it safe

   3. RAII (Resource Acquisition Is Initialization)

   Every resource (file, lock, memory) must be wrapped in an object:

     // ✅ CORRECT - Automatic cleanup
     {
         std::lock_guard lock(m_mutex);  // Lock acquired
         // Critical section
     }  // Lock automatically released, even if exception thrown

     // ❌ WRONG - Manual cleanup (forgettable, exception-unsafe)
     m_mutex.lock();
     // Critical section
     m_mutex.unlock();  // What if exception thrown?

   4. Thread Safety - Always Assume Multi-threaded

   The minifilter driver will call your code from arbitrary worker threads. ALWAYS:

     class QuarantineManager final {
     private:
         mutable std::shared_mutex m_mutex;  // NOT std::mutex
         std::vector<QuarantinedFile> m_files;

     public:
         [[nodiscard]] std::vector<QuarantinedFile> GetFiles() const {
             std::shared_lock lock(m_mutex);  // Read lock
             return m_files;  // Copy (thread-safe)
         }

         [[nodiscard]] bool Quarantine(const fs::path& path) {
             std::unique_lock lock(m_mutex);  // Write lock
             m_files.push_back({path});
             return true;
         }
     };

   Why std::shared_mutex? Multiple threads can read simultaneously. Only one writes.

   -------------------------------------------------------------------------------------------------------------------

   💎 C++20 MANDATORY FEATURES

   Your .cpp files MUST use modern C++20:

   [[nodiscard]] - Prevent ignoring important results

     [[nodiscard]] bool QuarantineManager::Quarantine(const fs::path& path);
     // ✅ Client must do: auto success = Quarantine(path);
     // ❌ Won't compile if client ignores: Quarantine(path);  // Compiler error!

   std::span<> - View over arrays (no copies)

     // ❌ OLD - Copies data
     bool AnalyzeBuffer(const std::vector<uint8_t> data);

     // ✅ NEW - Zero-copy view
     bool AnalyzeBuffer(std::span<const uint8_t> data);

   std::optional<> - Nullable values (no null pointers)

     // ❌ OLD - Can be nullptr
     std::string* GetThreatName() { return ptr; }

     // ✅ NEW - Type-safe, no segfaults
     std::optional<std::string> GetThreatName();

     // Usage
     if (auto name = GetThreatName()) {
         std::cout << *name;  // name is definitely set
     }

   std::atomic<> - Thread-safe counters

     // ❌ OLD - Race condition possible
     uint64_t m_threatCount = 0;  // Needs lock!

     // ✅ NEW - No lock needed
     std::atomic<uint64_t> m_threatCount{0};
     m_threatCount++;  // Thread-safe

   Structured Bindings - Clean unpacking

     // ✅ Clean
     auto [name, severity, family] = result.GetThreatInfo();

     // ❌ Verbose
     std::string name = result.GetThreatInfo().name;
     uint32_t severity = result.GetThreatInfo().severity;

   -------------------------------------------------------------------------------------------------------------------

   🎖️ ENTERPRISE-GRADE STANDARDS

   Rule #1: Never Simplify Error Handling

   Every Windows API call can fail. Handle it:

     // ✅ CORRECT
     [[nodiscard]] bool QuarantineManager::MoveToQuarantine(const fs::path& src) {
         try {
             if (!fs::exists(src)) {
                 Logger::Warn("File not found: {}", src.string());
                 return false;
             }

             auto dest = m_quarantineDir / src.filename();
             fs::rename(src, dest);

             Logger::Info("Quarantined: {}", dest.string());
             m_stats.filesQuarantined++;
             return true;

         } catch (const fs::filesystem_error& e) {
             Logger::Error("Quarantine failed [{}]: {}", e.code().value(), e.what());
             return false;
         } catch (...) {
             Logger::Critical("Unexpected error in quarantine");
             return false;
         }
     }

     // ❌ WRONG - Silently fails
     bool QuarantineManager::MoveToQuarantine(const fs::path& src) {
         fs::rename(src, m_quarantineDir / src.filename());
         return true;
     }

   Rule #2: Use Infrastructure

   Before writing any code, check if it exists in Utils/HashStore/PatternStore/ThreatIntel:

     // ✅ CORRECT - Using HashStore for lookups
     #include "../../HashStore/HashStore.hpp"

     bool ThreatDetector::Analyze(const fs::path& file) {
         auto hash = HashStore::CalculateSHA256(file);  // From infrastructure
         if (HashStore::Instance().IsKnownMalware(hash)) {
             return true;  // Detected!
         }
         // Continue with deeper analysis
     }

     // ❌ WRONG - Reimplementing hash lookup
     bool ThreatDetector::Analyze(const fs::path& file) {
         // Reading file manually, computing hash manually...
         // 500 lines of code that already exist in HashStore
     }

   Code Reuse is Enterprise Discipline.

   Rule #3: Implement Statistics

   Every module must track its performance:

     struct ThreatDetectorStatistics {
         std::atomic<uint64_t> filesAnalyzed{0};
         std::atomic<uint64_t> threatsDetected{0};
         std::atomic<uint64_t> falsePositives{0};
         std::atomic<uint64_t> totalAnalysisTimeUs{0};
         std::array<std::atomic<uint64_t>, 20> byThreatType{};
         TimePoint startTime = Clock::now();

         void Reset() noexcept;
         [[nodiscard]] double GetAverageAnalysisTimeMs() const noexcept;
         [[nodiscard]] std::string ToJson() const;
     };

     // Usage
     m_stats.filesAnalyzed++;
     m_stats.totalAnalysisTimeUs += (endTime - startTime).count();
     if (detected) m_stats.threatsDetected++;

   Why: Enterprise deployments need metrics. If 1M endpoints have 0.1% false positives, that's 1,000 false alarms per
   day. Tracking stats reveals problems.

   Rule #4: Support JSON Serialization

   All important structures must serialize to JSON for logging/reporting:

     [[nodiscard]] std::string ThreatInfo::ToJson() const {
         return nlohmann::json{
             {"name", name},
             {"severity", severity},
             {"family", family},
             {"detectionTime", std::chrono::system_clock::now().time_since_epoch().count()},
             {"indicators", indicators}
         }.dump();
     }

   Rule #5: Validate Input Obsessively

   Enterprise software is attacked. Assume all input is malicious:

     // ✅ CORRECT - Defensive
     bool QuarantineManager::Quarantine(const fs::path& path) {
         // Validate before using
         if (path.empty()) {
             Logger::Error("Quarantine: Empty path");
             return false;
         }

         if (path.string().length() > 32767) {  // Windows MAX_PATH
             Logger::Error("Quarantine: Path too long");
             return false;
         }

         if (!fs::exists(path)) {
             Logger::Error("Quarantine: File doesn't exist");
             return false;
         }

         if (IsInWhitelist(path)) {
             Logger::Warn("Quarantine: File is whitelisted");
             return false;
         }

         // NOW it's safe to proceed
     }

     // ❌ WRONG - Trusting input
     bool QuarantineManager::Quarantine(const fs::path& path) {
         fs::rename(path, m_quarantineDir / path.filename());
         return true;
     }

   -------------------------------------------------------------------------------------------------------------------

   🔐 SECURITY REQUIREMENTS

   Memory Safety

     - Use std::unique_ptr<> and std::shared_ptr<> - NO raw new/delete
     - Use std::string and std::vector - NO C-style arrays
     - Use std::span<> - NO pointer arithmetic
     - Bounds-check array access: m_array.at(i) not m_array[i]

   Information Disclosure Prevention

     - Never log sensitive data (passwords, encryption keys)
     - Sanitize file paths before logging
     - Don't leak memory addresses (ASLR bypass)

   Injection Attack Prevention

     - Use XMLUtils::isXPathSafe() before XPath queries
     - SQL injection: Use parameterized queries
     - Command injection: Use CreateProcessW() with argument array, NOT system()

   Denial of Service Prevention

     // ❌ WRONG - Could allocate 1 GB if file size is forged
     std::vector<uint8_t> buffer(file.size());

     // ✅ CORRECT - Cap allocation
     constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024;  // 100 MB
     if (file.size() > MAX_FILE_SIZE) {
         throw std::runtime_error("File too large");
     }
     std::vector<uint8_t> buffer(file.size());

   -------------------------------------------------------------------------------------------------------------------

   📋 IMPLEMENTATION CHECKLIST

   For EVERY .cpp file you write:

     - [ ]  PIMPL pattern: Implementation in separate class
     - [ ]  Thread-safety: std::shared_mutex for concurrent access
     - [ ]  Error handling: Try-catch, validation, logging
     - [ ]  Statistics: m_stats tracking calls, successes, failures
     - [ ]  Callbacks: Support for event notification (if applicable)
     - [ ]  Logging: Info, Warn, Error, Critical messages
     - [ ]  JSON export: ToJson() on important results
     - [ ]  Input validation: Check all parameters
     - [ ]  Memory safety: Smart pointers, no raw new/delete
     - [ ]  Performance: Minimize allocations, use std::span<> for views
     - [ ]  Testing: SelfTest() method that validates core functionality
     - [ ]  Documentation: Clear comments explaining complex logic

   -------------------------------------------------------------------------------------------------------------------

   🏢 COMPARISON WITH COMPETITORS

   ┌────────────────────────────┬───────────────────────┬────────────────┬────────────────┬────────────────┐
   │ Feature                    │ ShadowStrike          │ CrowdStrike    │ Kaspersky      │ BitDefender    │
   ├────────────────────────────┼───────────────────────┼────────────────┼────────────────┼────────────────┤
   │ Kernel-level protection    │ ✅ Minifilter         │ ✅ Driver      │ ✅ Driver      │ ✅ Driver      │
   ├────────────────────────────┼───────────────────────┼────────────────┼────────────────┼────────────────┤
   │ Machine Learning           │ ✅ Ensemble models    │ ✅ Yes         │ ✅ Yes         │ ✅ Yes         │
   ├────────────────────────────┼───────────────────────┼────────────────┼────────────────┼────────────────┤
   │ Sandbox analysis           │ ✅ Hyper-V            │ ✅ Proprietary │ ✅ Proprietary │ ✅ Proprietary │
   ├────────────────────────────┼───────────────────────┼────────────────┼────────────────┼────────────────┤
   │ Zero-day detection         │ ✅ ROP/shellcode      │ ✅ Yes         │ ✅ Yes         │ ✅ Yes         │
   ├────────────────────────────┼───────────────────────┼────────────────┼────────────────┼────────────────┤
   │ Open source infrastructure │ ✅ 233k LOC           │ ❌ Proprietary │ ❌ Proprietary │ ❌ Proprietary │
   ├────────────────────────────┼───────────────────────┼────────────────┼────────────────┼────────────────┤
   │ Enterprise grade           │ ✅ You're building it │ ✅ Yes         │ ✅ Yes         │ ✅ Yes         │
   └────────────────────────────┴───────────────────────┴────────────────┴────────────────┴────────────────┘

   -------------------------------------------------------------------------------------------------------------------

   🚀 YOUR MISSION

   You are responsible for .cpp implementations that:

     - Faithfully implement the .hpp contracts (signatures are non-negotiable)
     - Leverage infrastructure - reuse HashStore, PatternStore, ThreatIntel
     - Maintain ABI stability - use PIMPL, no public member variable changes
     - Handle errors gracefully - never crash, always log
     - Protect enterprise data - apply security principles religiously
     - Track everything - statistics on every operation
     - Test thoroughly - implement SelfTest() methods
     - Document clearly - explain non-obvious logic

   -------------------------------------------------------------------------------------------------------------------

   📚 REFERENCE STANDARDS

     - C++ Standard: C++20 (std::span, std::optional, concepts)
     - Threading: std::shared_mutex, std::atomic, lock_guard
     - Memory: Smart pointers only, no raw new/delete
     - Error handling: Exception-safe, RAII everywhere
     - Logging: 4 levels - Info, Warn, Error, Critical
     - Performance: Sub-millisecond for hash lookups, <100ms for scans

   -------------------------------------------------------------------------------------------------------------------

   ⚠️ CRITICAL REMINDERS

     - This is NOT hobby code. Enterprises will deploy it to protect critical infrastructure.
     - Every function should have [[nodiscard]] if ignoring the result is a mistake.
     - Every error should be logged with context for debugging.
     - Every data structure should serialize to JSON for diagnostics.
     - Every module should track statistics - operations, successes, failures, timing.
     - Thread safety is NOT optional - assume concurrent access from day one.
     - Memory safety is CRITICAL - use smart pointers, no buffer overflows.
     - Code reuse is discipline - use the 233k LOC infrastructure obsessively.

   -------------------------------------------------------------------------------------------------------------------

   🎯 SUCCESS CRITERIA

   Your .cpp implementation is enterprise-grade when:

     - ✅ It compiles with zero warnings (-Wall -Wextra -Wpedantic)
     - ✅ Every public function has [[nodiscard]] or void return
     - ✅ Thread-safe under concurrent stress
     - ✅ No memory leaks (valgrind clean)
     - ✅ All errors logged with context
     - ✅ Statistics tracked accurately
     - ✅ JSON serialization works
     - ✅ SelfTest() passes completely
     - ✅ Follows all architecture patterns (PIMPL, Singleton, RAII)
     - ✅ Uses infrastructure modules, never reinvents

   -------------------------------------------------------------------------------------------------------------------

   💬 FINAL WORDS

   You're building the next CrowdStrike. Every line of code matters. Every function call happens on millions of
   endpoints. Security researchers will audit your code. Enterprise customers will depend on your reliability.

   Write it like someone's business depends on it. Because it will.

   Welcome to enterprise-grade security software development.

   -------------------------------------------------------------------------------------------------------------------

   PROJECT: ShadowStrike NGAV VERSION: 3.0.0 STATUS: Pre-Release Enterprise QUALITY TIER: Mission-Critical COMPETITOR
   REFERENCE: CrowdStrike Falcon, Kaspersky, BitDefender

