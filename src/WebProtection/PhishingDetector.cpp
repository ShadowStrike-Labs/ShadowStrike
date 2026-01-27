#include "pch.h"
#include "PhishingDetector.hpp"
#include <regex>
#include <cmath>
#include <algorithm>
#include <future>
#include <sstream>
#include <iomanip>
#include <numeric>

// JSON support
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ShadowStrike::WebBrowser {

    // ============================================================================
    // STATIC DATA
    // ============================================================================

    std::atomic<bool> PhishingDetector::s_instanceCreated{false};

    // ============================================================================
    // IMPLEMENTATION CLASS
    // ============================================================================

    class PhishingDetectorImpl {
    public:
        PhishingDetectorConfiguration m_config;
        PhishingDetectorStatistics m_stats;
        mutable std::shared_mutex m_mutex;
        std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

        // Protected brands database: Brand Name -> List of legitimate domains
        std::unordered_map<std::string, std::vector<std::string>> m_protectedBrands;

        // Callbacks
        std::vector<PhishingDetectionCallback> m_detectionCallbacks;
        std::vector<BrandAlertCallback> m_brandCallbacks;
        std::vector<ErrorCallback> m_errorCallbacks;
        mutable std::shared_mutex m_callbackMutex;

        PhishingDetectorImpl() {
            // Default protected brands initialization
            for (const auto* brand : PhishingDetectorConstants::PROTECTED_BRANDS) {
                // Heuristic: brand.com is usually the legit domain
                m_protectedBrands[brand] = { std::string(brand) + ".com" };
            }
        }

        void LogError(const std::string& message, int code = 0) {
            Logger::Error("PhishingDetector: {}", message);

            std::shared_lock lock(m_callbackMutex);
            for (const auto& callback : m_errorCallbacks) {
                try {
                    callback(message, code);
                } catch (...) {}
            }
        }

        PhishingScore AnalyzeURLInternal(const std::string& url) {
            PhishingScore result;
            result.analysisDuration = std::chrono::microseconds(0);
            auto start = std::chrono::high_resolution_clock::now();

            // 1. Basic URL Parsing
            // NOTE: Ideally use NetworkUtils::ParseURL, implementing basic here for self-containment/demo
            // Simple regex for scheme://domain/path
            std::regex urlRegex(R"(^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?)");
            std::smatch urlMatch;

            if (std::regex_match(url, urlMatch, urlRegex)) {
                result.urlAnalysis.originalUrl = url;
                // Group 4 is authority (domain + port)
                std::string authority = urlMatch[4].str();

                // Extract port if present
                size_t colonPos = authority.find(':');
                if (colonPos != std::string::npos) {
                    result.urlAnalysis.domain = authority.substr(0, colonPos);
                    // result.urlAnalysis.port = ... parse port
                    result.urlAnalysis.hasPort = true;
                } else {
                    result.urlAnalysis.domain = authority;
                }

                result.urlAnalysis.path = urlMatch[5].str();
                result.urlAnalysis.query = urlMatch[7].str();
                result.urlAnalysis.isHTTPS = (urlMatch[2].str() == "https");

                // TLD extraction (simplistic)
                size_t lastDot = result.urlAnalysis.domain.rfind('.');
                if (lastDot != std::string::npos) {
                    result.urlAnalysis.tld = result.urlAnalysis.domain.substr(lastDot + 1);
                }

                // Subdomain count
                result.urlAnalysis.subdomainCount = (int)std::count(
                    result.urlAnalysis.domain.begin(),
                    result.urlAnalysis.domain.end(),
                    '.');
            }

            // 2. IP Address Check
            std::regex ipRegex(R"((\d{1,3}\.){3}\d{1,3})");
            if (std::regex_match(result.urlAnalysis.domain, ipRegex)) {
                result.urlAnalysis.isIPAddress = true;
                result.indicators = (PhishingIndicator)((uint32_t)result.indicators | (uint32_t)PhishingIndicator::IPAddressURL);
                result.allReasons.push_back("URL uses IP address instead of domain");
                result.score += 0.2;
            }

            // 3. Length Check
            result.urlAnalysis.urlLength = url.length();
            if (result.urlAnalysis.urlLength > 75) {
                result.indicators = (PhishingIndicator)((uint32_t)result.indicators | (uint32_t)PhishingIndicator::LongURL);
                result.score += 0.1;
            }

            // 4. Entropy Check
            result.urlAnalysis.entropyScore = CalculateEntropy(result.urlAnalysis.domain);
            if (result.urlAnalysis.entropyScore > 4.5) { // High entropy -> DGA or random
                 result.indicators = (PhishingIndicator)((uint32_t)result.indicators | (uint32_t)PhishingIndicator::DGADomain);
                 result.allReasons.push_back("Domain has high entropy (possible DGA)");
                 result.score += 0.2;
            }

            // 5. Homograph Check
            auto homographRes = CheckHomographInternal(result.urlAnalysis.domain);
            result.homographResult = homographRes;
            if (homographRes.hasHomograph) {
                result.indicators = (PhishingIndicator)((uint32_t)result.indicators | (uint32_t)PhishingIndicator::HomographAttack);
                result.allReasons.push_back("Homograph attack detected targeting " + homographRes.targetedBrand);
                result.score += 0.8; // High confidence
            }

            // 6. Typosquatting Check
            auto typoRes = CheckTyposquattingInternal(result.urlAnalysis.domain);
            result.typosquattingResult = typoRes;
            if (typoRes.isTyposquatting) {
                result.indicators = (PhishingIndicator)((uint32_t)result.indicators | (uint32_t)PhishingIndicator::Typosquatting);
                result.allReasons.push_back("Typosquatting detected targeting " + typoRes.targetBrand);
                result.score += 0.6;
                result.targetedBrand = typoRes.targetBrand;
            }

            // 7. Threat Intel Check
            if (m_config.checkThreatIntel) {
                // Using infrastructure
                // Note: Assuming ThreatIntelManager has IsPhishingUrl or similar
                // For now, simulate or use generic IsMalicious
                /*
                if (ThreatIntelManager::Instance().IsKnownMalicious(url)) {
                    result.indicators |= PhishingIndicator::ThreatIntelMatch;
                    result.allReasons.push_back("URL found in Threat Intelligence database");
                    result.score = 1.0;
                    result.verdict = PhishingVerdict::KnownBad;
                }
                */
            }

            // Calculate final verdict
            if (result.score >= m_config.phishingThreshold) {
                result.isPhishing = true;
                result.verdict = PhishingVerdict::Phishing;
                result.reason = "Multiple phishing indicators detected";
            } else if (result.score >= m_config.suspiciousThreshold) {
                result.verdict = PhishingVerdict::Suspicious;
                result.reason = "Suspicious characteristics detected";
            }

            result.confidence = (int)(result.score * 100);
            if (result.confidence > 100) result.confidence = 100;

            auto end = std::chrono::high_resolution_clock::now();
            result.analysisDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

            return result;
        }

        HomographResult CheckHomographInternal(const std::string& domain) {
            HomographResult result;
            result.originalDomain = domain;

            std::wstring wDomain = StringUtils::ToWide(domain);

            // Iterate through domain characters
            for (wchar_t c : wDomain) {
                for (const auto& pair : PhishingDetectorConstants::HOMOGRAPH_CHARS) {
                    if (c == pair[0]) {
                        result.hasHomograph = true;
                        result.confusables.push_back({c, (char)pair[1]});
                    }
                }
            }

            if (result.hasHomograph) {
                // Try to reconstruct "normalized" domain (replacing cyrillic with latin)
                std::wstring normalized = wDomain;
                for (auto& c : normalized) {
                     for (const auto& pair : PhishingDetectorConstants::HOMOGRAPH_CHARS) {
                        if (c == pair[0]) c = (wchar_t)pair[1];
                     }
                }
                result.decodedDomain = StringUtils::ToUtf8(normalized);
                result.similarityScore = 1.0; // It's a visual match

                // Check if the normalized domain is a protected brand
                // Simple containment check for now
                std::shared_lock lock(m_mutex);
                for (const auto& [brand, domains] : m_protectedBrands) {
                    for (const auto& legit : domains) {
                        if (result.decodedDomain.find(legit) != std::string::npos) {
                            result.targetedBrand = brand;
                            break;
                        }
                    }
                }
            }

            return result;
        }

        TyposquattingResult CheckTyposquattingInternal(const std::string& domain) {
            TyposquattingResult result;
            result.suspiciousDomain = domain;

            std::shared_lock lock(m_mutex);

            int minDistance = 1000;
            std::string bestMatchBrand;
            std::string bestMatchDomain;

            for (const auto& [brand, domains] : m_protectedBrands) {
                for (const auto& legit : domains) {
                    // Skip if exact match
                    if (domain == legit) continue;

                    int dist = LevenshteinDistance(domain, legit);

                    // Normalize by length
                    double similarity = 1.0 - ((double)dist / (double)std::max(domain.length(), legit.length()));

                    if (similarity > 0.8) { // Threshold for "close enough"
                        if (dist < minDistance) {
                            minDistance = dist;
                            bestMatchBrand = brand;
                            bestMatchDomain = legit;
                            result.similarityScore = similarity;
                        }
                    }
                }
            }

            if (!bestMatchBrand.empty()) {
                result.isTyposquatting = true;
                result.targetBrand = bestMatchBrand;
                result.targetDomain = bestMatchDomain;
                result.editDistance = minDistance;
                result.typoType = "Levenshtein Similarity";
            }

            return result;
        }

        FormAnalysisResult AnalyzeFormsInternal(const std::string& html) {
            FormAnalysisResult result;

            // Basic regex-based HTML parsing (robust enough for simple checks,
            // but not a full parser replacement)

            // 1. Detect Forms
            std::regex formRegex(R"(<form[^>]*>)");
            auto formsBegin = std::sregex_iterator(html.begin(), html.end(), formRegex);
            auto formsEnd = std::sregex_iterator();
            result.formCount = (int)std::distance(formsBegin, formsEnd);

            // 2. Detect Password Fields
            std::regex pwdRegex(R"(type=["']password["'])", std::regex_constants::icase);
            auto pwdBegin = std::sregex_iterator(html.begin(), html.end(), pwdRegex);
            result.passwordFieldCount = (int)std::distance(pwdBegin, std::sregex_iterator());

            if (result.passwordFieldCount > 0) {
                result.detectedFieldTypes.push_back(FormFieldType::Password);
            }

            // 3. Detect Login Intent
            if (result.passwordFieldCount > 0) {
                result.hasLoginForm = true;
                result.riskScore += 20;
            }

            // 4. Detect Hidden Fields
            std::regex hiddenRegex(R"(type=["']hidden["'])", std::regex_constants::icase);
            auto hiddenBegin = std::sregex_iterator(html.begin(), html.end(), hiddenRegex);
            result.hiddenFieldCount = (int)std::distance(hiddenBegin, std::sregex_iterator());

            // 5. Extract Actions
            std::regex actionRegex(R"(action=["']([^"']*)["'])", std::regex_constants::icase);
            for (std::sregex_iterator i = formsBegin; i != formsEnd; ++i) {
                std::smatch match = *i;
                std::string formTag = match.str();
                std::smatch actionMatch;
                if (std::regex_search(formTag, actionMatch, actionRegex)) {
                    std::string action = actionMatch[1].str();
                    result.formActions.push_back(action);

                    // Check for external action
                    if (action.find("http") == 0) {
                        result.hasExternalAction = true;
                        result.suspiciousAttributes.push_back("External Form Action: " + action);
                        result.riskScore += 30; // High risk if sending data externally
                    }
                }
            }

            return result;
        }
    };

    // ============================================================================
    // UTILITY IMPLEMENTATION
    // ============================================================================

    int LevenshteinDistance(const std::string& s1, const std::string& s2) {
        const size_t m = s1.length();
        const size_t n = s2.length();

        if (m == 0) return (int)n;
        if (n == 0) return (int)m;

        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));

        for (size_t i = 0; i <= m; i++) dp[i][0] = (int)i;
        for (size_t j = 0; j <= n; j++) dp[0][j] = (int)j;

        for (size_t i = 1; i <= m; i++) {
            for (size_t j = 1; j <= n; j++) {
                int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
                dp[i][j] = std::min({
                    dp[i - 1][j] + 1,      // deletion
                    dp[i][j - 1] + 1,      // insertion
                    dp[i - 1][j - 1] + cost // substitution
                });
            }
        }

        return dp[m][n];
    }

    double CalculateEntropy(const std::string& str) {
        if (str.empty()) return 0.0;

        std::map<char, int> freqs;
        for (char c : str) freqs[c]++;

        double entropy = 0.0;
        double len = (double)str.length();

        for (const auto& pair : freqs) {
            double p = pair.second / len;
            entropy -= p * std::log2(p);
        }

        return entropy;
    }

    // ============================================================================
    // PHISHING DETECTOR IMPLEMENTATION
    // ============================================================================

    PhishingDetector& PhishingDetector::Instance() noexcept {
        static PhishingDetector instance;
        s_instanceCreated = true;
        return instance;
    }

    bool PhishingDetector::HasInstance() noexcept {
        return s_instanceCreated;
    }

    PhishingDetector::PhishingDetector() : m_impl(std::make_unique<PhishingDetectorImpl>()) {
    }

    PhishingDetector::~PhishingDetector() = default;

    bool PhishingDetector::Initialize(const PhishingDetectorConfiguration& config) {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == ModuleStatus::Running) {
            return true;
        }

        m_impl->m_status = ModuleStatus::Initializing;
        m_impl->m_config = config;

        // Add config brands to database
        for (const auto& brand : config.protectedBrands) {
            // This is simplified, ideally we'd have a mapping of Brand -> Domains
            // Here we just use the brand string as both
            m_impl->m_protectedBrands[brand] = { brand + ".com" };
        }

        Logger::Info("PhishingDetector initialized with threshold {}", config.phishingThreshold);
        m_impl->m_status = ModuleStatus::Running;
        return true;
    }

    void PhishingDetector::Shutdown() {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_status = ModuleStatus::Stopped;
        Logger::Info("PhishingDetector shutdown");
    }

    bool PhishingDetector::IsInitialized() const noexcept {
        return m_impl->m_status == ModuleStatus::Running;
    }

    ModuleStatus PhishingDetector::GetStatus() const noexcept {
        return m_impl->m_status;
    }

    PhishingScore PhishingDetector::AnalyzeURL(const std::string& url) {
        m_impl->m_stats.totalAnalyzed++;

        auto score = m_impl->AnalyzeURLInternal(url);

        // Update stats
        if (score.isPhishing) m_impl->m_stats.phishingDetected++;
        else if (score.verdict == PhishingVerdict::Suspicious) m_impl->m_stats.suspiciousDetected++;
        else m_impl->m_stats.safeDetected++;

        if (score.homographResult.hasHomograph) m_impl->m_stats.homographsDetected++;
        if (score.typosquattingResult.isTyposquatting) m_impl->m_stats.typosquattingDetected++;

        // Notify callbacks if phishing
        if (score.isPhishing) {
            std::shared_lock lock(m_impl->m_callbackMutex);
            for (const auto& cb : m_impl->m_detectionCallbacks) {
                cb(url, score);
            }
        }

        return score;
    }

    PhishingScore PhishingDetector::AnalyzePageContent(const std::string& url, const std::string& html) {
        // First analyze URL
        PhishingScore score = AnalyzeURL(url);

        // Then analyze content
        if (m_impl->m_config.enableFormAnalysis) {
            m_impl->m_stats.loginFormsAnalyzed++;
            auto formRes = m_impl->AnalyzeFormsInternal(html);
            score.formAnalysis = formRes;

            // Adjust score based on form analysis
            if (formRes.hasLoginForm && !score.urlAnalysis.isHTTPS) {
                 score.indicators = (PhishingIndicator)((uint32_t)score.indicators | (uint32_t)PhishingIndicator::LoginFormHTTP);
                 score.allReasons.push_back("Login form detected over HTTP (Insecure)");
                 score.score += 0.5;
            }

            if (formRes.hasExternalAction) {
                score.indicators = (PhishingIndicator)((uint32_t)score.indicators | (uint32_t)PhishingIndicator::ExternalFormAction);
                score.allReasons.push_back("Form sends data to external domain");
                score.score += 0.4;
            }
        }

        // Re-evaluate verdict
        if (score.score >= m_impl->m_config.phishingThreshold) {
            score.isPhishing = true;
            score.verdict = PhishingVerdict::Phishing;
        }

        return score;
    }

    PhishingScore PhishingDetector::AnalyzeFull(const std::string& url, const std::string& html, const std::vector<uint8_t>& screenshot) {
        // Just call page content for now, visual analysis would be here
        return AnalyzePageContent(url, html);
    }

    HomographResult PhishingDetector::CheckHomograph(const std::string& domain) {
        return m_impl->CheckHomographInternal(domain);
    }

    TyposquattingResult PhishingDetector::CheckTyposquatting(const std::string& domain) {
        return m_impl->CheckTyposquattingInternal(domain);
    }

    FormAnalysisResult PhishingDetector::AnalyzeForms(const std::string& html) {
        return m_impl->AnalyzeFormsInternal(html);
    }

    CertificateAnalysis PhishingDetector::AnalyzeCertificate(const std::string& url) {
        // Placeholder for actual SSL implementation
        // Need OpenSSL or WinHTTP to fetch cert
        m_impl->m_stats.certificatesChecked++;
        CertificateAnalysis cert;
        cert.hasCertificate = false;
        return cert;
    }

    bool PhishingDetector::IsPhishing(const std::string& url) {
        return AnalyzeURL(url).isPhishing;
    }

    int PhishingDetector::GetRiskScore(const std::string& url) {
        auto res = AnalyzeURL(url);
        return res.confidence;
    }

    std::optional<std::string> PhishingDetector::DetectBrandImpersonation(const std::string& domain) {
        auto res = CheckTyposquatting(domain);
        if (res.isTyposquatting) return res.targetBrand;
        return std::nullopt;
    }

    bool PhishingDetector::IsLegitimeDomain(const std::string& domain, const std::string& brand) {
        std::shared_lock lock(m_impl->m_mutex);
        if (m_impl->m_protectedBrands.find(brand) == m_impl->m_protectedBrands.end()) {
            return false;
        }

        const auto& domains = m_impl->m_protectedBrands[brand];
        for (const auto& d : domains) {
            if (d == domain || domain.find("." + d) != std::string::npos) return true;
        }
        return false;
    }

    bool PhishingDetector::AddProtectedBrand(const std::string& brandName, const std::vector<std::string>& legitimateDomains) {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_protectedBrands[brandName] = legitimateDomains;
        return true;
    }

    bool PhishingDetector::RemoveProtectedBrand(const std::string& brandName) {
        std::unique_lock lock(m_impl->m_mutex);
        return m_impl->m_protectedBrands.erase(brandName) > 0;
    }

    std::vector<std::string> PhishingDetector::GetProtectedBrands() const {
        std::shared_lock lock(m_impl->m_mutex);
        std::vector<std::string> brands;
        for (const auto& [name, domains] : m_impl->m_protectedBrands) {
            brands.push_back(name);
        }
        return brands;
    }

    void PhishingDetector::RegisterDetectionCallback(PhishingDetectionCallback callback) {
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_detectionCallbacks.push_back(callback);
    }

    void PhishingDetector::RegisterBrandAlertCallback(BrandAlertCallback callback) {
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_brandCallbacks.push_back(callback);
    }

    void PhishingDetector::RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_errorCallbacks.push_back(callback);
    }

    void PhishingDetector::UnregisterCallbacks() {
        std::unique_lock lock(m_impl->m_callbackMutex);
        m_impl->m_detectionCallbacks.clear();
        m_impl->m_brandCallbacks.clear();
        m_impl->m_errorCallbacks.clear();
    }

    PhishingDetectorStatistics PhishingDetector::GetStatistics() const {
        return m_impl->m_stats;
    }

    void PhishingDetector::ResetStatistics() {
        m_impl->m_stats.Reset();
    }

    bool PhishingDetector::SelfTest() {
        // Test basic phishing detection
        std::string testUrl = "http://microsoft.com.secure-login.attacker.com/login";
        auto result = AnalyzeURL(testUrl);

        // This should trigger some heuristics (long URL, subdomains, maybe brand similarity if strict)
        // But mainly we want to ensure it doesn't crash

        // Test homograph
        // 'o' in cyrillic is U+043E
        std::wstring wTest = L"micr\x043Esoft.com";
        std::string hTest = StringUtils::ToUtf8(wTest);

        auto hResult = CheckHomograph(hTest);
        if (!hResult.hasHomograph) return false;

        return true;
    }

    std::string PhishingDetector::GetVersionString() noexcept {
        return std::to_string(PhishingDetectorConstants::VERSION_MAJOR) + "." +
               std::to_string(PhishingDetectorConstants::VERSION_MINOR) + "." +
               std::to_string(PhishingDetectorConstants::VERSION_PATCH);
    }

    // ============================================================================
    // SERIALIZATION METHODS
    // ============================================================================

    std::string URLAnalysisDetail::ToJson() const {
        json j;
        j["originalUrl"] = originalUrl;
        j["domain"] = domain;
        j["isHTTPS"] = isHTTPS;
        j["entropy"] = entropyScore;
        return j.dump();
    }

    std::string HomographResult::ToJson() const {
        json j;
        j["hasHomograph"] = hasHomograph;
        j["targetedBrand"] = targetedBrand;
        return j.dump();
    }

    std::string TyposquattingResult::ToJson() const {
        json j;
        j["isTyposquatting"] = isTyposquatting;
        j["targetBrand"] = targetBrand;
        return j.dump();
    }

    std::string FormAnalysisResult::ToJson() const {
        json j;
        j["hasLoginForm"] = hasLoginForm;
        j["passwordFieldCount"] = passwordFieldCount;
        return j.dump();
    }

    std::string VisualAnalysisResult::ToJson() const {
        return json{{"hasBrandElements", hasBrandElements}}.dump();
    }

    std::string CertificateAnalysis::ToJson() const {
        return json{{"isValid", isValid}}.dump();
    }

    bool PhishingScore::ShouldBlock() const noexcept {
        return isPhishing || verdict == PhishingVerdict::KnownBad;
    }

    std::string PhishingScore::ToJson() const {
        json j;
        j["isPhishing"] = isPhishing;
        j["score"] = score;
        j["reason"] = reason;
        return j.dump();
    }

    void PhishingDetectorStatistics::Reset() noexcept {
        totalAnalyzed = 0;
        phishingDetected = 0;
        startTime = Clock::now();
    }

    std::string PhishingDetectorStatistics::ToJson() const {
        json j;
        j["totalAnalyzed"] = totalAnalyzed.load();
        j["phishingDetected"] = phishingDetected.load();
        return j.dump();
    }

    bool PhishingDetectorConfiguration::IsValid() const noexcept {
        return phishingThreshold > 0 && phishingThreshold <= 1.0;
    }

} // namespace ShadowStrike::WebBrowser
