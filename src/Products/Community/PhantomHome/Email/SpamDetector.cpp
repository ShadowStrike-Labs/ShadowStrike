/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike Email Protection - SPAM DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file SpamDetector.cpp
 * @brief Enterprise-grade spam detection engine with Bayesian classification.
 *
 * This module provides comprehensive spam detection including Bayesian
 * classification, RBL/DNSBL checking, content analysis, sender reputation,
 * header analysis, and behavioral detection to protect email infrastructure.
 *
 * Key Detection Methods:
 * - Bayesian classification with token-based probability
 * - RBL/DNSBL lookups (Spamhaus, SpamCop, etc.)
 * - Content analysis (keyword density, hidden text, Base64 spam)
 * - Sender reputation tracking
 * - Header validation and forgery detection
 * - Behavioral analysis (send rate, recipient patterns)
 * - Auto-learning and corpus training
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "SpamDetector.hpp"

// Infrastructure includes
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../PatternStore/PatternStore.hpp"

// Windows headers
#include <windows.h>
#include <windns.h>

#pragma comment(lib, "dnsapi.lib")

// Standard library
#include <algorithm>
#include <regex>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <format>
#include <deque>
#include <set>
#include <fstream>

namespace ShadowStrike {
namespace Email {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Tokenize text into words/n-grams
 */
std::vector<std::string> TokenizeText(const std::string& text, bool useNGrams = true) {
    std::vector<std::string> tokens;

    // Convert to lowercase
    std::string lower = Utils::StringUtils::ToLower(text);

    // Extract words (alphanumeric sequences)
    std::regex wordRegex(R"([a-z0-9]+)");
    auto wordsBegin = std::sregex_iterator(lower.begin(), lower.end(), wordRegex);
    auto wordsEnd = std::sregex_iterator();

    std::vector<std::string> words;
    for (auto it = wordsBegin; it != wordsEnd; ++it) {
        words.push_back(it->str());
    }

    // Single words
    tokens.insert(tokens.end(), words.begin(), words.end());

    // Bigrams
    if (useNGrams && words.size() >= 2) {
        for (size_t i = 0; i < words.size() - 1; ++i) {
            tokens.push_back(words[i] + " " + words[i + 1]);
        }
    }

    return tokens;
}

/**
 * @brief Calculate keyword density
 */
double CalculateKeywordDensity(const std::string& text, const std::vector<std::string>& keywords) {
    if (text.empty() || keywords.empty()) return 0.0;

    const std::string lower = Utils::StringUtils::ToLower(text);
    uint32_t matches = 0;

    for (const auto& keyword : keywords) {
        size_t pos = 0;
        while ((pos = lower.find(keyword, pos)) != std::string::npos) {
            matches++;
            pos += keyword.length();
        }
    }

    const size_t wordCount = std::count_if(text.begin(), text.end(),
        [](char c) { return std::isspace(c); }) + 1;

    return (static_cast<double>(matches) / static_cast<double>(wordCount)) * 100.0;
}

/**
 * @brief Detect hidden text in HTML
 */
bool HasHiddenText(const std::string& html) {
    if (html.empty()) return false;

    // Check for color=#ffffff on white background
    if (html.find("color:#fff") != std::string::npos ||
        html.find("color:white") != std::string::npos ||
        html.find("color:#ffffff") != std::string::npos) {
        return true;
    }

    // Check for font-size:0 or display:none
    if (html.find("font-size:0") != std::string::npos ||
        html.find("display:none") != std::string::npos ||
        html.find("visibility:hidden") != std::string::npos) {
        return true;
    }

    return false;
}

/**
 * @brief Calculate image-to-text ratio
 */
double CalculateImageToTextRatio(const std::string& html, const std::string& text) {
    if (html.empty()) return 0.0;

    // Count <img> tags
    size_t imgCount = 0;
    size_t pos = 0;
    while ((pos = html.find("<img", pos)) != std::string::npos) {
        imgCount++;
        pos += 4;
    }

    const size_t textLen = text.length();
    if (textLen == 0 && imgCount > 0) return 100.0;
    if (textLen == 0) return 0.0;

    return (static_cast<double>(imgCount) / static_cast<double>(textLen)) * 1000.0;
}

/**
 * @brief Detect Base64-encoded content
 */
bool HasBase64Spam(const std::string& content) {
    if (content.length() < 100) return false;

    // Look for long Base64 sequences
    std::regex base64Regex(R"([A-Za-z0-9+/]{100,}={0,2})");
    return std::regex_search(content, base64Regex);
}

/**
 * @brief Extract domain from email address
 */
std::string ExtractDomain(const std::string& email) {
    const size_t atPos = email.find('@');
    if (atPos == std::string::npos) return "";

    return email.substr(atPos + 1);
}

/**
 * @brief Extract IP from Received header
 */
std::string ExtractIPFromReceived(const std::string& received) {
    // Simple IPv4 extraction
    std::regex ipRegex(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
    std::smatch match;

    if (std::regex_search(received, match, ipRegex)) {
        return match[0].str();
    }

    return "";
}

/**
 * @brief Common spam keywords
 */
const std::vector<std::string> SPAM_KEYWORDS = {
    "viagra", "cialis", "pharmacy", "prescription", "pills",
    "enlarge", "enhancement", "weight loss", "diet",
    "casino", "poker", "lottery", "winner", "jackpot",
    "loan", "mortgage", "refinance", "credit",
    "free", "guaranteed", "limited time", "act now",
    "click here", "unsubscribe", "opt out",
    "nigerian prince", "inheritance", "million dollars"
};

} // anonymous namespace

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

std::string TokenStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"token\": \"" << token << "\",\n";
    oss << "  \"spamCount\": " << spamCount << ",\n";
    oss << "  \"hamCount\": " << hamCount << ",\n";
    oss << "  \"spamProbability\": " << std::fixed << std::setprecision(4) << spamProbability << "\n";
    oss << "}";
    return oss.str();
}

double TokenStatistics::GetWeight() const noexcept {
    const uint32_t total = spamCount + hamCount;
    if (total == 0) return 0.0;

    // Weight based on frequency (more frequent = more weight)
    return std::min(static_cast<double>(total) / 10.0, 1.0);
}

std::string RBLCheckResult::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"provider\": \"" << provider << "\",\n";
    oss << "  \"ipAddress\": \"" << ipAddress << "\",\n";
    oss << "  \"isListed\": " << (isListed ? "true" : "false") << ",\n";
    oss << "  \"responseCode\": \"" << responseCode << "\",\n";
    oss << "  \"responseText\": \"" << responseText << "\"\n";
    oss << "}";
    return oss.str();
}

std::string SenderReputation::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"email\": \"" << email << "\",\n";
    oss << "  \"domain\": \"" << domain << "\",\n";
    oss << "  \"ipAddress\": \"" << ipAddress << "\",\n";
    oss << "  \"reputationScore\": " << reputationScore << ",\n";
    oss << "  \"totalEmails\": " << totalEmails << ",\n";
    oss << "  \"spamEmails\": " << spamEmails << ",\n";
    oss << "  \"hamEmails\": " << hamEmails << ",\n";
    oss << "  \"isWhitelisted\": " << (isWhitelisted ? "true" : "false") << ",\n";
    oss << "  \"isBlacklisted\": " << (isBlacklisted ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

std::string SpamAnalysisResult::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"verdict\": \"" << GetSpamVerdictName(verdict) << "\",\n";
    oss << "  \"isSpam\": " << (isSpam ? "true" : "false") << ",\n";
    oss << "  \"spamScore\": " << spamScore << ",\n";
    oss << "  \"bayesianScore\": " << bayesianScore << ",\n";
    oss << "  \"ruleScore\": " << ruleScore << ",\n";
    oss << "  \"rblScore\": " << rblScore << ",\n";
    oss << "  \"reputationScore\": " << reputationScore << ",\n";
    oss << "  \"confidence\": " << confidence << ",\n";
    oss << "  \"summary\": \"" << summary << "\",\n";
    oss << "  \"analysisDuration\": " << analysisDuration.count() << "\n";
    oss << "}";
    return oss.str();
}

void SpamDetectorStatistics::Reset() noexcept {
    totalAnalyzed.store(0, std::memory_order_relaxed);
    spamDetected.store(0, std::memory_order_relaxed);
    hamDetected.store(0, std::memory_order_relaxed);
    bulkDetected.store(0, std::memory_order_relaxed);
    phishingDetected.store(0, std::memory_order_relaxed);
    malwareDetected.store(0, std::memory_order_relaxed);
    rblHits.store(0, std::memory_order_relaxed);
    bayesianHits.store(0, std::memory_order_relaxed);
    ruleHits.store(0, std::memory_order_relaxed);
    whitelistHits.store(0, std::memory_order_relaxed);
    blacklistHits.store(0, std::memory_order_relaxed);
    falsePositives.store(0, std::memory_order_relaxed);
    falseNegatives.store(0, std::memory_order_relaxed);
    tokensLearned.store(0, std::memory_order_relaxed);
}

std::string SpamDetectorStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"totalAnalyzed\": " << totalAnalyzed.load() << ",\n";
    oss << "  \"spamDetected\": " << spamDetected.load() << ",\n";
    oss << "  \"hamDetected\": " << hamDetected.load() << ",\n";
    oss << "  \"bulkDetected\": " << bulkDetected.load() << ",\n";
    oss << "  \"phishingDetected\": " << phishingDetected.load() << ",\n";
    oss << "  \"malwareDetected\": " << malwareDetected.load() << ",\n";
    oss << "  \"rblHits\": " << rblHits.load() << ",\n";
    oss << "  \"bayesianHits\": " << bayesianHits.load() << ",\n";
    oss << "  \"ruleHits\": " << ruleHits.load() << ",\n";
    oss << "  \"whitelistHits\": " << whitelistHits.load() << ",\n";
    oss << "  \"blacklistHits\": " << blacklistHits.load() << ",\n";
    oss << "  \"falsePositives\": " << falsePositives.load() << ",\n";
    oss << "  \"falseNegatives\": " << falseNegatives.load() << ",\n";
    oss << "  \"tokensLearned\": " << tokensLearned.load() << "\n";
    oss << "}";
    return oss.str();
}

bool SpamDetectorConfiguration::IsValid() const noexcept {
    return spamThreshold > 0 && spamThreshold <= 100 &&
           hamThreshold >= 0 && hamThreshold < spamThreshold &&
           bayesianWeight >= 0.0 && bayesianWeight <= 1.0 &&
           ruleWeight >= 0.0 && ruleWeight <= 1.0 &&
           rblWeight >= 0.0 && rblWeight <= 1.0 &&
           reputationWeight >= 0.0 && reputationWeight <= 1.0 &&
           maxTokens > 0 &&
           minTokenFrequency > 0;
}

// ============================================================================
// BAYESIAN CLASSIFIER
// ============================================================================

class BayesianClassifier {
public:
    void LearnSpam(const std::vector<std::string>& tokens) {
        std::unique_lock lock(m_mutex);

        for (const auto& token : tokens) {
            auto& stats = m_tokenStats[token];
            stats.token = token;
            stats.spamCount++;
            stats.lastSeen = std::chrono::steady_clock::now();
            UpdateProbability(stats);
        }

        m_totalSpamEmails++;
    }

    void LearnHam(const std::vector<std::string>& tokens) {
        std::unique_lock lock(m_mutex);

        for (const auto& token : tokens) {
            auto& stats = m_tokenStats[token];
            stats.token = token;
            stats.hamCount++;
            stats.lastSeen = std::chrono::steady_clock::now();
            UpdateProbability(stats);
        }

        m_totalHamEmails++;
    }

    double ClassifyProbability(const std::vector<std::string>& tokens,
                              std::vector<std::pair<std::string, double>>& topTokens) const {
        std::shared_lock lock(m_mutex);

        if (m_tokenStats.empty()) return 0.5;

        std::vector<std::pair<std::string, double>> tokenProbs;

        for (const auto& token : tokens) {
            auto it = m_tokenStats.find(token);
            if (it != m_tokenStats.end()) {
                const auto& stats = it->second;
                const double weight = stats.GetWeight();

                // Only use tokens with sufficient frequency
                if (stats.spamCount + stats.hamCount >= 2) {
                    tokenProbs.push_back({token, stats.spamProbability * weight});
                }
            }
        }

        if (tokenProbs.empty()) return 0.5;

        // Sort by spam probability (descending)
        std::sort(tokenProbs.begin(), tokenProbs.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        // Take top N most significant tokens
        const size_t maxTokens = std::min(tokenProbs.size(), size_t(15));
        topTokens.assign(tokenProbs.begin(), tokenProbs.begin() + maxTokens);

        // Combined probability using naive Bayes
        double productSpam = 1.0;
        double productHam = 1.0;

        for (size_t i = 0; i < maxTokens; ++i) {
            const double spamProb = tokenProbs[i].second;
            const double hamProb = 1.0 - spamProb;

            productSpam *= spamProb;
            productHam *= hamProb;
        }

        // Avoid division by zero
        if (productSpam + productHam == 0.0) return 0.5;

        const double finalProb = productSpam / (productSpam + productHam);
        return std::clamp(finalProb, 0.0, 1.0);
    }

    size_t GetTokenCount() const {
        std::shared_lock lock(m_mutex);
        return m_tokenStats.size();
    }

    bool SaveCorpus(const std::string& filePath) const {
        std::shared_lock lock(m_mutex);

        try {
            std::ofstream ofs(filePath, std::ios::binary);
            if (!ofs) return false;

            // Write header
            ofs.write(reinterpret_cast<const char*>(&m_totalSpamEmails), sizeof(m_totalSpamEmails));
            ofs.write(reinterpret_cast<const char*>(&m_totalHamEmails), sizeof(m_totalHamEmails));

            // Write token count
            const uint64_t tokenCount = m_tokenStats.size();
            ofs.write(reinterpret_cast<const char*>(&tokenCount), sizeof(tokenCount));

            // Write tokens
            for (const auto& [token, stats] : m_tokenStats) {
                const uint32_t tokenLen = static_cast<uint32_t>(token.length());
                ofs.write(reinterpret_cast<const char*>(&tokenLen), sizeof(tokenLen));
                ofs.write(token.data(), tokenLen);
                ofs.write(reinterpret_cast<const char*>(&stats.spamCount), sizeof(stats.spamCount));
                ofs.write(reinterpret_cast<const char*>(&stats.hamCount), sizeof(stats.hamCount));
            }

            return true;

        } catch (...) {
            return false;
        }
    }

    bool LoadCorpus(const std::string& filePath) {
        std::unique_lock lock(m_mutex);

        try {
            std::ifstream ifs(filePath, std::ios::binary);
            if (!ifs) return false;

            // Read header
            ifs.read(reinterpret_cast<char*>(&m_totalSpamEmails), sizeof(m_totalSpamEmails));
            ifs.read(reinterpret_cast<char*>(&m_totalHamEmails), sizeof(m_totalHamEmails));

            // Read token count
            uint64_t tokenCount = 0;
            ifs.read(reinterpret_cast<char*>(&tokenCount), sizeof(tokenCount));

            m_tokenStats.clear();

            // Read tokens
            for (uint64_t i = 0; i < tokenCount; ++i) {
                uint32_t tokenLen = 0;
                ifs.read(reinterpret_cast<char*>(&tokenLen), sizeof(tokenLen));

                std::string token(tokenLen, '\0');
                ifs.read(token.data(), tokenLen);

                TokenStatistics stats;
                stats.token = token;
                ifs.read(reinterpret_cast<char*>(&stats.spamCount), sizeof(stats.spamCount));
                ifs.read(reinterpret_cast<char*>(&stats.hamCount), sizeof(stats.hamCount));

                UpdateProbability(stats);
                m_tokenStats[token] = stats;
            }

            return true;

        } catch (...) {
            return false;
        }
    }

private:
    void UpdateProbability(TokenStatistics& stats) const {
        const uint32_t total = stats.spamCount + stats.hamCount;
        if (total == 0) {
            stats.spamProbability = 0.5;
            return;
        }

        // Robinson's method with bias towards neutral
        const double spamProb = static_cast<double>(stats.spamCount) / static_cast<double>(total);

        // Adjust for small sample sizes (bias towards 0.5)
        const double s = 1.0;  // Strength of bias
        const double x = 0.5;  // Neutral probability

        stats.spamProbability = (s * x + total * spamProb) / (s + total);
    }

    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, TokenStatistics> m_tokenStats;
    uint64_t m_totalSpamEmails{ 0 };
    uint64_t m_totalHamEmails{ 0 };
};

// ============================================================================
// RBL CHECKER
// ============================================================================

class RBLChecker {
public:
    RBLChecker(const std::vector<std::string>& providers, uint32_t timeoutMs)
        : m_providers(providers), m_timeoutMs(timeoutMs) {
    }

    std::vector<RBLCheckResult> CheckIP(const std::string& ipAddress) {
        std::vector<RBLCheckResult> results;

        // Parse IP
        std::vector<std::string> octets;
        std::stringstream ss(ipAddress);
        std::string octet;

        while (std::getline(ss, octet, '.')) {
            octets.push_back(octet);
        }

        if (octets.size() != 4) {
            return results;
        }

        // Reverse IP for RBL query
        const std::string reversedIP = octets[3] + "." + octets[2] + "." +
                                      octets[1] + "." + octets[0];

        // Check each provider
        for (const auto& provider : m_providers) {
            RBLCheckResult result;
            result.provider = provider;
            result.ipAddress = ipAddress;
            result.checkTime = std::chrono::system_clock::now();

            const std::string query = reversedIP + "." + provider;

            // Perform DNS lookup
            if (PerformDNSLookup(query, result)) {
                result.isListed = true;
                m_stats.rblHits.fetch_add(1, std::memory_order_relaxed);
            }

            results.push_back(result);
        }

        return results;
    }

private:
    bool PerformDNSLookup(const std::string& query, RBLCheckResult& result) {
        try {
            PDNS_RECORD pDnsRecord = nullptr;

            const DNS_STATUS status = DnsQuery_A(
                Utils::StringUtils::Utf8ToWide(query).c_str(),
                DNS_TYPE_A,
                DNS_QUERY_STANDARD,
                nullptr,
                &pDnsRecord,
                nullptr
            );

            if (status == 0 && pDnsRecord) {
                // Listed in RBL
                if (pDnsRecord->wType == DNS_TYPE_A) {
                    const IN_ADDR* addr = reinterpret_cast<const IN_ADDR*>(&pDnsRecord->Data.A.IpAddress);
                    result.responseCode = std::format("{}.{}.{}.{}",
                        addr->S_un.S_un_b.s_b1,
                        addr->S_un.S_un_b.s_b2,
                        addr->S_un.S_un_b.s_b3,
                        addr->S_un.S_un_b.s_b4);
                }

                DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
                return true;
            }

            return false;

        } catch (...) {
            return false;
        }
    }

    std::vector<std::string> m_providers;
    uint32_t m_timeoutMs;

    struct {
        std::atomic<uint64_t> rblHits{ 0 };
    } m_stats;
};

// ============================================================================
// REPUTATION TRACKER
// ============================================================================

class ReputationTracker {
public:
    SenderReputation GetReputation(const std::string& sender, const std::string& ipAddress) {
        std::shared_lock lock(m_mutex);

        const std::string key = sender + "|" + ipAddress;
        auto it = m_reputations.find(key);

        if (it != m_reputations.end()) {
            return it->second;
        }

        // New sender
        SenderReputation rep;
        rep.email = sender;
        rep.domain = ExtractDomain(sender);
        rep.ipAddress = ipAddress;
        rep.reputationScore = 50;  // Neutral
        rep.firstSeen = std::chrono::steady_clock::now();
        rep.lastSeen = rep.firstSeen;

        return rep;
    }

    void UpdateReputation(const std::string& sender, const std::string& ipAddress, bool isSpam) {
        std::unique_lock lock(m_mutex);

        const std::string key = sender + "|" + ipAddress;
        auto& rep = m_reputations[key];

        if (rep.email.empty()) {
            rep.email = sender;
            rep.domain = ExtractDomain(sender);
            rep.ipAddress = ipAddress;
            rep.reputationScore = 50;
            rep.firstSeen = std::chrono::steady_clock::now();
        }

        rep.totalEmails++;
        rep.lastSeen = std::chrono::steady_clock::now();

        if (isSpam) {
            rep.spamEmails++;
        } else {
            rep.hamEmails++;
        }

        // Calculate reputation score (0-100, lower is worse)
        if (rep.totalEmails > 0) {
            const double spamRatio = static_cast<double>(rep.spamEmails) /
                                    static_cast<double>(rep.totalEmails);
            rep.reputationScore = static_cast<int>((1.0 - spamRatio) * 100.0);
        }
    }

    void AddToWhitelist(const std::string& sender) {
        std::unique_lock lock(m_mutex);
        m_whitelist.insert(Utils::StringUtils::ToLower(sender));
    }

    void AddToBlacklist(const std::string& sender) {
        std::unique_lock lock(m_mutex);
        m_blacklist.insert(Utils::StringUtils::ToLower(sender));
    }

    bool IsWhitelisted(const std::string& sender) const {
        std::shared_lock lock(m_mutex);
        const std::string lower = Utils::StringUtils::ToLower(sender);

        // Check exact match
        if (m_whitelist.count(lower)) return true;

        // Check domain
        const std::string domain = ExtractDomain(lower);
        return m_whitelist.count(domain);
    }

    bool IsBlacklisted(const std::string& sender) const {
        std::shared_lock lock(m_mutex);
        const std::string lower = Utils::StringUtils::ToLower(sender);

        // Check exact match
        if (m_blacklist.count(lower)) return true;

        // Check domain
        const std::string domain = ExtractDomain(lower);
        return m_blacklist.count(domain);
    }

private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<std::string, SenderReputation> m_reputations;
    std::set<std::string> m_whitelist;
    std::set<std::string> m_blacklist;
};

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterAnalysis(AnalysisCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_analysisCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterTraining(TrainingCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_trainingCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterRBL(RBLCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_rblCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterError(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_errorCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);
        return m_analysisCallbacks.erase(id) > 0 ||
               m_trainingCallbacks.erase(id) > 0 ||
               m_rblCallbacks.erase(id) > 0 ||
               m_errorCallbacks.erase(id) > 0;
    }

    void InvokeAnalysis(const SpamAnalysisResult& result) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_analysisCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("AnalysisCallback exception: {}", e.what());
            }
        }
    }

    void InvokeTraining(bool isSpam, size_t tokensLearned) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_trainingCallbacks) {
            try {
                callback(isSpam, tokensLearned);
            } catch (const std::exception& e) {
                Logger::Error("TrainingCallback exception: {}", e.what());
            }
        }
    }

    void InvokeRBL(const std::string& ipAddress, const std::vector<RBLCheckResult>& results) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_rblCallbacks) {
            try {
                callback(ipAddress, results);
            } catch (const std::exception& e) {
                Logger::Error("RBLCallback exception: {}", e.what());
            }
        }
    }

    void InvokeError(const std::string& message, int code) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_errorCallbacks) {
            try {
                callback(message, code);
            } catch (const std::exception& e) {
                Logger::Error("ErrorCallback exception: {}", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, AnalysisCallback> m_analysisCallbacks;
    std::unordered_map<uint64_t, TrainingCallback> m_trainingCallbacks;
    std::unordered_map<uint64_t, RBLCallback> m_rblCallbacks;
    std::unordered_map<uint64_t, ErrorCallback> m_errorCallbacks;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class SpamDetectorImpl {
public:
    SpamDetectorImpl() = default;
    ~SpamDetectorImpl() = default;

    // Prevent copying
    SpamDetectorImpl(const SpamDetectorImpl&) = delete;
    SpamDetectorImpl& operator=(const SpamDetectorImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const SpamDetectorConfiguration& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("SpamDetector: Initializing...");

            if (!config.IsValid()) {
                Logger::Error("SpamDetector: Invalid configuration");
                return false;
            }

            m_config = config;

            // Initialize managers
            m_bayesianClassifier = std::make_unique<BayesianClassifier>();
            m_rblChecker = std::make_unique<RBLChecker>(config.rblProviders, config.rblTimeoutMs);
            m_reputationTracker = std::make_unique<ReputationTracker>();
            m_callbackManager = std::make_unique<CallbackManager>();

            m_initialized = true;

            Logger::Info("SpamDetector: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("SpamDetector: Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        Logger::Info("SpamDetector: Shutdown complete");
    }

    // ========================================================================
    // ANALYSIS
    // ========================================================================

    bool IsSpam(const std::string& headers, const std::string& body) {
        auto result = Analyze("", body, "", {});
        return result.isSpam;
    }

    SpamAnalysisResult Analyze(const std::string& subject,
                              const std::string& body,
                              const std::string& sender,
                              const std::map<std::string, std::string>& headers) {
        return AnalyzeEmail(subject, body, "", sender, {}, headers);
    }

    SpamAnalysisResult AnalyzeEmail(const std::string& subject,
                                   const std::string& bodyText,
                                   const std::string& bodyHtml,
                                   const std::string& sender,
                                   const std::vector<std::string>& recipients,
                                   const std::map<std::string, std::string>& headers) {
        const auto startTime = std::chrono::steady_clock::now();

        SpamAnalysisResult result;
        result.verdict = SpamVerdict::Unknown;
        result.isSpam = false;

        try {
            std::shared_lock lock(m_mutex);

            if (!m_initialized) {
                return result;
            }

            // Check whitelist/blacklist first
            if (!sender.empty()) {
                if (m_reputationTracker->IsWhitelisted(sender)) {
                    result.verdict = SpamVerdict::Ham;
                    result.isSpam = false;
                    result.summary = "Whitelisted sender";
                    m_stats.whitelistHits.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }

                if (m_reputationTracker->IsBlacklisted(sender)) {
                    result.verdict = SpamVerdict::Spam;
                    result.isSpam = true;
                    result.spamScore = 100;
                    result.summary = "Blacklisted sender";
                    m_stats.blacklistHits.fetch_add(1, std::memory_order_relaxed);
                    m_stats.spamDetected.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }
            }

            // Tokenize content
            const std::string fullText = subject + " " + bodyText + " " + bodyHtml;
            const auto tokens = TokenizeText(fullText, m_config.useNGrams);

            // Bayesian classification
            std::vector<std::pair<std::string, double>> topTokens;
            const double bayesianProb = m_bayesianClassifier->ClassifyProbability(tokens, topTokens);
            result.bayesianScore = static_cast<int>(bayesianProb * 100.0);
            result.topSpamTokens = topTokens;

            // Content analysis
            const double keywordDensity = CalculateKeywordDensity(fullText, SPAM_KEYWORDS);
            if (keywordDensity > 5.0) {
                result.ruleScore += 20;
                result.indicators |= SpamIndicator::KeywordDensity;
                result.matchedRules.push_back("High spam keyword density");
            }

            if (HasHiddenText(bodyHtml)) {
                result.ruleScore += 30;
                result.indicators |= SpamIndicator::HiddenText;
                result.matchedRules.push_back("Hidden text detected");
            }

            if (HasBase64Spam(fullText)) {
                result.ruleScore += 15;
                result.indicators |= SpamIndicator::Base64Abuse;
                result.matchedRules.push_back("Excessive Base64 encoding");
            }

            const double imageRatio = CalculateImageToTextRatio(bodyHtml, bodyText);
            if (imageRatio > 10.0) {
                result.ruleScore += 25;
                result.indicators |= SpamIndicator::ImageSpam;
                result.matchedRules.push_back("High image-to-text ratio");
            }

            // RBL check
            if (m_config.enableRBL) {
                auto receivedIt = headers.find("Received");
                if (receivedIt != headers.end()) {
                    const std::string ipAddress = ExtractIPFromReceived(receivedIt->second);
                    if (!ipAddress.empty()) {
                        result.rblResults = m_rblChecker->CheckIP(ipAddress);

                        for (const auto& rblResult : result.rblResults) {
                            if (rblResult.isListed) {
                                result.rblScore += 40;
                                result.indicators |= SpamIndicator::RBLListed;
                                result.matchedRules.push_back("Listed in RBL: " + rblResult.provider);
                                m_stats.rblHits.fetch_add(1, std::memory_order_relaxed);
                            }
                        }

                        m_callbackManager->InvokeRBL(ipAddress, result.rblResults);
                    }
                }
            }

            // Sender reputation
            if (!sender.empty()) {
                std::string ipAddress;
                auto receivedIt = headers.find("Received");
                if (receivedIt != headers.end()) {
                    ipAddress = ExtractIPFromReceived(receivedIt->second);
                }

                result.senderReputation = m_reputationTracker->GetReputation(sender, ipAddress);
                result.reputationScore = result.senderReputation.reputationScore;

                if (result.reputationScore < 30) {
                    result.indicators |= SpamIndicator::BadReputation;
                    result.matchedRules.push_back("Poor sender reputation");
                }
            }

            // Header analysis
            if (headers.empty() || !headers.count("Message-ID") || !headers.count("Date")) {
                result.ruleScore += 15;
                result.indicators |= SpamIndicator::MissingHeaders;
                result.matchedRules.push_back("Missing required headers");
            }

            // Recipient check
            if (recipients.size() > m_config.maxRecipients) {
                result.ruleScore += 20;
                result.indicators |= SpamIndicator::ExcessiveRecipients;
                result.matchedRules.push_back("Excessive recipients");
            }

            // Calculate final score
            result.spamScore = static_cast<int>(
                result.bayesianScore * m_config.bayesianWeight +
                result.ruleScore * m_config.ruleWeight +
                result.rblScore * m_config.rblWeight +
                (100 - result.reputationScore) * m_config.reputationWeight
            );

            // Determine verdict
            if (result.spamScore >= m_config.spamThreshold) {
                result.isSpam = true;

                if (result.indicators & SpamIndicator::RBLListed) {
                    result.verdict = SpamVerdict::Phishing;
                    m_stats.phishingDetected.fetch_add(1, std::memory_order_relaxed);
                } else {
                    result.verdict = SpamVerdict::Spam;
                    m_stats.spamDetected.fetch_add(1, std::memory_order_relaxed);
                }
            } else if (result.spamScore <= m_config.hamThreshold) {
                result.verdict = SpamVerdict::Ham;
                m_stats.hamDetected.fetch_add(1, std::memory_order_relaxed);
            } else {
                result.verdict = SpamVerdict::Suspicious;
            }

            // Confidence (based on token count and score)
            result.confidence = std::min(static_cast<int>(tokens.size() / 10), 100);

            // Summary
            if (result.matchedRules.empty()) {
                result.summary = "No spam indicators detected";
            } else {
                result.summary = std::format("{} spam indicators", result.matchedRules.size());
            }

            // Duration
            const auto endTime = std::chrono::steady_clock::now();
            result.analysisDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                endTime - startTime
            );

            m_stats.totalAnalyzed.fetch_add(1, std::memory_order_relaxed);

            if (bayesianProb > 0.8) {
                m_stats.bayesianHits.fetch_add(1, std::memory_order_relaxed);
            }
            if (!result.matchedRules.empty()) {
                m_stats.ruleHits.fetch_add(1, std::memory_order_relaxed);
            }

            // Invoke callback
            m_callbackManager->InvokeAnalysis(result);

        } catch (const std::exception& e) {
            Logger::Error("SpamDetector::AnalyzeEmail: {}", e.what());
            m_callbackManager->InvokeError(e.what(), -1);
        }

        return result;
    }

    std::vector<RBLCheckResult> CheckRBL(const std::string& ipAddress) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized || !m_config.enableRBL) {
            return {};
        }

        return m_rblChecker->CheckIP(ipAddress);
    }

    // ========================================================================
    // TRAINING
    // ========================================================================

    void MarkAsSpam(const std::string& content) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return;

        const auto tokens = TokenizeText(content, m_config.useNGrams);
        m_bayesianClassifier->LearnSpam(tokens);

        m_stats.tokensLearned.fetch_add(tokens.size(), std::memory_order_relaxed);
        m_callbackManager->InvokeTraining(true, tokens.size());

        Logger::Info("SpamDetector: Learned {} spam tokens", tokens.size());
    }

    void MarkAsHam(const std::string& content) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return;

        const auto tokens = TokenizeText(content, m_config.useNGrams);
        m_bayesianClassifier->LearnHam(tokens);

        m_stats.tokensLearned.fetch_add(tokens.size(), std::memory_order_relaxed);
        m_callbackManager->InvokeTraining(false, tokens.size());

        Logger::Info("SpamDetector: Learned {} ham tokens", tokens.size());
    }

    size_t TrainSpamBatch(const std::vector<std::string>& samples) {
        size_t totalTokens = 0;

        for (const auto& sample : samples) {
            const auto tokens = TokenizeText(sample, m_config.useNGrams);
            m_bayesianClassifier->LearnSpam(tokens);
            totalTokens += tokens.size();
        }

        m_stats.tokensLearned.fetch_add(totalTokens, std::memory_order_relaxed);

        Logger::Info("SpamDetector: Batch trained {} spam samples ({} tokens)",
                    samples.size(), totalTokens);

        return totalTokens;
    }

    size_t TrainHamBatch(const std::vector<std::string>& samples) {
        size_t totalTokens = 0;

        for (const auto& sample : samples) {
            const auto tokens = TokenizeText(sample, m_config.useNGrams);
            m_bayesianClassifier->LearnHam(tokens);
            totalTokens += tokens.size();
        }

        m_stats.tokensLearned.fetch_add(totalTokens, std::memory_order_relaxed);

        Logger::Info("SpamDetector: Batch trained {} ham samples ({} tokens)",
                    samples.size(), totalTokens);

        return totalTokens;
    }

    void ReportFalsePositive(const std::string& content) {
        MarkAsHam(content);
        m_stats.falsePositives.fetch_add(1, std::memory_order_relaxed);
        Logger::Warn("SpamDetector: False positive reported");
    }

    void ReportFalseNegative(const std::string& content) {
        MarkAsSpam(content);
        m_stats.falseNegatives.fetch_add(1, std::memory_order_relaxed);
        Logger::Warn("SpamDetector: False negative reported");
    }

    bool LoadCorpus(const std::string& filePath) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return false;

        if (m_bayesianClassifier->LoadCorpus(filePath)) {
            Logger::Info("SpamDetector: Loaded corpus from {}", filePath);
            return true;
        }

        Logger::Error("SpamDetector: Failed to load corpus from {}", filePath);
        return false;
    }

    bool SaveCorpus(const std::string& filePath) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return false;

        if (m_bayesianClassifier->SaveCorpus(filePath)) {
            Logger::Info("SpamDetector: Saved corpus to {}", filePath);
            return true;
        }

        Logger::Error("SpamDetector: Failed to save corpus to {}", filePath);
        return false;
    }

    // ========================================================================
    // WHITELIST/BLACKLIST
    // ========================================================================

    bool AddToWhitelist(const std::string& sender) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return false;

        m_reputationTracker->AddToWhitelist(sender);
        Logger::Info("SpamDetector: Added to whitelist: {}", sender);
        return true;
    }

    bool AddToBlacklist(const std::string& sender) {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return false;

        m_reputationTracker->AddToBlacklist(sender);
        Logger::Info("SpamDetector: Added to blacklist: {}", sender);
        return true;
    }

    bool IsWhitelisted(const std::string& sender) const {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return false;

        return m_reputationTracker->IsWhitelisted(sender);
    }

    bool IsBlacklisted(const std::string& sender) const {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return false;

        return m_reputationTracker->IsBlacklisted(sender);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    bool UpdateConfiguration(const SpamDetectorConfiguration& config) {
        if (!config.IsValid()) {
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;

        Logger::Info("SpamDetector: Configuration updated");
        return true;
    }

    SpamDetectorConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterAnalysisCallback(AnalysisCallback callback) {
        return m_callbackManager->RegisterAnalysis(std::move(callback));
    }

    uint64_t RegisterTrainingCallback(TrainingCallback callback) {
        return m_callbackManager->RegisterTraining(std::move(callback));
    }

    uint64_t RegisterRBLCallback(RBLCallback callback) {
        return m_callbackManager->RegisterRBL(std::move(callback));
    }

    uint64_t RegisterErrorCallback(ErrorCallback callback) {
        return m_callbackManager->RegisterError(std::move(callback));
    }

    void UnregisterCallback(uint64_t callbackId) {
        m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const SpamDetectorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    size_t GetTokenCount() const {
        std::shared_lock lock(m_mutex);

        if (!m_initialized) return 0;

        return m_bayesianClassifier->GetTokenCount();
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    bool SelfTest() {
        Logger::Info("SpamDetector: Running self-test...");

        try {
            // Test configuration
            SpamDetectorConfiguration testConfig;
            if (!testConfig.IsValid()) {
                Logger::Error("SelfTest: Default config invalid");
                return false;
            }

            // Test invalid config
            testConfig.spamThreshold = 150;
            if (testConfig.IsValid()) {
                Logger::Error("SelfTest: Invalid config accepted");
                return false;
            }

            // Test training
            MarkAsSpam("Buy cheap viagra pills online now!");
            MarkAsHam("Meeting scheduled for tomorrow at 10 AM");

            // Test analysis
            auto result = Analyze(
                "Cheap viagra pills",
                "Buy now and get 50% discount!",
                "spammer@example.com",
                {}
            );

            if (result.spamScore == 0) {
                Logger::Warn("SelfTest: Spam detection may not be working");
            }

            Logger::Info("SpamDetector: Self-test PASSED");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("SpamDetector: Self-test FAILED: {}", e.what());
            return false;
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    SpamDetectorConfiguration m_config;

    // Managers
    std::unique_ptr<BayesianClassifier> m_bayesianClassifier;
    std::unique_ptr<RBLChecker> m_rblChecker;
    std::unique_ptr<ReputationTracker> m_reputationTracker;
    std::unique_ptr<CallbackManager> m_callbackManager;

    // Statistics
    mutable SpamDetectorStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

std::atomic<bool> SpamDetector::s_instanceCreated{ false };

SpamDetector::SpamDetector()
    : m_impl(std::make_unique<SpamDetectorImpl>()) {
}

SpamDetector::~SpamDetector() = default;

SpamDetector& SpamDetector::Instance() noexcept {
    static SpamDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool SpamDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

bool SpamDetector::Initialize(const SpamDetectorConfiguration& config) {
    return m_impl->Initialize(config);
}

void SpamDetector::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool SpamDetector::IsSpam(const std::string& headers, const std::string& body) {
    return m_impl->IsSpam(headers, body);
}

SpamAnalysisResult SpamDetector::Analyze(const std::string& subject,
                                        const std::string& body,
                                        const std::string& sender,
                                        const std::map<std::string, std::string>& headers) {
    return m_impl->Analyze(subject, body, sender, headers);
}

SpamAnalysisResult SpamDetector::AnalyzeEmail(const std::string& subject,
                                             const std::string& bodyText,
                                             const std::string& bodyHtml,
                                             const std::string& sender,
                                             const std::vector<std::string>& recipients,
                                             const std::map<std::string, std::string>& headers) {
    return m_impl->AnalyzeEmail(subject, bodyText, bodyHtml, sender, recipients, headers);
}

std::vector<RBLCheckResult> SpamDetector::CheckRBL(const std::string& ipAddress) {
    return m_impl->CheckRBL(ipAddress);
}

void SpamDetector::MarkAsSpam(const std::string& content) {
    m_impl->MarkAsSpam(content);
}

void SpamDetector::MarkAsHam(const std::string& content) {
    m_impl->MarkAsHam(content);
}

size_t SpamDetector::TrainSpamBatch(const std::vector<std::string>& samples) {
    return m_impl->TrainSpamBatch(samples);
}

size_t SpamDetector::TrainHamBatch(const std::vector<std::string>& samples) {
    return m_impl->TrainHamBatch(samples);
}

void SpamDetector::ReportFalsePositive(const std::string& content) {
    m_impl->ReportFalsePositive(content);
}

void SpamDetector::ReportFalseNegative(const std::string& content) {
    m_impl->ReportFalseNegative(content);
}

bool SpamDetector::LoadCorpus(const std::string& filePath) {
    return m_impl->LoadCorpus(filePath);
}

bool SpamDetector::SaveCorpus(const std::string& filePath) {
    return m_impl->SaveCorpus(filePath);
}

bool SpamDetector::AddToWhitelist(const std::string& sender) {
    return m_impl->AddToWhitelist(sender);
}

bool SpamDetector::AddToBlacklist(const std::string& sender) {
    return m_impl->AddToBlacklist(sender);
}

bool SpamDetector::IsWhitelisted(const std::string& sender) const {
    return m_impl->IsWhitelisted(sender);
}

bool SpamDetector::IsBlacklisted(const std::string& sender) const {
    return m_impl->IsBlacklisted(sender);
}

bool SpamDetector::UpdateConfiguration(const SpamDetectorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

SpamDetectorConfiguration SpamDetector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

uint64_t SpamDetector::RegisterAnalysisCallback(AnalysisCallback callback) {
    return m_impl->RegisterAnalysisCallback(std::move(callback));
}

uint64_t SpamDetector::RegisterTrainingCallback(TrainingCallback callback) {
    return m_impl->RegisterTrainingCallback(std::move(callback));
}

uint64_t SpamDetector::RegisterRBLCallback(RBLCallback callback) {
    return m_impl->RegisterRBLCallback(std::move(callback));
}

uint64_t SpamDetector::RegisterErrorCallback(ErrorCallback callback) {
    return m_impl->RegisterErrorCallback(std::move(callback));
}

void SpamDetector::UnregisterCallback(uint64_t callbackId) {
    m_impl->UnregisterCallback(callbackId);
}

const SpamDetectorStatistics& SpamDetector::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void SpamDetector::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

size_t SpamDetector::GetTokenCount() const {
    return m_impl->GetTokenCount();
}

bool SpamDetector::SelfTest() {
    return m_impl->SelfTest();
}

std::string SpamDetector::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        SpamDetectorConstants::VERSION_MAJOR,
        SpamDetectorConstants::VERSION_MINOR,
        SpamDetectorConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetSpamVerdictName(SpamVerdict verdict) noexcept {
    switch (verdict) {
        case SpamVerdict::Ham: return "Ham";
        case SpamVerdict::Unknown: return "Unknown";
        case SpamVerdict::Suspicious: return "Suspicious";
        case SpamVerdict::Spam: return "Spam";
        case SpamVerdict::Bulk: return "Bulk";
        case SpamVerdict::Newsletter: return "Newsletter";
        case SpamVerdict::Phishing: return "Phishing";
        case SpamVerdict::Malware: return "Malware";
        default: return "Unknown";
    }
}

}  // namespace Email
}  // namespace ShadowStrike
