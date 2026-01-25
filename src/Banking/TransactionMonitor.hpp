/**
 * ============================================================================
 * ShadowStrike Banking Security - TRANSACTION MONITOR (The Ledger)
 * ============================================================================
 *
 * @file TransactionMonitor.hpp
 * @brief Logic for identifying Man-In-The-Browser (MITB) attacks.
 *
 * Monitors for:
 * 1. Double Submission: When malware performs a second, hidden transaction.
 * 2. Recipient Modification: When the destination account number is changed in the POST data.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Banking {

        struct Transaction {
            std::string recipient;
            double amount;
            std::string currency;
            uint64_t timestamp;
        };

        class TransactionMonitor {
        public:
            static TransactionMonitor& Instance();

            /**
             * @brief Record a transaction for audit.
             */
            void LogTransaction(const Transaction& tx);

            /**
             * @brief Check if a transaction is anomalous based on user history.
             */
            bool IsAnomalous(const Transaction& tx);

        private:
            TransactionMonitor() = default;
        };

    } // namespace Banking
} // namespace ShadowStrike
