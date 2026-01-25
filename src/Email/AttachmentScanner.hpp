/**
 * ============================================================================
 * ShadowStrike Email Security - ATTACHMENT SCANNER (The Sorter)
 * ============================================================================
 *
 * @file AttachmentScanner.hpp
 * @brief Logic for extracting and analyzing email attachments.
 *
 * This module specializes in MIME parsing to find `Content-Disposition: attachment`.
 * It extracts the payload and sends it to the `ScanEngine`.
 *
 * Capabilities:
 * 1. Deep Archive Scan: Unzips .zip/.7z attachments automatically.
 * 2. Macro Detection: Specifically flags .docm/.xlsm attachments.
 * 3. Fileless Attachment: Detects attachments that are just Base64 encoded scripts.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Engine/ScanEngine.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Email {

        struct EmailAttachment {
            std::string fileName;
            std::string mimeType;
            std::vector<uint8_t> data;
            bool isMalicious;
        };

        class AttachmentScanner {
        public:
            static AttachmentScanner& Instance();

            /**
             * @brief Extract all attachments from a raw MIME message.
             */
            std::vector<EmailAttachment> ExtractAttachments(const std::vector<uint8_t>& rawEmail);

            /**
             * @brief Scan an extracted attachment.
             */
            bool ScanAttachment(const EmailAttachment& attachment);

        private:
            AttachmentScanner() = default;
        };

    } // namespace Email
} // namespace ShadowStrike
