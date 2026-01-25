/**
 * ============================================================================
 * ShadowStrike Privacy - DNS LEAK PROTECTION (The Resolver Guard)
 * ============================================================================
 *
 * @file DNSLeakProtection.hpp
 * @brief Prevention of DNS requests leaking outside of a VPN or secure tunnel.
 *
 * Capabilities:
 * 1. Force DoH: Re-routing DNS queries to DNS-over-HTTPS (Cloudflare/Google).
 * 2. DNS Hijack detection: Verifies that the OS resolver hasn't been changed.
 * 3. Cache Poisoning Check: Cross-references local DNS cache with trusted sources.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/NetworkUtils.hpp"
#include <string>

namespace ShadowStrike {
    namespace Privacy {

        class DNSLeakProtection {
        public:
            static DNSLeakProtection& Instance();

            /**
             * @brief Monitor for DNS packets sent to unexpected servers.
             */
            void MonitorDnsActivity();

            /**
             * @brief Configure the system to use a secure, encrypted DNS.
             */
            bool EnableSecureDns(const std::string& providerUrl);

        private:
            DNSLeakProtection() = default;
        };

    } // namespace Privacy
} // namespace ShadowStrike
