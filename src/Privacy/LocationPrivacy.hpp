/**
 * ============================================================================
 * ShadowStrike Privacy - LOCATION PRIVACY (The Mask)
 * ============================================================================
 *
 * @file LocationPrivacy.hpp
 * @brief Management of OS Location Services access.
 *
 * Capabilities:
 * 1. Geo-Fencing: Blocks location access outside of allowed areas.
 * 2. Fake Location: Feeds mock GPS coordinates to unauthorized apps.
 * 3. IP Geolocation Block: Blocks websites from querying IP-based location APIs.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Privacy {

        struct GeoLocation {
            double latitude;
            double longitude;
        };

        class LocationPrivacy {
        public:
            static LocationPrivacy& Instance();

            /**
             * @brief Enable/Disable OS location services globally.
             */
            void SetLocationEnabled(bool enabled);

            /**
             * @brief Provide a mock location to the OS.
             */
            void SetMockLocation(const GeoLocation& loc);

        private:
            LocationPrivacy() = default;
        };

    } // namespace Privacy
} // namespace ShadowStrike
