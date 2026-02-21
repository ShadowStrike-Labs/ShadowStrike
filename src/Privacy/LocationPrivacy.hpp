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
 * ShadowStrike NGAV - LOCATION PRIVACY MODULE
 * ============================================================================
 *
 * @file LocationPrivacy.hpp
 * @brief Enterprise-grade location privacy protection with GPS spoofing,
 *        geofencing, and IP geolocation blocking capabilities.
 *
 * Provides comprehensive location privacy protection including system-wide
 * location service control, mock location injection, and application-level
 * location access management.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. LOCATION ACCESS CONTROL
 *    - System-wide disable
 *    - Per-app permissions
 *    - Time-based access
 *    - User consent management
 *    - Background location blocking
 *
 * 2. MOCK LOCATION
 *    - GPS coordinate spoofing
 *    - Random location within area
 *    - Route simulation
 *    - Timezone matching
 *    - Altitude spoofing
 *
 * 3. GEOFENCING
 *    - Allowed areas definition
 *    - Block outside boundaries
 *    - Alert on boundary cross
 *    - Work/Home zones
 *    - Country restrictions
 *
 * 4. IP GEOLOCATION BLOCKING
 *    - Block geolocation APIs
 *    - IP lookup interception
 *    - WebRTC leak prevention
 *    - VPN leak detection
 *    - CDN geolocation
 *
 * 5. WIFI/CELL LOCATION BLOCKING
 *    - WiFi positioning block
 *    - Cell tower triangulation block
 *    - Bluetooth beacon blocking
 *    - SSID harvesting prevention
 *
 * WINDOWS APIs CONTROLLED:
 * ========================
 * - Windows.Devices.Geolocation
 * - Location Sensor API
 * - WiFi Positioning API
 * - IP Helper API (network location)
 *
 * @note Requires Location Provider hooks for full spoofing.
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class LocationPrivacyImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace LocationConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum geofence regions
    inline constexpr size_t MAX_GEOFENCE_REGIONS = 100;
    
    /// @brief Maximum mock route points
    inline constexpr size_t MAX_ROUTE_POINTS = 1000;
    
    /// @brief Earth radius (km)
    inline constexpr double EARTH_RADIUS_KM = 6371.0;

    /// @brief Default location accuracy (meters)
    inline constexpr double DEFAULT_ACCURACY_METERS = 10.0;

}  // namespace LocationConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Location protection mode
 */
enum class LocationProtectionMode : uint8_t {
    Disabled        = 0,    ///< No protection
    Monitor         = 1,    ///< Log only
    Prompt          = 2,    ///< Ask user
    WhitelistOnly   = 3,    ///< Only whitelist apps
    BlockAll        = 4,    ///< Block all location access
    MockLocation    = 5     ///< Return mock location
};

/**
 * @brief Location access decision
 */
enum class LocationAccessDecision : uint8_t {
    Allow           = 0,    ///< Allow real location
    Block           = 1,    ///< Block access
    Mock            = 2,    ///< Return mock location
    Prompt          = 3,    ///< Prompt user
    AllowOnce       = 4     ///< Allow once
};

/**
 * @brief Location source
 */
enum class LocationSource : uint8_t {
    Unknown         = 0,
    GPS             = 1,    ///< Satellite GPS
    WiFi            = 2,    ///< WiFi positioning
    CellTower       = 3,    ///< Cell tower triangulation
    IP              = 4,    ///< IP geolocation
    Bluetooth       = 5,    ///< Bluetooth beacons
    Sensor          = 6,    ///< Sensor fusion
    Manual          = 7     ///< User specified
};

/**
 * @brief Geofence action
 */
enum class GeofenceAction : uint8_t {
    None            = 0,
    AllowInside     = 1,    ///< Allow location only inside
    BlockInside     = 2,    ///< Block location inside
    MockOutside     = 3,    ///< Mock location when outside
    AlertOnExit     = 4,    ///< Alert when leaving
    AlertOnEnter    = 5     ///< Alert when entering
};

/**
 * @brief Geofence shape
 */
enum class GeofenceShape : uint8_t {
    Circle          = 0,    ///< Circular region
    Rectangle       = 1,    ///< Rectangular region
    Polygon         = 2     ///< Custom polygon
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Geographic location
 */
struct GeoLocation {
    /// @brief Latitude (-90 to 90)
    double latitude = 0.0;
    
    /// @brief Longitude (-180 to 180)
    double longitude = 0.0;
    
    /// @brief Altitude (meters, optional)
    std::optional<double> altitude;
    
    /// @brief Accuracy (meters)
    double accuracy = LocationConstants::DEFAULT_ACCURACY_METERS;
    
    /// @brief Speed (m/s, optional)
    std::optional<double> speed;
    
    /// @brief Heading (degrees, optional)
    std::optional<double> heading;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Source
    LocationSource source = LocationSource::Unknown;
    
    /// @brief Is valid
    [[nodiscard]] bool IsValid() const noexcept;
    
    /// @brief Distance to another location (km)
    [[nodiscard]] double DistanceTo(const GeoLocation& other) const noexcept;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Geofence region
 */
struct GeofenceRegion {
    /// @brief Region ID
    std::string regionId;
    
    /// @brief Region name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Shape
    GeofenceShape shape = GeofenceShape::Circle;
    
    /// @brief Center point (for circle)
    GeoLocation center;
    
    /// @brief Radius (meters, for circle)
    double radiusMeters = 1000.0;
    
    /// @brief Boundary points (for polygon)
    std::vector<GeoLocation> boundaries;
    
    /// @brief Action
    GeofenceAction action = GeofenceAction::AllowInside;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Mock location to use (if action is mock)
    std::optional<GeoLocation> mockLocation;
    
    /// @brief Check if location is inside
    [[nodiscard]] bool Contains(const GeoLocation& location) const;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Location access event
 */
struct LocationAccessEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Process path
    fs::path processPath;
    
    /// @brief User name
    std::string userName;
    
    /// @brief Source requested
    LocationSource sourceRequested = LocationSource::Unknown;
    
    /// @brief Decision
    LocationAccessDecision decision = LocationAccessDecision::Allow;
    
    /// @brief Real location (if available)
    std::optional<GeoLocation> realLocation;
    
    /// @brief Location provided (may be mock)
    std::optional<GeoLocation> providedLocation;
    
    /// @brief Was mocked
    bool wasMocked = false;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Notes
    std::string notes;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Mock route
 */
struct MockRoute {
    /// @brief Route ID
    std::string routeId;
    
    /// @brief Route name
    std::string name;
    
    /// @brief Waypoints
    std::vector<GeoLocation> waypoints;
    
    /// @brief Is loop (repeat from start)
    bool isLoop = false;
    
    /// @brief Speed (m/s)
    double speedMps = 1.4;  // Walking speed
    
    /// @brief Current position index
    size_t currentIndex = 0;
    
    /// @brief Is active
    bool isActive = false;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief Get current location on route
    [[nodiscard]] GeoLocation GetCurrentLocation() const;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Whitelist entry
 */
struct LocationWhitelistEntry {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Process pattern
    std::string processPattern;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Allow real location
    bool allowRealLocation = true;
    
    /// @brief Allow background access
    bool allowBackground = false;
    
    /// @brief Mock location to provide (if not real)
    std::optional<GeoLocation> mockLocation;
    
    /// @brief Time restrictions
    std::optional<int> allowFromHour;
    std::optional<int> allowToHour;
    
    /// @brief Reason
    std::string reason;
    
    /// @brief Added by
    std::string addedBy;
    
    /// @brief When added
    SystemTimePoint addedTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct LocationStatistics {
    std::atomic<uint64_t> totalAccessAttempts{0};
    std::atomic<uint64_t> accessAllowed{0};
    std::atomic<uint64_t> accessBlocked{0};
    std::atomic<uint64_t> accessMocked{0};
    std::atomic<uint64_t> whitelistHits{0};
    std::atomic<uint64_t> geofenceTriggered{0};
    std::atomic<uint64_t> ipGeolocationBlocked{0};
    std::atomic<uint64_t> wifiPositioningBlocked{0};
    std::atomic<uint64_t> backgroundAccessBlocked{0};
    std::array<std::atomic<uint64_t>, 8> bySource{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct LocationConfiguration {
    /// @brief Protection mode
    LocationProtectionMode mode = LocationProtectionMode::WhitelistOnly;
    
    /// @brief Show notification on access
    bool showNotification = true;
    
    /// @brief Log all access
    bool logAllAccess = true;
    
    /// @brief Block WiFi positioning
    bool blockWiFiPositioning = false;
    
    /// @brief Block IP geolocation
    bool blockIPGeolocation = true;
    
    /// @brief Block background location
    bool blockBackgroundLocation = true;
    
    /// @brief Default mock location
    std::optional<GeoLocation> defaultMockLocation;
    
    /// @brief Enable random location fuzzing
    bool enableFuzzing = false;
    
    /// @brief Fuzzing radius (meters)
    double fuzzingRadiusMeters = 100.0;
    
    /// @brief Geofence regions
    std::vector<GeofenceRegion> geofences;
    
    /// @brief Mock routes
    std::vector<MockRoute> routes;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AccessEventCallback = std::function<void(const LocationAccessEvent&)>;
using GeofenceCallback = std::function<void(const GeofenceRegion&, bool entered)>;
using LocationCallback = std::function<GeoLocation(const GeoLocation& real)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// LOCATION PRIVACY CLASS
// ============================================================================

/**
 * @class LocationPrivacy
 * @brief Enterprise location privacy protection
 */
class LocationPrivacy final {
public:
    [[nodiscard]] static LocationPrivacy& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    LocationPrivacy(const LocationPrivacy&) = delete;
    LocationPrivacy& operator=(const LocationPrivacy&) = delete;
    LocationPrivacy(LocationPrivacy&&) = delete;
    LocationPrivacy& operator=(LocationPrivacy&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const LocationConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const LocationConfiguration& config);
    [[nodiscard]] LocationConfiguration GetConfiguration() const;

    // ========================================================================
    // PROTECTION CONTROL
    // ========================================================================
    
    /// @brief Set protection mode
    void SetProtectionMode(LocationProtectionMode mode);
    
    /// @brief Get protection mode
    [[nodiscard]] LocationProtectionMode GetProtectionMode() const noexcept;
    
    /// @brief Enable/disable OS location services
    [[nodiscard]] bool SetLocationEnabled(bool enabled);
    
    /// @brief Is location enabled
    [[nodiscard]] bool IsLocationEnabled() const noexcept;

    // ========================================================================
    // MOCK LOCATION
    // ========================================================================
    
    /// @brief Set mock location
    void SetMockLocation(const GeoLocation& loc);
    
    /// @brief Get current mock location
    [[nodiscard]] std::optional<GeoLocation> GetMockLocation() const;
    
    /// @brief Clear mock location
    void ClearMockLocation();
    
    /// @brief Set random mock location within region
    [[nodiscard]] bool SetRandomMockLocation(const GeofenceRegion& region);
    
    /// @brief Fuzz location (add random offset)
    [[nodiscard]] GeoLocation FuzzLocation(
        const GeoLocation& location,
        double radiusMeters = 100.0);

    // ========================================================================
    // MOCK ROUTES
    // ========================================================================
    
    /// @brief Add mock route
    [[nodiscard]] bool AddRoute(const MockRoute& route);
    
    /// @brief Remove mock route
    [[nodiscard]] bool RemoveRoute(const std::string& routeId);
    
    /// @brief Start route simulation
    [[nodiscard]] bool StartRoute(const std::string& routeId);
    
    /// @brief Stop route simulation
    void StopRoute();
    
    /// @brief Get active route
    [[nodiscard]] std::optional<MockRoute> GetActiveRoute() const;
    
    /// @brief Get all routes
    [[nodiscard]] std::vector<MockRoute> GetRoutes() const;

    // ========================================================================
    // GEOFENCING
    // ========================================================================
    
    /// @brief Add geofence region
    [[nodiscard]] bool AddGeofence(const GeofenceRegion& region);
    
    /// @brief Remove geofence region
    [[nodiscard]] bool RemoveGeofence(const std::string& regionId);
    
    /// @brief Update geofence region
    [[nodiscard]] bool UpdateGeofence(const GeofenceRegion& region);
    
    /// @brief Get geofence regions
    [[nodiscard]] std::vector<GeofenceRegion> GetGeofences() const;
    
    /// @brief Check location against geofences
    [[nodiscard]] std::vector<GeofenceRegion> CheckGeofences(
        const GeoLocation& location);

    // ========================================================================
    // ACCESS CONTROL
    // ========================================================================
    
    /// @brief Evaluate access request
    [[nodiscard]] LocationAccessDecision EvaluateAccess(
        uint32_t processId,
        LocationSource source = LocationSource::Unknown);
    
    /// @brief Get location to provide (real or mock)
    [[nodiscard]] GeoLocation GetLocationToProvide(
        const GeoLocation& realLocation,
        uint32_t processId);

    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const LocationWhitelistEntry& entry);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& entryId);
    
    /// @brief Is process whitelisted
    [[nodiscard]] bool IsProcessWhitelisted(const std::string& processName);
    
    /// @brief Get whitelist
    [[nodiscard]] std::vector<LocationWhitelistEntry> GetWhitelist() const;

    // ========================================================================
    // IP GEOLOCATION BLOCKING
    // ========================================================================
    
    /// @brief Block IP geolocation API
    [[nodiscard]] bool BlockIPGeolocation(bool block);
    
    /// @brief Is IP geolocation blocked
    [[nodiscard]] bool IsIPGeolocationBlocked() const noexcept;
    
    /// @brief Add blocked geolocation domain
    [[nodiscard]] bool AddBlockedGeolocationDomain(const std::string& domain);
    
    /// @brief Get blocked geolocation domains
    [[nodiscard]] std::vector<std::string> GetBlockedGeolocationDomains() const;

    // ========================================================================
    // EVENT HISTORY
    // ========================================================================
    
    /// @brief Get recent events
    [[nodiscard]] std::vector<LocationAccessEvent> GetRecentEvents(
        size_t limit = 100,
        std::optional<SystemTimePoint> since = std::nullopt);
    
    /// @brief Clear event history
    void ClearEventHistory();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAccessCallback(AccessEventCallback callback);
    void RegisterGeofenceCallback(GeofenceCallback callback);
    void RegisterLocationCallback(LocationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] LocationStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    LocationPrivacy();
    ~LocationPrivacy();
    
    std::unique_ptr<LocationPrivacyImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetProtectionModeName(LocationProtectionMode mode) noexcept;
[[nodiscard]] std::string_view GetLocationSourceName(LocationSource source) noexcept;
[[nodiscard]] std::string_view GetGeofenceActionName(GeofenceAction action) noexcept;
[[nodiscard]] std::string_view GetDecisionName(LocationAccessDecision decision) noexcept;

/// @brief Calculate distance between two coordinates (Haversine)
[[nodiscard]] double CalculateDistance(
    double lat1, double lon1,
    double lat2, double lon2);

/// @brief Generate random location within radius
[[nodiscard]] GeoLocation GenerateRandomLocation(
    const GeoLocation& center,
    double radiusMeters);

/// @brief Point in polygon test
[[nodiscard]] bool PointInPolygon(
    const GeoLocation& point,
    const std::vector<GeoLocation>& polygon);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_LOCATION_BLOCK_ALL() \
    ::ShadowStrike::Privacy::LocationPrivacy::Instance().SetLocationEnabled(false)

#define SS_LOCATION_SET_MOCK(loc) \
    ::ShadowStrike::Privacy::LocationPrivacy::Instance().SetMockLocation(loc)

#define SS_LOCATION_IS_BLOCKED() \
    (!::ShadowStrike::Privacy::LocationPrivacy::Instance().IsLocationEnabled())
