/**
 * ============================================================================
 * ShadowStrike NGAV - LOCATION PRIVACY IMPLEMENTATION
 * ============================================================================
 *
 * @file LocationPrivacy.cpp
 * @brief Enterprise-grade location privacy protection engine
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "LocationPrivacy.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"

#include <Windows.h>
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <regex>
#include <cmath>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> LocationPrivacy::s_instanceCreated{false};

// ============================================================================
// INTERNAL STRUCTURES & HELPERS
// ============================================================================

namespace {

/// @brief Generate unique event ID
uint64_t GenerateEventId() {
    static std::atomic<uint64_t> counter{0};
    return counter.fetch_add(1);
}

/// @brief Generate unique region ID
std::string GenerateRegionId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << "GEO-" << std::hex << std::setw(12) << std::setfill('0') << ms
        << "-" << std::setw(6) << std::setfill('0') << counter.fetch_add(1);
    return oss.str();
}

/// @brief Convert degrees to radians
constexpr double ToRadians(double degrees) noexcept {
    return degrees * 3.14159265358979323846 / 180.0;
}

/// @brief Convert radians to degrees
constexpr double ToDegrees(double radians) noexcept {
    return radians * 180.0 / 3.14159265358979323846;
}

/// @brief Random number generator
std::mt19937& GetRNG() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return gen;
}

/// @brief Known IP geolocation services
const std::vector<std::string> IP_GEOLOCATION_DOMAINS = {
    "ip-api.com",
    "ipapi.co",
    "ipgeolocation.io",
    "ipinfo.io",
    "geoip.maxmind.com",
    "freegeoip.app",
    "ipstack.com",
    "ipdata.co",
    "geolocation-db.com",
    "api.iplocation.net"
};

} // anonymous namespace

// ============================================================================
// GEOLOCATION STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool GeoLocation::IsValid() const noexcept {
    if (latitude < -90.0 || latitude > 90.0) return false;
    if (longitude < -180.0 || longitude > 180.0) return false;
    if (accuracy < 0.0) return false;
    if (altitude.has_value() && *altitude < -500.0) return false;  // Below Dead Sea
    if (speed.has_value() && *speed < 0.0) return false;
    if (heading.has_value() && (*heading < 0.0 || *heading >= 360.0)) return false;
    return true;
}

double GeoLocation::DistanceTo(const GeoLocation& other) const noexcept {
    return CalculateDistance(latitude, longitude, other.latitude, other.longitude);
}

std::string GeoLocation::ToJson() const {
    json j;
    j["latitude"] = latitude;
    j["longitude"] = longitude;

    if (altitude.has_value()) {
        j["altitude"] = *altitude;
    }

    j["accuracy"] = accuracy;

    if (speed.has_value()) {
        j["speed"] = *speed;
    }

    if (heading.has_value()) {
        j["heading"] = *heading;
    }

    j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    j["source"] = static_cast<int>(source);

    return j.dump();
}

bool GeofenceRegion::Contains(const GeoLocation& location) const {
    if (shape == GeofenceShape::Circle) {
        double distance = center.DistanceTo(location);
        return distance * 1000.0 <= radiusMeters;  // Convert km to meters
    } else if (shape == GeofenceShape::Polygon) {
        return PointInPolygon(location, boundaries);
    } else if (shape == GeofenceShape::Rectangle) {
        // Rectangle defined by first two boundary points (opposite corners)
        if (boundaries.size() >= 2) {
            double minLat = std::min(boundaries[0].latitude, boundaries[1].latitude);
            double maxLat = std::max(boundaries[0].latitude, boundaries[1].latitude);
            double minLon = std::min(boundaries[0].longitude, boundaries[1].longitude);
            double maxLon = std::max(boundaries[0].longitude, boundaries[1].longitude);

            return location.latitude >= minLat && location.latitude <= maxLat &&
                   location.longitude >= minLon && location.longitude <= maxLon;
        }
    }

    return false;
}

std::string GeofenceRegion::ToJson() const {
    json j;
    j["regionId"] = regionId;
    j["name"] = name;
    j["description"] = description;
    j["shape"] = static_cast<int>(shape);
    j["center"] = json::parse(center.ToJson());
    j["radiusMeters"] = radiusMeters;

    json boundariesArray = json::array();
    for (const auto& boundary : boundaries) {
        boundariesArray.push_back(json::parse(boundary.ToJson()));
    }
    j["boundaries"] = boundariesArray;

    j["action"] = static_cast<int>(action);
    j["enabled"] = enabled;

    if (mockLocation.has_value()) {
        j["mockLocation"] = json::parse(mockLocation->ToJson());
    }

    return j.dump();
}

std::string LocationAccessEvent::ToJson() const {
    json j;
    j["eventId"] = eventId;
    j["processId"] = processId;
    j["processName"] = processName;
    j["processPath"] = processPath.string();
    j["userName"] = userName;
    j["sourceRequested"] = static_cast<int>(sourceRequested);
    j["decision"] = static_cast<int>(decision);

    if (realLocation.has_value()) {
        j["realLocation"] = json::parse(realLocation->ToJson());
    }

    if (providedLocation.has_value()) {
        j["providedLocation"] = json::parse(providedLocation->ToJson());
    }

    j["wasMocked"] = wasMocked;
    j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    j["notes"] = notes;

    return j.dump();
}

GeoLocation MockRoute::GetCurrentLocation() const {
    if (waypoints.empty() || !isActive) {
        return GeoLocation{};
    }

    if (currentIndex >= waypoints.size()) {
        if (isLoop) {
            // Wrap around
            return waypoints[currentIndex % waypoints.size()];
        } else {
            // Return last waypoint
            return waypoints.back();
        }
    }

    return waypoints[currentIndex];
}

std::string MockRoute::ToJson() const {
    json j;
    j["routeId"] = routeId;
    j["name"] = name;

    json waypointsArray = json::array();
    for (const auto& waypoint : waypoints) {
        waypointsArray.push_back(json::parse(waypoint.ToJson()));
    }
    j["waypoints"] = waypointsArray;

    j["isLoop"] = isLoop;
    j["speedMps"] = speedMps;
    j["currentIndex"] = currentIndex;
    j["isActive"] = isActive;
    j["startTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        startTime.time_since_epoch()).count();

    return j.dump();
}

std::string LocationWhitelistEntry::ToJson() const {
    json j;
    j["entryId"] = entryId;
    j["processPattern"] = processPattern;
    j["enabled"] = enabled;
    j["allowRealLocation"] = allowRealLocation;
    j["allowBackground"] = allowBackground;

    if (mockLocation.has_value()) {
        j["mockLocation"] = json::parse(mockLocation->ToJson());
    }

    if (allowFromHour.has_value()) {
        j["allowFromHour"] = *allowFromHour;
    }

    if (allowToHour.has_value()) {
        j["allowToHour"] = *allowToHour;
    }

    j["reason"] = reason;
    j["addedBy"] = addedBy;
    j["addedTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        addedTime.time_since_epoch()).count();

    return j.dump();
}

void LocationStatistics::Reset() noexcept {
    totalAccessAttempts = 0;
    accessAllowed = 0;
    accessBlocked = 0;
    accessMocked = 0;
    whitelistHits = 0;
    geofenceTriggered = 0;
    ipGeolocationBlocked = 0;
    wifiPositioningBlocked = 0;
    backgroundAccessBlocked = 0;

    for (auto& count : bySource) {
        count = 0;
    }

    startTime = Clock::now();
}

std::string LocationStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    json j;
    j["uptimeSeconds"] = uptime;
    j["totalAccessAttempts"] = totalAccessAttempts.load();
    j["accessAllowed"] = accessAllowed.load();
    j["accessBlocked"] = accessBlocked.load();
    j["accessMocked"] = accessMocked.load();
    j["whitelistHits"] = whitelistHits.load();
    j["geofenceTriggered"] = geofenceTriggered.load();
    j["ipGeolocationBlocked"] = ipGeolocationBlocked.load();
    j["wifiPositioningBlocked"] = wifiPositioningBlocked.load();
    j["backgroundAccessBlocked"] = backgroundAccessBlocked.load();

    return j.dump();
}

bool LocationConfiguration::IsValid() const noexcept {
    if (enableFuzzing && fuzzingRadiusMeters <= 0.0) {
        return false;
    }

    if (defaultMockLocation.has_value() && !defaultMockLocation->IsValid()) {
        return false;
    }

    if (geofences.size() > LocationConstants::MAX_GEOFENCE_REGIONS) {
        return false;
    }

    return true;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class LocationPrivacyImpl final {
public:
    LocationPrivacyImpl();
    ~LocationPrivacyImpl();

    // Lifecycle
    bool Initialize(const LocationConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_isActive; }
    ModuleStatus GetStatus() const noexcept { return m_status; }
    bool UpdateConfiguration(const LocationConfiguration& config);
    LocationConfiguration GetConfiguration() const;

    // Protection control
    void SetProtectionMode(LocationProtectionMode mode);
    LocationProtectionMode GetProtectionMode() const noexcept { return m_protectionMode; }
    bool SetLocationEnabled(bool enabled);
    bool IsLocationEnabled() const noexcept { return m_locationEnabled; }

    // Mock location
    void SetMockLocation(const GeoLocation& loc);
    std::optional<GeoLocation> GetMockLocation() const;
    void ClearMockLocation();
    bool SetRandomMockLocation(const GeofenceRegion& region);
    GeoLocation FuzzLocation(const GeoLocation& location, double radiusMeters);

    // Mock routes
    bool AddRoute(const MockRoute& route);
    bool RemoveRoute(const std::string& routeId);
    bool StartRoute(const std::string& routeId);
    void StopRoute();
    std::optional<MockRoute> GetActiveRoute() const;
    std::vector<MockRoute> GetRoutes() const;

    // Geofencing
    bool AddGeofence(const GeofenceRegion& region);
    bool RemoveGeofence(const std::string& regionId);
    bool UpdateGeofence(const GeofenceRegion& region);
    std::vector<GeofenceRegion> GetGeofences() const;
    std::vector<GeofenceRegion> CheckGeofences(const GeoLocation& location);

    // Access control
    LocationAccessDecision EvaluateAccess(uint32_t processId, LocationSource source);
    GeoLocation GetLocationToProvide(const GeoLocation& realLocation, uint32_t processId);

    // Whitelist
    bool AddToWhitelist(const LocationWhitelistEntry& entry);
    bool RemoveFromWhitelist(const std::string& entryId);
    bool IsProcessWhitelisted(const std::string& processName);
    std::vector<LocationWhitelistEntry> GetWhitelist() const;

    // IP geolocation blocking
    bool BlockIPGeolocation(bool block);
    bool IsIPGeolocationBlocked() const noexcept { return m_blockIPGeolocation; }
    bool AddBlockedGeolocationDomain(const std::string& domain);
    std::vector<std::string> GetBlockedGeolocationDomains() const;

    // Event history
    std::vector<LocationAccessEvent> GetRecentEvents(
        size_t limit,
        std::optional<SystemTimePoint> since);
    void ClearEventHistory();

    // Callbacks
    void RegisterAccessCallback(AccessEventCallback callback);
    void RegisterGeofenceCallback(GeofenceCallback callback);
    void RegisterLocationCallback(LocationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    LocationStatistics GetStatistics() const;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal methods
    void RouteSimulationThreadFunc();
    void MonitoringThreadFunc();
    LocationAccessDecision EvaluateAccessInternal(
        uint32_t processId,
        const std::string& processName,
        LocationSource source);
    void RecordAccessEvent(const LocationAccessEvent& event);
    void NotifyAccessEvent(const LocationAccessEvent& event);
    void NotifyGeofenceEvent(const GeofenceRegion& region, bool entered);
    void NotifyError(const std::string& message, int code);
    bool CheckWhitelistTimeRestriction(const LocationWhitelistEntry& entry) const;
    std::string GetProcessNameFromPid(uint32_t pid);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_isActive{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    LocationConfiguration m_config;

    // Protection state
    std::atomic<LocationProtectionMode> m_protectionMode{LocationProtectionMode::WhitelistOnly};
    std::atomic<bool> m_locationEnabled{true};
    std::atomic<bool> m_blockIPGeolocation{true};

    // Mock location
    std::optional<GeoLocation> m_mockLocation;

    // Mock routes
    std::vector<MockRoute> m_routes;
    std::optional<MockRoute> m_activeRoute;

    // Geofences
    std::vector<GeofenceRegion> m_geofences;

    // Whitelist
    std::vector<LocationWhitelistEntry> m_whitelist;

    // Blocked geolocation domains
    std::unordered_set<std::string> m_blockedDomains;

    // Event history
    std::vector<LocationAccessEvent> m_eventHistory;

    // Threads
    std::unique_ptr<std::thread> m_routeThread;
    std::atomic<bool> m_stopRouteThread{false};

    std::unique_ptr<std::thread> m_monitorThread;
    std::atomic<bool> m_stopMonitoring{false};

    // Callbacks
    AccessEventCallback m_accessCallback;
    GeofenceCallback m_geofenceCallback;
    LocationCallback m_locationCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    LocationStatistics m_stats;

    // Last known location (for geofence monitoring)
    std::optional<GeoLocation> m_lastLocation;
};

// ============================================================================
// PIMPL CONSTRUCTOR/DESTRUCTOR
// ============================================================================

LocationPrivacyImpl::LocationPrivacyImpl() {
    Utils::Logger::Info("LocationPrivacyImpl constructed");
}

LocationPrivacyImpl::~LocationPrivacyImpl() {
    Shutdown();
    Utils::Logger::Info("LocationPrivacyImpl destroyed");
}

// ============================================================================
// LIFECYCLE IMPLEMENTATION
// ============================================================================

bool LocationPrivacyImpl::Initialize(const LocationConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (m_isActive) {
            Utils::Logger::Warn("LocationPrivacy already initialized");
            return false;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid LocationPrivacy configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;
        m_protectionMode = config.mode;
        m_blockIPGeolocation = config.blockIPGeolocation;

        // Load geofences from config
        m_geofences = config.geofences;

        // Load routes from config
        m_routes = config.routes;

        // Initialize blocked domains with known IP geolocation services
        for (const auto& domain : IP_GEOLOCATION_DOMAINS) {
            m_blockedDomains.insert(domain);
        }

        // Initialize statistics
        m_stats.Reset();

        // Start route simulation thread
        m_stopRouteThread = false;
        m_routeThread = std::make_unique<std::thread>(
            &LocationPrivacyImpl::RouteSimulationThreadFunc, this);

        // Start monitoring thread
        m_stopMonitoring = false;
        m_monitorThread = std::make_unique<std::thread>(
            &LocationPrivacyImpl::MonitoringThreadFunc, this);

        m_isActive = true;
        m_status = ModuleStatus::Running;

        Utils::Logger::Info("LocationPrivacy initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("LocationPrivacy initialization failed: {}", e.what());
        m_status = ModuleStatus::Error;
        return false;
    }
}

void LocationPrivacyImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    try {
        if (!m_isActive) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Stop route thread
        m_stopRouteThread = true;
        if (m_routeThread && m_routeThread->joinable()) {
            lock.unlock();
            m_routeThread->join();
            lock.lock();
        }

        // Stop monitoring thread
        m_stopMonitoring = true;
        if (m_monitorThread && m_monitorThread->joinable()) {
            lock.unlock();
            m_monitorThread->join();
            lock.lock();
        }

        m_isActive = false;
        m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("LocationPrivacy shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

bool LocationPrivacyImpl::UpdateConfiguration(const LocationConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_config = config;
        m_protectionMode = config.mode;
        m_blockIPGeolocation = config.blockIPGeolocation;

        Utils::Logger::Info("Configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UpdateConfiguration failed: {}", e.what());
        return false;
    }
}

LocationConfiguration LocationPrivacyImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// PROTECTION CONTROL IMPLEMENTATION
// ============================================================================

void LocationPrivacyImpl::SetProtectionMode(LocationProtectionMode mode) {
    std::unique_lock lock(m_mutex);
    m_protectionMode = mode;
    m_config.mode = mode;
    Utils::Logger::Info("Protection mode set to: {}", static_cast<int>(mode));
}

bool LocationPrivacyImpl::SetLocationEnabled(bool enabled) {
    try {
        std::unique_lock lock(m_mutex);
        m_locationEnabled = enabled;

        // In production, would modify Windows location settings via registry:
        // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location

        Utils::Logger::Info("Location services {}", enabled ? "enabled" : "disabled");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetLocationEnabled failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// MOCK LOCATION IMPLEMENTATION
// ============================================================================

void LocationPrivacyImpl::SetMockLocation(const GeoLocation& loc) {
    std::unique_lock lock(m_mutex);

    if (!loc.IsValid()) {
        Utils::Logger::Warn("Invalid mock location provided");
        return;
    }

    m_mockLocation = loc;
    Utils::Logger::Info("Mock location set: {}, {}", loc.latitude, loc.longitude);
}

std::optional<GeoLocation> LocationPrivacyImpl::GetMockLocation() const {
    std::shared_lock lock(m_mutex);
    return m_mockLocation;
}

void LocationPrivacyImpl::ClearMockLocation() {
    std::unique_lock lock(m_mutex);
    m_mockLocation.reset();
    Utils::Logger::Info("Mock location cleared");
}

bool LocationPrivacyImpl::SetRandomMockLocation(const GeofenceRegion& region) {
    try {
        std::unique_lock lock(m_mutex);

        if (region.shape == GeofenceShape::Circle) {
            GeoLocation randomLoc = GenerateRandomLocation(region.center, region.radiusMeters);
            randomLoc.source = LocationSource::Manual;
            randomLoc.timestamp = std::chrono::system_clock::now();

            m_mockLocation = randomLoc;

            Utils::Logger::Info("Random mock location set within region: {}", region.name);
            return true;
        }

        Utils::Logger::Error("Random mock location only supported for circular regions");
        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("SetRandomMockLocation failed: {}", e.what());
        return false;
    }
}

GeoLocation LocationPrivacyImpl::FuzzLocation(const GeoLocation& location, double radiusMeters) {
    try {
        GeoLocation fuzzed = GenerateRandomLocation(location, radiusMeters);
        fuzzed.source = location.source;
        fuzzed.timestamp = std::chrono::system_clock::now();
        fuzzed.accuracy = location.accuracy + radiusMeters;

        return fuzzed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("FuzzLocation failed: {}", e.what());
        return location;
    }
}

// ============================================================================
// MOCK ROUTES IMPLEMENTATION
// ============================================================================

bool LocationPrivacyImpl::AddRoute(const MockRoute& route) {
    std::unique_lock lock(m_mutex);

    try {
        if (route.routeId.empty()) {
            Utils::Logger::Error("Route ID cannot be empty");
            return false;
        }

        if (route.waypoints.empty()) {
            Utils::Logger::Error("Route must have waypoints");
            return false;
        }

        if (route.waypoints.size() > LocationConstants::MAX_ROUTE_POINTS) {
            Utils::Logger::Error("Route exceeds maximum waypoints");
            return false;
        }

        // Check if route already exists
        auto it = std::find_if(m_routes.begin(), m_routes.end(),
            [&route](const MockRoute& r) { return r.routeId == route.routeId; });

        if (it != m_routes.end()) {
            *it = route;
        } else {
            m_routes.push_back(route);
        }

        Utils::Logger::Info("Route added: {} ({} waypoints)", route.name, route.waypoints.size());
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("AddRoute failed: {}", e.what());
        return false;
    }
}

bool LocationPrivacyImpl::RemoveRoute(const std::string& routeId) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = std::remove_if(m_routes.begin(), m_routes.end(),
            [&routeId](const MockRoute& r) { return r.routeId == routeId; });

        if (it != m_routes.end()) {
            m_routes.erase(it, m_routes.end());
            Utils::Logger::Info("Route removed: {}", routeId);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RemoveRoute failed: {}", e.what());
        return false;
    }
}

bool LocationPrivacyImpl::StartRoute(const std::string& routeId) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = std::find_if(m_routes.begin(), m_routes.end(),
            [&routeId](const MockRoute& r) { return r.routeId == routeId; });

        if (it == m_routes.end()) {
            Utils::Logger::Error("Route not found: {}", routeId);
            return false;
        }

        MockRoute activeRoute = *it;
        activeRoute.isActive = true;
        activeRoute.currentIndex = 0;
        activeRoute.startTime = std::chrono::system_clock::now();

        m_activeRoute = activeRoute;

        Utils::Logger::Info("Route started: {}", activeRoute.name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("StartRoute failed: {}", e.what());
        return false;
    }
}

void LocationPrivacyImpl::StopRoute() {
    std::unique_lock lock(m_mutex);
    m_activeRoute.reset();
    Utils::Logger::Info("Route stopped");
}

std::optional<MockRoute> LocationPrivacyImpl::GetActiveRoute() const {
    std::shared_lock lock(m_mutex);
    return m_activeRoute;
}

std::vector<MockRoute> LocationPrivacyImpl::GetRoutes() const {
    std::shared_lock lock(m_mutex);
    return m_routes;
}

// ============================================================================
// GEOFENCING IMPLEMENTATION
// ============================================================================

bool LocationPrivacyImpl::AddGeofence(const GeofenceRegion& region) {
    std::unique_lock lock(m_mutex);

    try {
        if (region.regionId.empty()) {
            Utils::Logger::Error("Region ID cannot be empty");
            return false;
        }

        if (m_geofences.size() >= LocationConstants::MAX_GEOFENCE_REGIONS) {
            Utils::Logger::Error("Maximum geofence regions reached");
            return false;
        }

        // Check if region already exists
        auto it = std::find_if(m_geofences.begin(), m_geofences.end(),
            [&region](const GeofenceRegion& r) { return r.regionId == region.regionId; });

        if (it != m_geofences.end()) {
            *it = region;
        } else {
            m_geofences.push_back(region);
        }

        Utils::Logger::Info("Geofence added: {}", region.name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("AddGeofence failed: {}", e.what());
        return false;
    }
}

bool LocationPrivacyImpl::RemoveGeofence(const std::string& regionId) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = std::remove_if(m_geofences.begin(), m_geofences.end(),
            [&regionId](const GeofenceRegion& r) { return r.regionId == regionId; });

        if (it != m_geofences.end()) {
            m_geofences.erase(it, m_geofences.end());
            Utils::Logger::Info("Geofence removed: {}", regionId);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RemoveGeofence failed: {}", e.what());
        return false;
    }
}

bool LocationPrivacyImpl::UpdateGeofence(const GeofenceRegion& region) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = std::find_if(m_geofences.begin(), m_geofences.end(),
            [&region](const GeofenceRegion& r) { return r.regionId == region.regionId; });

        if (it != m_geofences.end()) {
            *it = region;
            Utils::Logger::Info("Geofence updated: {}", region.name);
            return true;
        }

        Utils::Logger::Error("Geofence not found: {}", region.regionId);
        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UpdateGeofence failed: {}", e.what());
        return false;
    }
}

std::vector<GeofenceRegion> LocationPrivacyImpl::GetGeofences() const {
    std::shared_lock lock(m_mutex);
    return m_geofences;
}

std::vector<GeofenceRegion> LocationPrivacyImpl::CheckGeofences(const GeoLocation& location) {
    std::vector<GeofenceRegion> triggered;

    try {
        std::shared_lock lock(m_mutex);

        for (const auto& geofence : m_geofences) {
            if (!geofence.enabled) continue;

            bool isInside = geofence.Contains(location);

            // Check if we entered or exited
            bool wasInside = false;
            if (m_lastLocation.has_value()) {
                wasInside = geofence.Contains(*m_lastLocation);
            }

            bool stateChanged = (isInside != wasInside);

            // Trigger based on action
            bool shouldTrigger = false;
            switch (geofence.action) {
                case GeofenceAction::AllowInside:
                case GeofenceAction::BlockInside:
                case GeofenceAction::MockOutside:
                    shouldTrigger = isInside;
                    break;

                case GeofenceAction::AlertOnExit:
                    shouldTrigger = stateChanged && !isInside && wasInside;
                    break;

                case GeofenceAction::AlertOnEnter:
                    shouldTrigger = stateChanged && isInside && !wasInside;
                    break;

                default:
                    break;
            }

            if (shouldTrigger) {
                triggered.push_back(geofence);
                m_stats.geofenceTriggered++;

                lock.unlock();
                NotifyGeofenceEvent(geofence, isInside);
                lock.lock();
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckGeofences failed: {}", e.what());
    }

    return triggered;
}

// ============================================================================
// ACCESS CONTROL IMPLEMENTATION
// ============================================================================

LocationAccessDecision LocationPrivacyImpl::EvaluateAccess(
    uint32_t processId,
    LocationSource source) {

    try {
        std::string processName = GetProcessNameFromPid(processId);
        return EvaluateAccessInternal(processId, processName, source);

    } catch (const std::exception& e) {
        Utils::Logger::Error("EvaluateAccess failed: {}", e.what());
        return LocationAccessDecision::Block;
    }
}

LocationAccessDecision LocationPrivacyImpl::EvaluateAccessInternal(
    uint32_t processId,
    const std::string& processName,
    LocationSource source) {

    std::shared_lock lock(m_mutex);

    m_stats.totalAccessAttempts++;
    m_stats.bySource[static_cast<size_t>(source)]++;

    // Check protection mode
    switch (m_protectionMode.load()) {
        case LocationProtectionMode::Disabled:
            m_stats.accessAllowed++;
            return LocationAccessDecision::Allow;

        case LocationProtectionMode::BlockAll:
            m_stats.accessBlocked++;
            return LocationAccessDecision::Block;

        case LocationProtectionMode::MockLocation:
            m_stats.accessMocked++;
            return LocationAccessDecision::Mock;

        case LocationProtectionMode::Monitor:
            // Just log, allow access
            m_stats.accessAllowed++;
            return LocationAccessDecision::Allow;

        case LocationProtectionMode::Prompt:
            return LocationAccessDecision::Prompt;

        case LocationProtectionMode::WhitelistOnly:
            // Check whitelist
            if (IsProcessWhitelisted(processName)) {
                m_stats.whitelistHits++;
                m_stats.accessAllowed++;
                return LocationAccessDecision::Allow;
            }
            m_stats.accessBlocked++;
            return LocationAccessDecision::Block;

        default:
            m_stats.accessBlocked++;
            return LocationAccessDecision::Block;
    }
}

GeoLocation LocationPrivacyImpl::GetLocationToProvide(
    const GeoLocation& realLocation,
    uint32_t processId) {

    try {
        auto decision = EvaluateAccess(processId, realLocation.source);

        if (decision == LocationAccessDecision::Allow) {
            return realLocation;
        }

        if (decision == LocationAccessDecision::Mock) {
            std::shared_lock lock(m_mutex);

            // Check if active route
            if (m_activeRoute.has_value() && m_activeRoute->isActive) {
                GeoLocation routeLoc = m_activeRoute->GetCurrentLocation();
                routeLoc.timestamp = std::chrono::system_clock::now();
                return routeLoc;
            }

            // Check if mock location set
            if (m_mockLocation.has_value()) {
                GeoLocation mockLoc = *m_mockLocation;
                mockLoc.timestamp = std::chrono::system_clock::now();

                // Apply fuzzing if enabled
                if (m_config.enableFuzzing) {
                    mockLoc = FuzzLocation(mockLoc, m_config.fuzzingRadiusMeters);
                }

                return mockLoc;
            }

            // Use default mock location from config
            if (m_config.defaultMockLocation.has_value()) {
                GeoLocation mockLoc = *m_config.defaultMockLocation;
                mockLoc.timestamp = std::chrono::system_clock::now();
                return mockLoc;
            }
        }

        // Block - return invalid location
        GeoLocation blocked;
        blocked.latitude = 0.0;
        blocked.longitude = 0.0;
        blocked.accuracy = 0.0;
        blocked.timestamp = std::chrono::system_clock::now();
        return blocked;

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetLocationToProvide failed: {}", e.what());
        return realLocation;
    }
}

// ============================================================================
// WHITELIST IMPLEMENTATION
// ============================================================================

bool LocationPrivacyImpl::AddToWhitelist(const LocationWhitelistEntry& entry) {
    std::unique_lock lock(m_mutex);

    try {
        if (entry.entryId.empty() || entry.processPattern.empty()) {
            Utils::Logger::Error("Invalid whitelist entry");
            return false;
        }

        // Check if entry already exists
        auto it = std::find_if(m_whitelist.begin(), m_whitelist.end(),
            [&entry](const LocationWhitelistEntry& e) { return e.entryId == entry.entryId; });

        if (it != m_whitelist.end()) {
            *it = entry;
        } else {
            m_whitelist.push_back(entry);
        }

        Utils::Logger::Info("Whitelist entry added: {}", entry.processPattern);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("AddToWhitelist failed: {}", e.what());
        return false;
    }
}

bool LocationPrivacyImpl::RemoveFromWhitelist(const std::string& entryId) {
    std::unique_lock lock(m_mutex);

    try {
        auto it = std::remove_if(m_whitelist.begin(), m_whitelist.end(),
            [&entryId](const LocationWhitelistEntry& e) { return e.entryId == entryId; });

        if (it != m_whitelist.end()) {
            m_whitelist.erase(it, m_whitelist.end());
            Utils::Logger::Info("Whitelist entry removed: {}", entryId);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RemoveFromWhitelist failed: {}", e.what());
        return false;
    }
}

bool LocationPrivacyImpl::IsProcessWhitelisted(const std::string& processName) {
    std::shared_lock lock(m_mutex);

    for (const auto& entry : m_whitelist) {
        if (!entry.enabled) continue;

        // Simple pattern matching (could use regex for advanced patterns)
        if (processName.find(entry.processPattern) != std::string::npos) {
            // Check time restrictions
            if (!CheckWhitelistTimeRestriction(entry)) {
                continue;
            }

            return true;
        }
    }

    return false;
}

std::vector<LocationWhitelistEntry> LocationPrivacyImpl::GetWhitelist() const {
    std::shared_lock lock(m_mutex);
    return m_whitelist;
}

// ============================================================================
// IP GEOLOCATION BLOCKING IMPLEMENTATION
// ============================================================================

bool LocationPrivacyImpl::BlockIPGeolocation(bool block) {
    std::unique_lock lock(m_mutex);
    m_blockIPGeolocation = block;
    m_config.blockIPGeolocation = block;

    Utils::Logger::Info("IP geolocation blocking: {}", block ? "enabled" : "disabled");
    return true;
}

bool LocationPrivacyImpl::AddBlockedGeolocationDomain(const std::string& domain) {
    std::unique_lock lock(m_mutex);

    if (domain.empty()) {
        return false;
    }

    m_blockedDomains.insert(domain);
    Utils::Logger::Info("Blocked geolocation domain added: {}", domain);
    return true;
}

std::vector<std::string> LocationPrivacyImpl::GetBlockedGeolocationDomains() const {
    std::shared_lock lock(m_mutex);
    return std::vector<std::string>(m_blockedDomains.begin(), m_blockedDomains.end());
}

// ============================================================================
// EVENT HISTORY IMPLEMENTATION
// ============================================================================

std::vector<LocationAccessEvent> LocationPrivacyImpl::GetRecentEvents(
    size_t limit,
    std::optional<SystemTimePoint> since) {

    std::shared_lock lock(m_mutex);

    std::vector<LocationAccessEvent> filtered;

    for (const auto& event : m_eventHistory) {
        if (since.has_value() && event.timestamp < *since) {
            continue;
        }
        filtered.push_back(event);
    }

    // Sort by timestamp (newest first)
    std::sort(filtered.begin(), filtered.end(),
        [](const LocationAccessEvent& a, const LocationAccessEvent& b) {
            return a.timestamp > b.timestamp;
        });

    // Limit results
    if (filtered.size() > limit) {
        filtered.resize(limit);
    }

    return filtered;
}

void LocationPrivacyImpl::ClearEventHistory() {
    std::unique_lock lock(m_mutex);
    m_eventHistory.clear();
    Utils::Logger::Info("Event history cleared");
}

// ============================================================================
// CALLBACKS
// ============================================================================

void LocationPrivacyImpl::RegisterAccessCallback(AccessEventCallback callback) {
    std::unique_lock lock(m_mutex);
    m_accessCallback = std::move(callback);
}

void LocationPrivacyImpl::RegisterGeofenceCallback(GeofenceCallback callback) {
    std::unique_lock lock(m_mutex);
    m_geofenceCallback = std::move(callback);
}

void LocationPrivacyImpl::RegisterLocationCallback(LocationCallback callback) {
    std::unique_lock lock(m_mutex);
    m_locationCallback = std::move(callback);
}

void LocationPrivacyImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void LocationPrivacyImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_accessCallback = nullptr;
    m_geofenceCallback = nullptr;
    m_locationCallback = nullptr;
    m_errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

LocationStatistics LocationPrivacyImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

void LocationPrivacyImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    Utils::Logger::Info("Statistics reset");
}

bool LocationPrivacyImpl::SelfTest() {
    Utils::Logger::Info("Running LocationPrivacy self-test...");

    try {
        // Test 1: GeoLocation validation
        GeoLocation testLoc;
        testLoc.latitude = 40.7128;
        testLoc.longitude = -74.0060;  // New York
        testLoc.accuracy = 10.0;

        if (!testLoc.IsValid()) {
            Utils::Logger::Error("Self-test failed: GeoLocation validation");
            return false;
        }
        Utils::Logger::Info("✓ GeoLocation validation test passed");

        // Test 2: Distance calculation
        GeoLocation loc1;
        loc1.latitude = 40.7128;
        loc1.longitude = -74.0060;  // New York

        GeoLocation loc2;
        loc2.latitude = 34.0522;
        loc2.longitude = -118.2437;  // Los Angeles

        double distance = loc1.DistanceTo(loc2);
        if (distance < 3900.0 || distance > 4000.0) {  // Should be ~3935 km
            Utils::Logger::Error("Self-test failed: Distance calculation ({} km)", distance);
            return false;
        }
        Utils::Logger::Info("✓ Distance calculation test passed ({:.2f} km)", distance);

        // Test 3: Geofence creation
        GeofenceRegion testRegion;
        testRegion.regionId = GenerateRegionId();
        testRegion.name = "Test Region";
        testRegion.shape = GeofenceShape::Circle;
        testRegion.center = testLoc;
        testRegion.radiusMeters = 1000.0;
        testRegion.action = GeofenceAction::AllowInside;

        if (!AddGeofence(testRegion)) {
            Utils::Logger::Error("Self-test failed: Geofence creation");
            return false;
        }
        Utils::Logger::Info("✓ Geofence creation test passed");

        // Test 4: Geofence containment
        GeoLocation insideLoc = testLoc;  // Same as center
        if (!testRegion.Contains(insideLoc)) {
            Utils::Logger::Error("Self-test failed: Geofence containment (inside)");
            return false;
        }

        GeoLocation outsideLoc = loc2;  // Far away
        if (testRegion.Contains(outsideLoc)) {
            Utils::Logger::Error("Self-test failed: Geofence containment (outside)");
            return false;
        }
        Utils::Logger::Info("✓ Geofence containment test passed");

        // Test 5: Mock location
        SetMockLocation(testLoc);
        auto mockLoc = GetMockLocation();
        if (!mockLoc.has_value()) {
            Utils::Logger::Error("Self-test failed: Mock location");
            return false;
        }
        Utils::Logger::Info("✓ Mock location test passed");

        // Cleanup
        RemoveGeofence(testRegion.regionId);
        ClearMockLocation();

        Utils::Logger::Info("All LocationPrivacy self-tests passed!");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("Self-test failed with exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

void LocationPrivacyImpl::RouteSimulationThreadFunc() {
    Utils::Logger::Info("Route simulation thread started");

    try {
        while (!m_stopRouteThread.load()) {
            {
                std::unique_lock lock(m_mutex);

                if (m_activeRoute.has_value() && m_activeRoute->isActive) {
                    auto& route = *m_activeRoute;

                    // Advance to next waypoint based on time and speed
                    auto now = std::chrono::system_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - route.startTime).count();

                    // Calculate distance traveled
                    double distanceTraveled = route.speedMps * elapsed;

                    // Simplified: move to next waypoint when distance exceeds threshold
                    if (route.currentIndex < route.waypoints.size() - 1) {
                        auto currentWaypoint = route.waypoints[route.currentIndex];
                        auto nextWaypoint = route.waypoints[route.currentIndex + 1];

                        double waypointDistance = currentWaypoint.DistanceTo(nextWaypoint) * 1000.0;  // km to m

                        if (distanceTraveled >= waypointDistance) {
                            route.currentIndex++;
                            route.startTime = now;  // Reset timer for next segment
                        }
                    } else if (route.isLoop) {
                        // Loop back to start
                        route.currentIndex = 0;
                        route.startTime = now;
                    } else {
                        // Route finished
                        route.isActive = false;
                    }
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Route simulation thread exception: {}", e.what());
    }

    Utils::Logger::Info("Route simulation thread stopped");
}

void LocationPrivacyImpl::MonitoringThreadFunc() {
    Utils::Logger::Info("Monitoring thread started");

    try {
        while (!m_stopMonitoring.load()) {
            // Periodic monitoring tasks
            // In production, would monitor for location access attempts

            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Monitoring thread exception: {}", e.what());
    }

    Utils::Logger::Info("Monitoring thread stopped");
}

void LocationPrivacyImpl::RecordAccessEvent(const LocationAccessEvent& event) {
    std::unique_lock lock(m_mutex);

    m_eventHistory.push_back(event);

    // Limit history size
    if (m_eventHistory.size() > 10000) {
        m_eventHistory.erase(m_eventHistory.begin());
    }
}

void LocationPrivacyImpl::NotifyAccessEvent(const LocationAccessEvent& event) {
    if (m_accessCallback) {
        try {
            m_accessCallback(event);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Access callback exception: {}", e.what());
        }
    }
}

void LocationPrivacyImpl::NotifyGeofenceEvent(const GeofenceRegion& region, bool entered) {
    if (m_geofenceCallback) {
        try {
            m_geofenceCallback(region, entered);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Geofence callback exception: {}", e.what());
        }
    }
}

void LocationPrivacyImpl::NotifyError(const std::string& message, int code) {
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Error callback exception: {}", e.what());
        }
    }
}

bool LocationPrivacyImpl::CheckWhitelistTimeRestriction(const LocationWhitelistEntry& entry) const {
    if (!entry.allowFromHour.has_value() || !entry.allowToHour.has_value()) {
        return true;  // No time restriction
    }

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::tm localTime;
    localtime_s(&localTime, &time);

    int currentHour = localTime.tm_hour;
    int fromHour = *entry.allowFromHour;
    int toHour = *entry.allowToHour;

    if (fromHour <= toHour) {
        // Normal range (e.g., 9:00 to 17:00)
        return currentHour >= fromHour && currentHour < toHour;
    } else {
        // Overnight range (e.g., 22:00 to 6:00)
        return currentHour >= fromHour || currentHour < toHour;
    }
}

std::string LocationPrivacyImpl::GetProcessNameFromPid(uint32_t pid) {
    // In production, would use ProcessUtils to get process name
    // Simplified implementation
    return "process_" + std::to_string(pid);
}

// ============================================================================
// PUBLIC API IMPLEMENTATION (SINGLETON)
// ============================================================================

LocationPrivacy& LocationPrivacy::Instance() noexcept {
    static LocationPrivacy instance;
    return instance;
}

bool LocationPrivacy::HasInstance() noexcept {
    return s_instanceCreated.load();
}

LocationPrivacy::LocationPrivacy()
    : m_impl(std::make_unique<LocationPrivacyImpl>()) {
    s_instanceCreated = true;
}

LocationPrivacy::~LocationPrivacy() {
    s_instanceCreated = false;
}

// Forward all public methods to implementation

bool LocationPrivacy::Initialize(const LocationConfiguration& config) {
    return m_impl->Initialize(config);
}

void LocationPrivacy::Shutdown() {
    m_impl->Shutdown();
}

bool LocationPrivacy::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus LocationPrivacy::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool LocationPrivacy::UpdateConfiguration(const LocationConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

LocationConfiguration LocationPrivacy::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void LocationPrivacy::SetProtectionMode(LocationProtectionMode mode) {
    m_impl->SetProtectionMode(mode);
}

LocationProtectionMode LocationPrivacy::GetProtectionMode() const noexcept {
    return m_impl->GetProtectionMode();
}

bool LocationPrivacy::SetLocationEnabled(bool enabled) {
    return m_impl->SetLocationEnabled(enabled);
}

bool LocationPrivacy::IsLocationEnabled() const noexcept {
    return m_impl->IsLocationEnabled();
}

void LocationPrivacy::SetMockLocation(const GeoLocation& loc) {
    m_impl->SetMockLocation(loc);
}

std::optional<GeoLocation> LocationPrivacy::GetMockLocation() const {
    return m_impl->GetMockLocation();
}

void LocationPrivacy::ClearMockLocation() {
    m_impl->ClearMockLocation();
}

bool LocationPrivacy::SetRandomMockLocation(const GeofenceRegion& region) {
    return m_impl->SetRandomMockLocation(region);
}

GeoLocation LocationPrivacy::FuzzLocation(const GeoLocation& location, double radiusMeters) {
    return m_impl->FuzzLocation(location, radiusMeters);
}

bool LocationPrivacy::AddRoute(const MockRoute& route) {
    return m_impl->AddRoute(route);
}

bool LocationPrivacy::RemoveRoute(const std::string& routeId) {
    return m_impl->RemoveRoute(routeId);
}

bool LocationPrivacy::StartRoute(const std::string& routeId) {
    return m_impl->StartRoute(routeId);
}

void LocationPrivacy::StopRoute() {
    m_impl->StopRoute();
}

std::optional<MockRoute> LocationPrivacy::GetActiveRoute() const {
    return m_impl->GetActiveRoute();
}

std::vector<MockRoute> LocationPrivacy::GetRoutes() const {
    return m_impl->GetRoutes();
}

bool LocationPrivacy::AddGeofence(const GeofenceRegion& region) {
    return m_impl->AddGeofence(region);
}

bool LocationPrivacy::RemoveGeofence(const std::string& regionId) {
    return m_impl->RemoveGeofence(regionId);
}

bool LocationPrivacy::UpdateGeofence(const GeofenceRegion& region) {
    return m_impl->UpdateGeofence(region);
}

std::vector<GeofenceRegion> LocationPrivacy::GetGeofences() const {
    return m_impl->GetGeofences();
}

std::vector<GeofenceRegion> LocationPrivacy::CheckGeofences(const GeoLocation& location) {
    return m_impl->CheckGeofences(location);
}

LocationAccessDecision LocationPrivacy::EvaluateAccess(
    uint32_t processId,
    LocationSource source) {
    return m_impl->EvaluateAccess(processId, source);
}

GeoLocation LocationPrivacy::GetLocationToProvide(
    const GeoLocation& realLocation,
    uint32_t processId) {
    return m_impl->GetLocationToProvide(realLocation, processId);
}

bool LocationPrivacy::AddToWhitelist(const LocationWhitelistEntry& entry) {
    return m_impl->AddToWhitelist(entry);
}

bool LocationPrivacy::RemoveFromWhitelist(const std::string& entryId) {
    return m_impl->RemoveFromWhitelist(entryId);
}

bool LocationPrivacy::IsProcessWhitelisted(const std::string& processName) {
    return m_impl->IsProcessWhitelisted(processName);
}

std::vector<LocationWhitelistEntry> LocationPrivacy::GetWhitelist() const {
    return m_impl->GetWhitelist();
}

bool LocationPrivacy::BlockIPGeolocation(bool block) {
    return m_impl->BlockIPGeolocation(block);
}

bool LocationPrivacy::IsIPGeolocationBlocked() const noexcept {
    return m_impl->IsIPGeolocationBlocked();
}

bool LocationPrivacy::AddBlockedGeolocationDomain(const std::string& domain) {
    return m_impl->AddBlockedGeolocationDomain(domain);
}

std::vector<std::string> LocationPrivacy::GetBlockedGeolocationDomains() const {
    return m_impl->GetBlockedGeolocationDomains();
}

std::vector<LocationAccessEvent> LocationPrivacy::GetRecentEvents(
    size_t limit,
    std::optional<SystemTimePoint> since) {
    return m_impl->GetRecentEvents(limit, since);
}

void LocationPrivacy::ClearEventHistory() {
    m_impl->ClearEventHistory();
}

void LocationPrivacy::RegisterAccessCallback(AccessEventCallback callback) {
    m_impl->RegisterAccessCallback(std::move(callback));
}

void LocationPrivacy::RegisterGeofenceCallback(GeofenceCallback callback) {
    m_impl->RegisterGeofenceCallback(std::move(callback));
}

void LocationPrivacy::RegisterLocationCallback(LocationCallback callback) {
    m_impl->RegisterLocationCallback(std::move(callback));
}

void LocationPrivacy::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void LocationPrivacy::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

LocationStatistics LocationPrivacy::GetStatistics() const {
    return m_impl->GetStatistics();
}

void LocationPrivacy::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool LocationPrivacy::SelfTest() {
    return m_impl->SelfTest();
}

std::string LocationPrivacy::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << LocationConstants::VERSION_MAJOR << "."
        << LocationConstants::VERSION_MINOR << "."
        << LocationConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetProtectionModeName(LocationProtectionMode mode) noexcept {
    switch (mode) {
        case LocationProtectionMode::Disabled: return "Disabled";
        case LocationProtectionMode::Monitor: return "Monitor";
        case LocationProtectionMode::Prompt: return "Prompt";
        case LocationProtectionMode::WhitelistOnly: return "WhitelistOnly";
        case LocationProtectionMode::BlockAll: return "BlockAll";
        case LocationProtectionMode::MockLocation: return "MockLocation";
        default: return "Unknown";
    }
}

std::string_view GetLocationSourceName(LocationSource source) noexcept {
    switch (source) {
        case LocationSource::Unknown: return "Unknown";
        case LocationSource::GPS: return "GPS";
        case LocationSource::WiFi: return "WiFi";
        case LocationSource::CellTower: return "CellTower";
        case LocationSource::IP: return "IP";
        case LocationSource::Bluetooth: return "Bluetooth";
        case LocationSource::Sensor: return "Sensor";
        case LocationSource::Manual: return "Manual";
        default: return "Unknown";
    }
}

std::string_view GetGeofenceActionName(GeofenceAction action) noexcept {
    switch (action) {
        case GeofenceAction::None: return "None";
        case GeofenceAction::AllowInside: return "AllowInside";
        case GeofenceAction::BlockInside: return "BlockInside";
        case GeofenceAction::MockOutside: return "MockOutside";
        case GeofenceAction::AlertOnExit: return "AlertOnExit";
        case GeofenceAction::AlertOnEnter: return "AlertOnEnter";
        default: return "Unknown";
    }
}

std::string_view GetDecisionName(LocationAccessDecision decision) noexcept {
    switch (decision) {
        case LocationAccessDecision::Allow: return "Allow";
        case LocationAccessDecision::Block: return "Block";
        case LocationAccessDecision::Mock: return "Mock";
        case LocationAccessDecision::Prompt: return "Prompt";
        case LocationAccessDecision::AllowOnce: return "AllowOnce";
        default: return "Unknown";
    }
}

double CalculateDistance(double lat1, double lon1, double lat2, double lon2) {
    // Haversine formula
    double dLat = ToRadians(lat2 - lat1);
    double dLon = ToRadians(lon2 - lon1);

    lat1 = ToRadians(lat1);
    lat2 = ToRadians(lat2);

    double a = std::sin(dLat / 2.0) * std::sin(dLat / 2.0) +
               std::sin(dLon / 2.0) * std::sin(dLon / 2.0) *
               std::cos(lat1) * std::cos(lat2);

    double c = 2.0 * std::atan2(std::sqrt(a), std::sqrt(1.0 - a));

    return LocationConstants::EARTH_RADIUS_KM * c;
}

GeoLocation GenerateRandomLocation(const GeoLocation& center, double radiusMeters) {
    auto& rng = GetRNG();
    std::uniform_real_distribution<double> angleDist(0.0, 2.0 * 3.14159265358979323846);
    std::uniform_real_distribution<double> radiusDist(0.0, 1.0);

    // Random angle and distance
    double angle = angleDist(rng);
    double distance = radiusDist(rng) * radiusMeters;

    // Convert distance to degrees (approximate)
    double distanceKm = distance / 1000.0;
    double latOffset = (distanceKm / LocationConstants::EARTH_RADIUS_KM) * (180.0 / 3.14159265358979323846);
    double lonOffset = latOffset / std::cos(ToRadians(center.latitude));

    GeoLocation randomLoc;
    randomLoc.latitude = center.latitude + latOffset * std::cos(angle);
    randomLoc.longitude = center.longitude + lonOffset * std::sin(angle);
    randomLoc.accuracy = center.accuracy;
    randomLoc.timestamp = std::chrono::system_clock::now();
    randomLoc.source = LocationSource::Manual;

    return randomLoc;
}

bool PointInPolygon(const GeoLocation& point, const std::vector<GeoLocation>& polygon) {
    if (polygon.size() < 3) return false;

    // Ray casting algorithm
    bool inside = false;
    size_t j = polygon.size() - 1;

    for (size_t i = 0; i < polygon.size(); i++) {
        if (((polygon[i].latitude > point.latitude) != (polygon[j].latitude > point.latitude)) &&
            (point.longitude < (polygon[j].longitude - polygon[i].longitude) *
                               (point.latitude - polygon[i].latitude) /
                               (polygon[j].latitude - polygon[i].latitude) + polygon[i].longitude)) {
            inside = !inside;
        }
        j = i;
    }

    return inside;
}

}  // namespace Privacy
}  // namespace ShadowStrike
