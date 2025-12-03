/**
 * @file ThreadPoolEvents.h
 * @brief ETW Event definitions for ThreadPool diagnostics and tracing
 *
 * This header defines ETW (Event Tracing for Windows) event identifiers
 * and helper macros for the ShadowStrike ThreadPool subsystem. These events
 * enable detailed performance monitoring and debugging capabilities.
 *
 * @note These event IDs must remain stable across versions for ETW consumers.
 * @warning Do not reorder or reassign existing event IDs.
 *
 * @copyright ShadowStrike Security Suite
 */

#pragma once

#ifndef SHADOWSTRIKE_THREADPOOL_EVENTS_H
#define SHADOWSTRIKE_THREADPOOL_EVENTS_H

#include <evntprov.h>
#include <cstdint>

namespace ShadowStrike {
namespace Utils {
namespace ThreadPoolEvents {

    //=========================================================================
    // ETW Event ID Enumeration
    //=========================================================================

    /**
     * @enum ThreadPoolEventId
     * @brief Unique identifiers for ThreadPool ETW events
     *
     * Event IDs are assigned sequentially starting from 0.
     * MaxEventId is always the last entry for validation purposes.
     *
     * @note Event IDs should never be reordered to maintain compatibility
     *       with existing ETW consumers and log analyzers.
     */
    enum class ThreadPoolEventId : uint16_t {
        // Lifecycle events (0-9)
        ThreadPoolCreated = 0,        ///< Pool instance created
        ThreadPoolDestroyed = 1,      ///< Pool instance destroyed
        
        // Task events (10-19)
        ThreadPoolTaskSubmitted = 2,  ///< Task submitted to queue
        ThreadPoolTaskStarted = 3,    ///< Task execution began
        ThreadPoolTaskCompleted = 4,  ///< Task execution completed
        
        // Thread events (20-29)
        ThreadPoolThreadCreated = 5,  ///< Worker thread created
        ThreadPoolThreadDestroyed = 6,///< Worker thread destroyed
        
        // State events (30-39)
        ThreadPoolPaused = 7,         ///< Pool paused
        ThreadPoolResumed = 8,        ///< Pool resumed
        ThreadPoolResized = 9,        ///< Pool thread count changed
        
        // Group events (40-49)
        ThreadPoolGroupCreated = 10,      ///< Task group created
        ThreadPoolGroupWaitComplete = 11, ///< Task group wait completed
        ThreadPoolGroupCancelled = 12,    ///< Task group cancelled
        
        // Sentinel value - must be last
        MaxEventId                    ///< Total count of event IDs (for validation)
    };

    //=========================================================================
    // Helper Functions
    //=========================================================================

    /**
     * @brief Validates that an event ID is within the valid range
     * @param eventId The event ID to validate
     * @return true if the event ID is valid, false otherwise
     */
    [[nodiscard]] constexpr bool IsValidEventId(ThreadPoolEventId eventId) noexcept {
        return static_cast<uint16_t>(eventId) < static_cast<uint16_t>(ThreadPoolEventId::MaxEventId);
    }

    /**
     * @brief Converts ThreadPoolEventId to its underlying integer value
     * @param eventId The event ID to convert
     * @return The numeric value of the event ID
     */
    [[nodiscard]] constexpr uint16_t ToUnderlying(ThreadPoolEventId eventId) noexcept {
        return static_cast<uint16_t>(eventId);
    }

    //=========================================================================
    // ETW Event Descriptor Helpers
    //=========================================================================

    /**
     * @brief Creates an EVENT_DESCRIPTOR structure for ETW logging
     *
     * This inline function creates a properly initialized EVENT_DESCRIPTOR
     * that can be used with EventWrite and related ETW functions.
     *
     * @param eventId The ThreadPoolEventId for this event
     * @param level The ETW tracing level (0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose)
     * @param channel The ETW channel (typically 0)
     * @param opcode The ETW opcode (typically 0)
     * @param task The ETW task (typically 0)
     * @param keyword The ETW keyword mask (typically 0)
     * @return A properly initialized EVENT_DESCRIPTOR
     */
    [[nodiscard]] constexpr EVENT_DESCRIPTOR MakeEventDescriptor(
        ThreadPoolEventId eventId,
        uint8_t level = 4,      // Default: Information
        uint8_t channel = 0,
        uint8_t opcode = 0,
        uint16_t task = 0,
        uint64_t keyword = 0
    ) noexcept {
        return EVENT_DESCRIPTOR{
            ToUnderlying(eventId),  // Id
            0,                       // Version
            channel,                 // Channel
            level,                   // Level
            opcode,                  // Opcode
            task,                    // Task
            keyword                  // Keyword
        };
    }

} // namespace ThreadPoolEvents
} // namespace Utils
} // namespace ShadowStrike

//=============================================================================
// Legacy Macro Support (for backward compatibility)
//=============================================================================

/**
 * @def MAKE_EVT_DESCRIPTOR
 * @brief Legacy macro for creating EVENT_DESCRIPTOR structures
 * @deprecated Use ShadowStrike::Utils::ThreadPoolEvents::MakeEventDescriptor instead
 *
 * @param EventId The ThreadPoolEventId enum value (without namespace prefix)
 * @param Level The ETW tracing level
 */
#define MAKE_EVT_DESCRIPTOR(EventId, Level) \
    ShadowStrike::Utils::ThreadPoolEvents::MakeEventDescriptor( \
        ShadowStrike::Utils::ThreadPoolEvents::ThreadPoolEventId::EventId, \
        static_cast<uint8_t>(Level) \
    )

#endif // SHADOWSTRIKE_THREADPOOL_EVENTS_H
