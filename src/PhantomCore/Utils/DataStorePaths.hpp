/**
 * @file DataStorePaths.hpp
 * @brief Canonical on-disk locations for the detection data stores.
 *
 * The signature, pattern, hash-reputation, whitelist and threat-intel stores all
 * need a persistent, machine-wide, tamper-resistant home. Before this module
 * each store either had no path at all (so it was never opened) or invented one
 * locally - including a per-process file under %TEMP% that was discarded on
 * every service restart. Resolving them in one place makes the layout explicit,
 * keeps the installer and the service in agreement, and gives every store the
 * same security guarantees.
 *
 * @par Why the directory ACL matters
 * The whitelist is an allow decision: anything in it is trusted and skips deeper
 * analysis. If an unprivileged process can write to the store directory, malware
 * can add its own hash or publisher and become invisible to the engine - a
 * complete detection bypass that needs no exploit. The same applies in reverse to
 * the signature store, where a writer could remove the definitions that detect
 * it. These files are therefore held in a directory whose DACL is protected
 * against inheritance and grants write access only to LocalSystem and
 * Administrators, with read access for everyone else.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#pragma once

#include <string>

namespace ShadowStrike::Utils::DataStorePaths {

/// @brief Root directory holding every detection data store.
/// @return Absolute path, e.g. C:\ProgramData\ShadowStrike\Data (never empty).
[[nodiscard]] std::wstring GetDataDirectory();

/// @brief Create the data directory if absent and enforce its restrictive DACL.
///
/// Idempotent, and safe to call from multiple components during startup. The
/// ACL is (re)applied on every call so a directory that was created or loosened
/// by an earlier version, an installer, or an attacker is brought back to the
/// intended posture rather than trusted as-is.
///
/// @return true if the directory exists and is writable by this process.
[[nodiscard]] bool EnsureDataDirectory() noexcept;

/// @brief Whether the directory ACL currently restricts writes to SYSTEM/Admins.
/// @note Callers use this to refuse to honour a whitelist that anyone can edit.
[[nodiscard]] bool IsDataDirectoryHardened() noexcept;

/// @brief Signature store database (B-tree index, YARA rules, patterns, hashes).
[[nodiscard]] std::wstring SignatureDatabase();

/// @brief Whitelist store database (bloom filter, publisher and cert trust).
[[nodiscard]] std::wstring WhitelistDatabase();

/// @brief Threat-intel store database (IOC / reputation lookups).
[[nodiscard]] std::wstring ThreatIntelDatabase();

/// @brief Hash-reputation store database (bloom-filtered known-bad hashes).
[[nodiscard]] std::wstring HashReputationDatabase();

}  // namespace ShadowStrike::Utils::DataStorePaths
