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
#include <vector>

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

/// @brief Directory holding the read-only detection content shipped by the installer.
/// @return `<install dir>\content`, resolved from this module's own location.
[[nodiscard]] std::wstring GetShippedContentDirectory();

/// @brief Install or refresh the working signature database from the shipped baseline.
///
/// The installer places an immutable copy of signatures.sdb in the install tree
/// rather than writing directly into the data directory, because that file is
/// runtime state the updater and feed subsystem replace in place - if Windows
/// Installer also owned it, every repair and upgrade would fight the product for
/// it, and MSI's unversioned-file rules would decide the winner unpredictably.
/// Program Files is also not user-writable, so the baseline cannot be tampered
/// with by a non-administrator. This function is the bridge between the two.
///
/// Behaviour:
///  - working copy absent  -> the baseline is installed (a fresh install has no
///                            database at all, so the stores would otherwise open
///                            nothing and the product would detect nothing)
///  - baseline is newer    -> the working copy is replaced, so an upgrade that
///                            ships new content does not leave stale content in
///                            place. "Newer" is the database header's own
///                            lastUpdateTime, not a file timestamp, because file
///                            times survive copying and say nothing about content.
///  - working copy newer or
///    equal                -> left completely alone, so content already updated
///                            at runtime is never rolled back to the baseline.
///
/// The replacement is atomic and the baseline is validated before use, so a
/// truncated or corrupt baseline can never destroy a working database.
///
/// @return true if a usable working database exists when this returns, whether or
///         not anything was copied.
[[nodiscard]] bool SeedSignatureDatabaseFromBaseline() noexcept;

/// @brief Whitelist store database (bloom filter, publisher and cert trust).
[[nodiscard]] std::wstring WhitelistDatabase();

/// @brief Threat-intel store database (IOC / reputation lookups).
[[nodiscard]] std::wstring ThreatIntelDatabase();

/// @brief Hash-reputation store database (bloom-filtered known-bad hashes).
[[nodiscard]] std::wstring HashReputationDatabase();

/// @brief Absolute paths of the files this product owns as DATA, not as content.
///
/// These are the detection databases: the working stores in the data directory
/// plus the installer's read-only baseline copy. They must not be scanned as if
/// they were user content, because they legitimately contain malware indicators
/// verbatim - compiled YARA rules embed thousands of literal malware strings, and
/// the pattern section stores raw byte sequences such as the EICAR test string.
/// Scanning them finds our own detection content and reports it as a threat,
/// which at worst quarantines the database and takes all detection with it.
///
/// EXACT FILE PATHS, DELIBERATELY NOT DIRECTORIES. A directory exclusion would
/// create a location an attacker can drop a payload into and have it never
/// examined, which is a far worse trade than the cost it saves. Anything else
/// appearing in the data directory is still scanned normally, and the data
/// directory's DACL already restricts writes to SYSTEM and Administrators, so
/// these names cannot be squatted without the privilege to disable the product
/// outright.
///
/// Deliberately NOT included:
///  - the log directory. Our own writes never generate a scan: the driver exempts
///    the scanner process at create (PreCreate.c, ShadowStrikeIsScannerProcess)
///    and the write path posts no user-mode request. Another process reading our
///    logs SHOULD be scanned, and a wildcard over that directory would be a drop
///    zone since it is deliberately more permissive than the data directory.
///  - the quarantine vault. Its contents are AES-256-GCM encrypted, so no
///    pattern, rule or hash can match them and scanning costs a read that finds
///    nothing. Excluding the one directory that holds real malware would be the
///    worst possible exclusion in this product.
[[nodiscard]] std::vector<std::wstring> GetOwnedDataFiles();

}  // namespace ShadowStrike::Utils::DataStorePaths
