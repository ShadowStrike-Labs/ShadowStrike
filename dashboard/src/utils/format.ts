/* ============================================================================
 * ShadowStrike Phantom Dashboard — Utility Functions
 * ============================================================================ */

import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** Merge Tailwind classes without conflicts */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Format bytes to human-readable string */
export function formatBytes(bytes: number, decimals = 1): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const idx = Math.min(i, sizes.length - 1);
  return `${parseFloat((bytes / Math.pow(k, idx)).toFixed(decimals))} ${sizes[idx]}`;
}

/** Format milliseconds to human-readable duration */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainSec = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainSec}s`;
  const hours = Math.floor(minutes / 60);
  const remainMin = minutes % 60;
  if (hours < 24) return `${hours}h ${remainMin}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

/** Format uptime in seconds to human-readable */
export function formatUptime(seconds: number): string {
  return formatDuration(seconds * 1000);
}

/** Format ISO date string to locale-appropriate display */
export function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return iso;
  }
}

/** Format ISO date to relative time (e.g., "3 minutes ago") */
export function formatRelativeTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    const now = Date.now();
    const diffMs = now - d.getTime();
    if (diffMs < 0) return 'just now';
    if (diffMs < 60_000) return 'just now';
    if (diffMs < 3_600_000) return `${Math.floor(diffMs / 60_000)}m ago`;
    if (diffMs < 86_400_000) return `${Math.floor(diffMs / 3_600_000)}h ago`;
    if (diffMs < 604_800_000) return `${Math.floor(diffMs / 86_400_000)}d ago`;
    return formatTimestamp(iso);
  } catch {
    return iso;
  }
}

/** Truncate path for display, keeping filename */
export function truncatePath(path: string, maxLen = 60): string {
  if (path.length <= maxLen) return path;
  const sep = path.includes('\\') ? '\\' : '/';
  const parts = path.split(sep);
  const filename = parts[parts.length - 1] ?? path;
  if (filename.length >= maxLen - 5) return `...${filename.slice(-(maxLen - 3))}`;
  const prefix = path.slice(0, maxLen - filename.length - 4);
  return `${prefix}...${sep}${filename}`;
}

/** Get severity color class for Tailwind */
export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'text-threat-critical';
    case 'high':     return 'text-threat-high';
    case 'medium':   return 'text-threat-medium';
    case 'low':      return 'text-threat-low';
    case 'info':     return 'text-threat-info';
    default:         return 'text-gray-400';
  }
}

/** Get severity badge bg class */
export function severityBadge(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high':     return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium':   return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low':      return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'info':     return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    default:         return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

/** Get protection state display color */
export function stateColor(state: string): string {
  switch (state) {
    case 'ACTIVE':        return 'text-green-400';
    case 'PAUSED':        return 'text-yellow-400';
    case 'DEGRADED':      return 'text-orange-400';
    case 'ERROR':         return 'text-red-400';
    case 'DISABLED':      return 'text-red-500';
    case 'INITIALIZING':  return 'text-blue-400';
    case 'SHUTTING_DOWN': return 'text-gray-400';
    default:              return 'text-gray-500';
  }
}

/** Clamp a number between min and max */
export function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/** Format large numbers with commas */
export function formatNumber(n: number): string {
  return n.toLocaleString();
}
