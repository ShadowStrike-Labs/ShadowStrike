/* ============================================================================
 * ShadowStrike Phantom Dashboard — Type Definitions
 * ============================================================================
 * Mirrors the REST API response shapes from RESTServer.cpp
 */

// ============================================================================
// PROTECTION STATUS
// ============================================================================

export type ProtectionState =
  | 'UNINITIALIZED'
  | 'INITIALIZING'
  | 'ACTIVE'
  | 'PAUSED'
  | 'DEGRADED'
  | 'ERROR'
  | 'SHUTTING_DOWN'
  | 'DISABLED';

export interface ProtectionStatus {
  state: ProtectionState;
  uptime: number;
  version: string;
  engineVersion: string;
  signatureVersion: string;
  signatureDate: string;
  lastScanTime: string;
  lastUpdateTime: string;
  tier: 'community' | 'pro' | 'enterprise';
}

export interface ModuleStatus {
  name: string;
  enabled: boolean;
  state: string;
  version: string;
  lastActivity: string;
}

export interface EngineStats {
  totalScans: number;
  totalThreats: number;
  filesScanned: number;
  bytesScanned: number;
  cacheHits: number;
  cacheMisses: number;
  avgScanTimeMs: number;
  uptime: number;
}

// ============================================================================
// THREATS
// ============================================================================

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RemediationAction =
  | 'NONE'
  | 'QUARANTINED'
  | 'DELETED'
  | 'CLEANED'
  | 'BLOCKED'
  | 'ALLOWED';

export interface ThreatEvent {
  id: string;
  timestamp: string;
  threatName: string;
  threatCategory: string;
  threatFamily: string;
  severity: ThreatSeverity;
  filePath: string;
  fileHash: string;
  fileSize: number;
  pid: number;
  processName: string;
  processPath: string;
  userName: string;
  machineName: string;
  action: RemediationAction;
  actionSuccessful: boolean;
  detectionMethod: string;
  confidence: number;
  mitreIds: string[];
}

export interface ThreatSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  quarantined: number;
  cleaned: number;
  blocked: number;
}

// ============================================================================
// SCAN
// ============================================================================

export type ScanType = 'quick' | 'full' | 'custom';

export type ScanJobState =
  | 'IDLE'
  | 'QUEUED'
  | 'SCANNING'
  | 'PAUSED'
  | 'COMPLETED'
  | 'CANCELLED'
  | 'FAILED';

export interface ScanProgress {
  jobId: string;
  state: ScanJobState;
  filesScanned: number;
  totalFiles: number;
  bytesScanned: number;
  percentComplete: number;
  currentFile: string;
  elapsedMs: number;
  estimatedRemainingMs: number;
  threatsFound: number;
}

export interface ScanStatistics {
  filesScanned: number;
  filesInfected: number;
  filesSuspicious: number;
  filesCleaned: number;
  filesQuarantined: number;
  filesSkipped: number;
  filesErrors: number;
  totalBytesScanned: number;
  scanDurationMs: number;
  whitelistHits: number;
  cacheHits: number;
  hashMatches: number;
  signatureMatches: number;
  heuristicDetections: number;
  mlDetections: number;
}

// ============================================================================
// QUARANTINE
// ============================================================================

export interface QuarantineEntry {
  id: string;
  originalPath: string;
  quarantinePath: string;
  threatName: string;
  severity: ThreatSeverity;
  quarantinedAt: string;
  fileSize: number;
  fileHash: string;
  canRestore: boolean;
}

// ============================================================================
// ALERTS
// ============================================================================

export type AlertPriority = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Alert {
  id: string;
  timestamp: string;
  title: string;
  message: string;
  priority: AlertPriority;
  source: string;
  acknowledged: boolean;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  relatedThreatId?: string;
}

// ============================================================================
// THREAT INTELLIGENCE
// ============================================================================

export interface ThreatIntelFeed {
  id: string;
  name: string;
  provider: string;
  lastUpdate: string;
  totalIndicators: number;
  enabled: boolean;
  type: 'hash' | 'url' | 'ip' | 'domain' | 'yara';
}

// ============================================================================
// CONFIGURATION
// ============================================================================

export interface SystemConfig {
  realTimeProtection: boolean;
  cloudLookup: boolean;
  autoQuarantine: boolean;
  scanArchives: boolean;
  maxFileSize: number;
  scanSchedule: string;
  exclusions: string[];
  notificationsEnabled: boolean;
  telemetryEnabled: boolean;
}

// ============================================================================
// REAL-TIME EVENTS (SSE)
// ============================================================================

export type SSEEventType =
  | 'threat_detected'
  | 'scan_started'
  | 'scan_progress'
  | 'scan_completed'
  | 'state_changed'
  | 'alert'
  | 'update_available';

export interface SSEEvent {
  type: SSEEventType;
  timestamp: string;
  data: unknown;
}

// ============================================================================
// DASHBOARD OVERVIEW
// ============================================================================

export interface TimeSeriesPoint {
  timestamp: string;
  value: number;
}

export interface OverviewData {
  status: ProtectionStatus;
  stats: EngineStats;
  recentThreats: ThreatEvent[];
  threatTrend: TimeSeriesPoint[];
  scanTrend: TimeSeriesPoint[];
  alertCount: number;
  quarantineCount: number;
}

// ============================================================================
// AUTH
// ============================================================================

export interface AuthSession {
  authenticated: boolean;
  username: string;
  role: string;
  expiresAt: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  token?: string;
  error?: string;
}

// ============================================================================
// API RESPONSE WRAPPER
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

// ============================================================================
// LICENSE
// ============================================================================

export interface LicenseInfo {
  tier: 'community' | 'pro' | 'enterprise';
  features: string[];
  expiresAt?: string;
  machineId: string;
}
