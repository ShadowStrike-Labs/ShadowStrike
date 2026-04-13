/* ============================================================================
 * ShadowStrike Phantom Dashboard — API Client
 * ============================================================================
 * Type-safe HTTP client that talks to the embedded REST API server.
 * All endpoints mirror RESTServer.cpp routes.
 */

import type {
  ApiResponse,
  ProtectionStatus,
  EngineStats,
  ModuleStatus,
  ThreatEvent,
  ScanProgress,
  QuarantineEntry,
  Alert,
  ThreatIntelFeed,
  SystemConfig,
  LicenseInfo,
  AuthSession,
  LoginRequest,
  LoginResponse,
} from '@/types';

// ============================================================================
// BASE CLIENT
// ============================================================================

const BASE_URL = '/api/v1';

class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly statusText: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };

  const token = sessionStorage.getItem('phantom_token');
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const csrfToken = document.cookie
    .split('; ')
    .find(c => c.startsWith('csrf_token='))
    ?.split('=')[1];
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'same-origin',
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new ApiError(
      response.status,
      response.statusText,
      body || `Request failed: ${response.status} ${response.statusText}`,
    );
  }

  const contentType = response.headers.get('content-type');
  if (contentType?.includes('application/json')) {
    const json = (await response.json()) as ApiResponse<T>;
    if (json.success === false) {
      throw new ApiError(response.status, response.statusText, json.error ?? 'Unknown error');
    }
    return (json.data ?? json) as T;
  }

  return (await response.text()) as unknown as T;
}

function get<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'GET' });
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
  });
}

function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PUT',
    body: body ? JSON.stringify(body) : undefined,
  });
}

// ============================================================================
// AUTH
// ============================================================================

export const auth = {
  login: (creds: LoginRequest) => post<LoginResponse>('/auth/login', creds),
  logout: () => post<void>('/auth/logout'),
  session: () => get<AuthSession>('/auth/session'),
};

// ============================================================================
// STATUS & HEALTH
// ============================================================================

export const status = {
  health: () => get<{ status: string }>('/health'),
  protection: () => get<ProtectionStatus>('/status'),
  stats: () => get<EngineStats>('/stats'),
  modules: () => get<ModuleStatus[]>('/modules'),
  license: () => get<LicenseInfo>('/license'),
};

// ============================================================================
// REAL-TIME PROTECTION
// ============================================================================

export const rtp = {
  status: () => get<{ active: boolean; state: string }>('/rtp/status'),
  toggle: () => post<{ active: boolean }>('/rtp/toggle'),
};

// ============================================================================
// SCAN
// ============================================================================

export const scan = {
  quick: () => post<{ jobId: string }>('/scan/quick'),
  full: () => post<{ jobId: string }>('/scan/full'),
  custom: (paths: string[]) => post<{ jobId: string }>('/scan/custom', { paths }),
  stop: (jobId?: string) => post<void>('/scan/stop', jobId ? { jobId } : undefined),
  progress: () => get<ScanProgress>('/scan/progress'),
};

// ============================================================================
// THREATS
// ============================================================================

export const threats = {
  list: () => get<ThreatEvent[]>('/threats'),
  get: (id: string) => get<ThreatEvent>(`/threats/${encodeURIComponent(id)}`),
};

// ============================================================================
// QUARANTINE
// ============================================================================

export const quarantine = {
  list: () => get<QuarantineEntry[]>('/quarantine'),
  restore: (id: string) => post<void>('/quarantine/restore', { id }),
  remove: (id: string) => post<void>('/quarantine/delete', { id }),
};

// ============================================================================
// ALERTS
// ============================================================================

export const alerts = {
  list: () => get<Alert[]>('/alerts'),
  acknowledge: (id: string) => post<void>(`/alerts/${encodeURIComponent(id)}/acknowledge`),
};

// ============================================================================
// THREAT INTELLIGENCE
// ============================================================================

export const threatIntel = {
  feeds: () => get<ThreatIntelFeed[]>('/threatintel/feeds'),
};

// ============================================================================
// CONFIGURATION
// ============================================================================

export const config = {
  get: () => get<SystemConfig>('/config'),
  update: (cfg: Partial<SystemConfig>) => put<SystemConfig>('/config', cfg),
};

// ============================================================================
// SSE (SERVER-SENT EVENTS)
// ============================================================================

export function connectEventStream(
  onEvent: (event: { type: string; data: unknown }) => void,
  onError?: (error: Event) => void,
): EventSource {
  const source = new EventSource(`${BASE_URL}/events/stream`);

  source.onmessage = (e) => {
    try {
      const parsed = JSON.parse(e.data as string) as { type: string; data: unknown };
      onEvent(parsed);
    } catch {
      // Non-JSON heartbeat, ignore
    }
  };

  source.onerror = (e) => {
    onError?.(e);
  };

  return source;
}

// ============================================================================
// RE-EXPORT
// ============================================================================

export { ApiError };
