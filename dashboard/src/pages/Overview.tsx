/* ============================================================================
 * ShadowStrike Phantom Dashboard — Overview Page
 * ============================================================================
 * The landing page showing real-time protection status, threat trends,
 * engine stats, and recent activity.
 */

import { useCallback } from 'react';
import {
  Shield,
  ShieldAlert,
  Activity,
  HardDrive,
  Clock,
  Zap,
  AlertTriangle,
  FolderLock,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { Card, StatCard, Badge, StatusIndicator, PageHeader } from '@/components/ui';
import { usePolling } from '@/hooks';
import { status as statusApi, threats as threatsApi, alerts as alertsApi } from '@/api/client';
import type { ProtectionStatus, EngineStats, ThreatEvent, Alert } from '@/types';
import {
  formatBytes,
  formatUptime,
  formatRelativeTime,
  formatNumber,
  severityBadge,
  stateColor,
} from '@/utils/format';

// ============================================================================
// Protection Shield Hero
// ============================================================================

function ProtectionHero({ status }: { status: ProtectionStatus | null }) {
  const isActive = status?.state === 'ACTIVE';
  const stateLabel = status?.state ?? 'CONNECTING';

  return (
    <Card className="relative overflow-hidden">
      {/* Background glow */}
      <div
        className={`absolute -right-20 -top-20 h-64 w-64 rounded-full blur-3xl opacity-10 ${
          isActive ? 'bg-green-500' : 'bg-red-500'
        }`}
      />

      <div className="relative flex items-center gap-6">
        {/* Shield icon */}
        <div
          className={`flex h-20 w-20 items-center justify-center rounded-2xl ${
            isActive
              ? 'bg-green-500/10 ring-1 ring-green-500/30'
              : 'bg-red-500/10 ring-1 ring-red-500/30'
          }`}
        >
          {isActive ? (
            <Shield className="h-10 w-10 text-green-400" />
          ) : (
            <ShieldAlert className="h-10 w-10 text-red-400" />
          )}
        </div>

        <div className="flex-1">
          <div className="flex items-center gap-3">
            <StatusIndicator active={isActive} />
            <h2 className={`text-xl font-bold ${stateColor(stateLabel)}`}>
              {isActive ? 'Protected' : stateLabel}
            </h2>
          </div>
          <p className="mt-1 text-sm text-gray-400">
            {isActive
              ? 'All protection modules are active and monitoring.'
              : 'Protection is not fully active. Check module status.'}
          </p>
          <div className="mt-3 flex flex-wrap gap-4 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              Uptime: {status ? formatUptime(status.uptime) : '—'}
            </span>
            <span>Engine: {status?.engineVersion ?? '—'}</span>
            <span>Signatures: {status?.signatureVersion ?? '—'}</span>
            <span>
              Last scan: {status?.lastScanTime ? formatRelativeTime(status.lastScanTime) : 'Never'}
            </span>
          </div>
        </div>

        {/* Tier badge */}
        <Badge variant="info" className="self-start">
          {status?.tier?.toUpperCase() ?? 'COMMUNITY'}
        </Badge>
      </div>
    </Card>
  );
}

// ============================================================================
// Stats Row
// ============================================================================

function StatsRow({ stats }: { stats: EngineStats | null }) {
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <StatCard
        label="Total Scans"
        value={formatNumber(stats?.totalScans ?? 0)}
        icon={<Activity className="h-4 w-4" />}
      />
      <StatCard
        label="Threats Detected"
        value={formatNumber(stats?.totalThreats ?? 0)}
        icon={<AlertTriangle className="h-4 w-4" />}
      />
      <StatCard
        label="Data Scanned"
        value={formatBytes(stats?.bytesScanned ?? 0)}
        icon={<HardDrive className="h-4 w-4" />}
      />
      <StatCard
        label="Avg Scan Time"
        value={`${stats?.avgScanTimeMs ?? 0}ms`}
        icon={<Zap className="h-4 w-4" />}
      />
    </div>
  );
}

// ============================================================================
// Threat Trend Chart
// ============================================================================

const DEMO_TREND = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  threats: Math.floor(Math.random() * 8),
  scans: Math.floor(Math.random() * 150 + 50),
}));

function ThreatTrendChart() {
  return (
    <Card className="col-span-2">
      <h3 className="mb-4 text-sm font-semibold text-gray-300">Threat Activity (24h)</h3>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={DEMO_TREND}>
            <defs>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#5a6ef2" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#5a6ef2" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2e3142" />
            <XAxis
              dataKey="hour"
              stroke="#4b5563"
              tick={{ fontSize: 10 }}
              interval={3}
            />
            <YAxis stroke="#4b5563" tick={{ fontSize: 10 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e2029',
                borderColor: '#2e3142',
                borderRadius: 8,
                fontSize: 12,
              }}
            />
            <Area
              type="monotone"
              dataKey="scans"
              stroke="#5a6ef2"
              fill="url(#scanGrad)"
              strokeWidth={2}
              name="Scans"
            />
            <Area
              type="monotone"
              dataKey="threats"
              stroke="#ef4444"
              fill="url(#threatGrad)"
              strokeWidth={2}
              name="Threats"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

// ============================================================================
// Detection Breakdown (Pie)
// ============================================================================

const DETECTION_DATA = [
  { name: 'Signature', value: 45, color: '#5a6ef2' },
  { name: 'Heuristic', value: 25, color: '#f97316' },
  { name: 'ML/AI',     value: 20, color: '#22c55e' },
  { name: 'Behavior',  value: 10, color: '#eab308' },
];

function DetectionBreakdown() {
  return (
    <Card>
      <h3 className="mb-4 text-sm font-semibold text-gray-300">Detection Methods</h3>
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={DETECTION_DATA}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
            >
              {DETECTION_DATA.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e2029',
                borderColor: '#2e3142',
                borderRadius: 8,
                fontSize: 12,
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-2 flex flex-wrap justify-center gap-3">
        {DETECTION_DATA.map((d) => (
          <div key={d.name} className="flex items-center gap-1.5 text-xs text-gray-400">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
            {d.name}
          </div>
        ))}
      </div>
    </Card>
  );
}

// ============================================================================
// Recent Threats List
// ============================================================================

function RecentThreats({ threats }: { threats: ThreatEvent[] }) {
  const recent = threats.slice(0, 8);

  return (
    <Card className="col-span-2">
      <h3 className="mb-4 text-sm font-semibold text-gray-300">Recent Detections</h3>
      {recent.length === 0 ? (
        <div className="flex items-center justify-center py-8 text-sm text-gray-500">
          <Shield className="mr-2 h-4 w-4" />
          No recent threats — environment is clean
        </div>
      ) : (
        <div className="space-y-2">
          {recent.map((t) => (
            <div
              key={t.id}
              className="flex items-center gap-3 rounded-lg bg-surface-overlay px-3 py-2"
            >
              <AlertTriangle className="h-4 w-4 flex-shrink-0 text-red-400" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white truncate">{t.threatName}</span>
                  <Badge
                    variant={
                      t.severity === 'critical'
                        ? 'danger'
                        : t.severity === 'high'
                          ? 'warning'
                          : 'default'
                    }
                  >
                    {t.severity}
                  </Badge>
                </div>
                <span className="text-xs text-gray-500 truncate block">{t.filePath}</span>
              </div>
              <span className={`text-xs font-mono ${severityBadge(t.severity).split(' ')[1]}`}>
                {t.action}
              </span>
              <span className="text-xs text-gray-600">{formatRelativeTime(t.timestamp)}</span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ============================================================================
// Recent Alerts
// ============================================================================

function RecentAlerts({ alerts }: { alerts: Alert[] }) {
  const recent = alerts.filter((a) => !a.acknowledged).slice(0, 5);

  return (
    <Card>
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300">Unacknowledged Alerts</h3>
        {recent.length > 0 && (
          <Badge variant="danger">{recent.length}</Badge>
        )}
      </div>
      {recent.length === 0 ? (
        <div className="flex items-center justify-center py-8 text-sm text-gray-500">
          <FolderLock className="mr-2 h-4 w-4" />
          All alerts acknowledged
        </div>
      ) : (
        <div className="space-y-2">
          {recent.map((a) => (
            <div key={a.id} className="rounded-lg bg-surface-overlay px-3 py-2">
              <div className="flex items-center gap-2">
                <span className={`text-sm font-medium ${
                  a.priority === 'critical' ? 'text-red-400' :
                  a.priority === 'high' ? 'text-orange-400' : 'text-gray-300'
                }`}>
                  {a.title}
                </span>
              </div>
              <span className="text-xs text-gray-500">{formatRelativeTime(a.timestamp)}</span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ============================================================================
// Overview Page
// ============================================================================

export default function OverviewPage() {
  const fetchStatus = useCallback(() => statusApi.protection(), []);
  const fetchStats = useCallback(() => statusApi.stats(), []);
  const fetchThreats = useCallback(() => threatsApi.list(), []);
  const fetchAlerts = useCallback(() => alertsApi.list(), []);

  const { data: protectionStatus } = usePolling(fetchStatus, 5000);
  const { data: stats } = usePolling(fetchStats, 5000);
  const { data: threatList } = usePolling(fetchThreats, 10000);
  const { data: alertList } = usePolling(fetchAlerts, 10000);

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Dashboard"
        description="Real-time endpoint protection overview"
      />

      <ProtectionHero status={protectionStatus} />
      <StatsRow stats={stats} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <ThreatTrendChart />
        <DetectionBreakdown />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <RecentThreats threats={threatList ?? []} />
        <RecentAlerts alerts={alertList ?? []} />
      </div>
    </div>
  );
}
