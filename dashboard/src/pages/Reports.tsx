/* ============================================================================
 * ShadowStrike Phantom Dashboard — Reports Page
 * ============================================================================ */

import { useCallback } from 'react';
import { BarChart3, TrendingUp, Shield, Clock, Calendar } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
} from 'recharts';
import { PageHeader, Card, StatCard } from '@/components/ui';
import { usePolling } from '@/hooks';
import { status as statusApi } from '@/api/client';
import { formatNumber, formatBytes } from '@/utils/format';

// Demo data — in production, the REST API would provide historical data
const WEEKLY_THREATS = [
  { day: 'Mon', threats: 12, scans: 340 },
  { day: 'Tue', threats: 8,  scans: 290 },
  { day: 'Wed', threats: 15, scans: 410 },
  { day: 'Thu', threats: 6,  scans: 380 },
  { day: 'Fri', threats: 22, scans: 520 },
  { day: 'Sat', threats: 3,  scans: 180 },
  { day: 'Sun', threats: 1,  scans: 120 },
];

const MONTHLY_TREND = Array.from({ length: 30 }, (_, i) => ({
  day: i + 1,
  detections: Math.floor(Math.random() * 20 + 2),
  cleaned: Math.floor(Math.random() * 15 + 1),
}));

const CHART_TOOLTIP_STYLE = {
  backgroundColor: '#1e2029',
  borderColor: '#2e3142',
  borderRadius: 8,
  fontSize: 12,
};

export default function ReportsPage() {
  const fetchStats = useCallback(() => statusApi.stats(), []);
  const { data: stats } = usePolling(fetchStats, 30000);

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Reports"
        description="Security analytics and trend analysis"
      />

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Total Scans"
          value={formatNumber(stats?.totalScans ?? 0)}
          icon={<Shield className="h-4 w-4" />}
        />
        <StatCard
          label="Threats Blocked"
          value={formatNumber(stats?.totalThreats ?? 0)}
          icon={<BarChart3 className="h-4 w-4" />}
        />
        <StatCard
          label="Data Analyzed"
          value={formatBytes(stats?.bytesScanned ?? 0)}
          icon={<TrendingUp className="h-4 w-4" />}
        />
        <StatCard
          label="Cache Efficiency"
          value={
            stats && (stats.cacheHits + stats.cacheMisses) > 0
              ? `${((stats.cacheHits / (stats.cacheHits + stats.cacheMisses)) * 100).toFixed(1)}%`
              : '—'
          }
          icon={<Clock className="h-4 w-4" />}
        />
      </div>

      {/* Weekly threat bar chart */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <h3 className="mb-4 text-sm font-semibold text-gray-300">
            <Calendar className="mr-1.5 inline-block h-4 w-4" />
            Weekly Threat Activity
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={WEEKLY_THREATS}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2e3142" />
                <XAxis dataKey="day" stroke="#4b5563" tick={{ fontSize: 11 }} />
                <YAxis stroke="#4b5563" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Bar dataKey="threats" fill="#ef4444" radius={[4, 4, 0, 0]} name="Threats" />
                <Bar dataKey="scans" fill="#5a6ef2" radius={[4, 4, 0, 0]} name="Scans" opacity={0.5} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <h3 className="mb-4 text-sm font-semibold text-gray-300">
            <TrendingUp className="mr-1.5 inline-block h-4 w-4" />
            30-Day Detection Trend
          </h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={MONTHLY_TREND}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2e3142" />
                <XAxis dataKey="day" stroke="#4b5563" tick={{ fontSize: 11 }} />
                <YAxis stroke="#4b5563" tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Line
                  type="monotone"
                  dataKey="detections"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  name="Detections"
                />
                <Line
                  type="monotone"
                  dataKey="cleaned"
                  stroke="#22c55e"
                  strokeWidth={2}
                  dot={false}
                  name="Cleaned"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Engine performance */}
      <Card>
        <h3 className="mb-4 text-sm font-semibold text-gray-300">Engine Performance</h3>
        <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
          <div>
            <div className="text-2xl font-bold text-white">{stats?.avgScanTimeMs ?? 0}ms</div>
            <div className="text-xs text-gray-500">Avg scan time per file</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{formatNumber(stats?.cacheHits ?? 0)}</div>
            <div className="text-xs text-gray-500">Cache hits (whitelist/hash)</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{formatNumber(stats?.filesScanned ?? 0)}</div>
            <div className="text-xs text-gray-500">Files processed lifetime</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-white">{formatBytes(stats?.bytesScanned ?? 0)}</div>
            <div className="text-xs text-gray-500">Total data analyzed</div>
          </div>
        </div>
      </Card>
    </div>
  );
}
