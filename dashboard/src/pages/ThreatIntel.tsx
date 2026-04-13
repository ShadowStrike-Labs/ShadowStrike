/* ============================================================================
 * ShadowStrike Phantom Dashboard — Threat Intelligence Page
 * ============================================================================ */

import { useCallback } from 'react';
import { Database, Globe, Hash, Link, Server, FileCode } from 'lucide-react';
import { PageHeader, Card, Badge, Table, StatCard, EmptyState } from '@/components/ui';
import { usePolling } from '@/hooks';
import { threatIntel } from '@/api/client';
import type { ThreatIntelFeed } from '@/types';
import { formatRelativeTime, formatNumber } from '@/utils/format';

function feedTypeIcon(type: string) {
  switch (type) {
    case 'hash':   return <Hash className="h-4 w-4 text-phantom-400" />;
    case 'url':    return <Link className="h-4 w-4 text-blue-400" />;
    case 'ip':     return <Server className="h-4 w-4 text-green-400" />;
    case 'domain': return <Globe className="h-4 w-4 text-orange-400" />;
    case 'yara':   return <FileCode className="h-4 w-4 text-yellow-400" />;
    default:       return <Database className="h-4 w-4 text-gray-400" />;
  }
}

export default function ThreatIntelPage() {
  const fetchFeeds = useCallback(() => threatIntel.feeds(), []);
  const { data: feeds, loading } = usePolling(fetchFeeds, 30000);

  const totalIndicators = (feeds ?? []).reduce((sum, f) => sum + f.totalIndicators, 0);
  const activeFeedCount = (feeds ?? []).filter((f) => f.enabled).length;

  const columns = [
    {
      key: 'type',
      header: '',
      render: (f: ThreatIntelFeed) => feedTypeIcon(f.type),
      className: 'w-10',
    },
    {
      key: 'name',
      header: 'Feed',
      render: (f: ThreatIntelFeed) => (
        <div>
          <span className="font-medium text-white">{f.name}</span>
          <span className="block text-xs text-gray-500">{f.provider}</span>
        </div>
      ),
    },
    {
      key: 'type-label',
      header: 'Type',
      render: (f: ThreatIntelFeed) => (
        <Badge variant="default">{f.type.toUpperCase()}</Badge>
      ),
    },
    {
      key: 'indicators',
      header: 'Indicators',
      render: (f: ThreatIntelFeed) => (
        <span className="font-mono text-sm text-white">{formatNumber(f.totalIndicators)}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (f: ThreatIntelFeed) => (
        <Badge variant={f.enabled ? 'success' : 'default'}>
          {f.enabled ? 'Active' : 'Disabled'}
        </Badge>
      ),
    },
    {
      key: 'updated',
      header: 'Last Update',
      render: (f: ThreatIntelFeed) => (
        <span className="text-xs text-gray-500">{formatRelativeTime(f.lastUpdate)}</span>
      ),
    },
  ];

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Threat Intelligence"
        description="IOC feeds, YARA rules, and indicator management"
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatCard
          label="Total Indicators"
          value={formatNumber(totalIndicators)}
          icon={<Database className="h-4 w-4" />}
        />
        <StatCard
          label="Active Feeds"
          value={activeFeedCount}
          sublabel={`of ${feeds?.length ?? 0} configured`}
          icon={<Globe className="h-4 w-4" />}
        />
        <StatCard
          label="Feed Types"
          value="5"
          sublabel="Hash, URL, IP, Domain, YARA"
          icon={<Hash className="h-4 w-4" />}
        />
      </div>

      {loading ? (
        <Card className="py-16 text-center text-gray-500">Loading feeds...</Card>
      ) : (feeds?.length ?? 0) === 0 ? (
        <EmptyState
          icon={<Database className="h-12 w-12" />}
          title="No threat intel feeds configured"
          description="Add IOC feeds to enhance detection capabilities."
        />
      ) : (
        <Table
          columns={columns}
          data={feeds ?? []}
          keyExtractor={(f) => f.id}
        />
      )}
    </div>
  );
}
