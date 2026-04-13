/* ============================================================================
 * ShadowStrike Phantom Dashboard — Settings Page
 * ============================================================================ */

import { useCallback, useState, useEffect } from 'react';
import {
  Shield,
  Cloud,
  Bell,
  FolderLock,
  Trash2,
  Plus,
  Save,
  Info,
  Eye,
} from 'lucide-react';
import { PageHeader, Card, Button, Badge } from '@/components/ui';
import { usePolling } from '@/hooks';
import {
  config as configApi,
  status as statusApi,
  rtp as rtpApi,
} from '@/api/client';
import type { SystemConfig } from '@/types';
import { cn } from '@/utils/format';

// ============================================================================
// Toggle Switch
// ============================================================================

function Toggle({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
        'focus:outline-none focus:ring-2 focus:ring-phantom-500/40',
        'disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'bg-phantom-600' : 'bg-surface-subtle',
      )}
    >
      <span
        className={cn(
          'inline-block h-4 w-4 rounded-full bg-white transition-transform',
          checked ? 'translate-x-6' : 'translate-x-1',
        )}
      />
    </button>
  );
}

// ============================================================================
// Setting Row
// ============================================================================

function SettingRow({
  icon,
  label,
  description,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between py-4">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 text-gray-500">{icon}</div>
        <div>
          <div className="text-sm font-medium text-white">{label}</div>
          <div className="text-xs text-gray-500">{description}</div>
        </div>
      </div>
      <div>{children}</div>
    </div>
  );
}

// ============================================================================
// Settings Page
// ============================================================================

export default function SettingsPage() {
  const fetchConfig = useCallback(() => configApi.get(), []);
  const fetchLicense = useCallback(() => statusApi.license(), []);
  const { data: serverConfig } = usePolling(fetchConfig, 30000);
  const { data: license } = usePolling(fetchLicense, 60000);

  const [localConfig, setLocalConfig] = useState<SystemConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [newExclusion, setNewExclusion] = useState('');
  const [rtpToggling, setRtpToggling] = useState(false);

  useEffect(() => {
    if (serverConfig && !localConfig) {
      setLocalConfig(serverConfig);
    }
  }, [serverConfig, localConfig]);

  function updateField<K extends keyof SystemConfig>(key: K, value: SystemConfig[K]) {
    setLocalConfig((prev) => (prev ? { ...prev, [key]: value } : null));
  }

  async function saveConfig() {
    if (!localConfig) return;
    setSaving(true);
    try {
      await configApi.update(localConfig);
    } catch {
      // handled
    } finally {
      setSaving(false);
    }
  }

  async function toggleRTP() {
    setRtpToggling(true);
    try {
      await rtpApi.toggle();
    } catch {
      // handled
    } finally {
      setRtpToggling(false);
    }
  }

  function addExclusion() {
    if (!newExclusion.trim() || !localConfig) return;
    updateField('exclusions', [...localConfig.exclusions, newExclusion.trim()]);
    setNewExclusion('');
  }

  function removeExclusion(idx: number) {
    if (!localConfig) return;
    updateField(
      'exclusions',
      localConfig.exclusions.filter((_, i) => i !== idx),
    );
  }

  const cfg = localConfig;

  return (
    <div className="animate-fade-in space-y-6">
      <PageHeader
        title="Settings"
        description="Configure protection, scanning, and notifications"
        action={
          <Button
            variant="primary"
            onClick={() => void saveConfig()}
            loading={saving}
          >
            <Save className="h-4 w-4" /> Save Changes
          </Button>
        }
      />

      {/* License info */}
      <Card>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-phantom-400" />
            <div>
              <div className="text-sm font-medium text-white">
                Phantom {license?.tier?.replace(/^\w/, (c: string) => c.toUpperCase()) ?? 'Community'}
              </div>
              <div className="text-xs text-gray-500">
                {license?.features?.length ?? 0} features enabled
              </div>
            </div>
          </div>
          <Badge variant="info">{license?.tier?.toUpperCase() ?? 'COMMUNITY'}</Badge>
        </div>
      </Card>

      {/* Protection settings */}
      <Card>
        <h3 className="mb-2 text-sm font-semibold text-gray-300">Protection</h3>
        <div className="divide-y divide-border/50">
          <SettingRow
            icon={<Shield className="h-4 w-4" />}
            label="Real-Time Protection"
            description="Monitor file system activity and block threats in real time"
          >
            <Toggle
              checked={cfg?.realTimeProtection ?? true}
              onChange={(v) => {
                updateField('realTimeProtection', v);
                void toggleRTP();
              }}
              disabled={rtpToggling}
            />
          </SettingRow>

          <SettingRow
            icon={<Cloud className="h-4 w-4" />}
            label="Cloud Lookup"
            description="Query cloud reputation databases for unknown files"
          >
            <Toggle
              checked={cfg?.cloudLookup ?? false}
              onChange={(v) => updateField('cloudLookup', v)}
            />
          </SettingRow>

          <SettingRow
            icon={<FolderLock className="h-4 w-4" />}
            label="Auto-Quarantine"
            description="Automatically quarantine detected threats"
          >
            <Toggle
              checked={cfg?.autoQuarantine ?? true}
              onChange={(v) => updateField('autoQuarantine', v)}
            />
          </SettingRow>

          <SettingRow
            icon={<Eye className="h-4 w-4" />}
            label="Scan Archives"
            description="Extract and scan contents of ZIP, RAR, 7z, and other archives"
          >
            <Toggle
              checked={cfg?.scanArchives ?? true}
              onChange={(v) => updateField('scanArchives', v)}
            />
          </SettingRow>
        </div>
      </Card>

      {/* Notification settings */}
      <Card>
        <h3 className="mb-2 text-sm font-semibold text-gray-300">Notifications</h3>
        <div className="divide-y divide-border/50">
          <SettingRow
            icon={<Bell className="h-4 w-4" />}
            label="Desktop Notifications"
            description="Show system tray balloon and toast notifications for threats"
          >
            <Toggle
              checked={cfg?.notificationsEnabled ?? true}
              onChange={(v) => updateField('notificationsEnabled', v)}
            />
          </SettingRow>

          <SettingRow
            icon={<Info className="h-4 w-4" />}
            label="Telemetry"
            description="Share anonymous detection statistics to improve protection"
          >
            <Toggle
              checked={cfg?.telemetryEnabled ?? false}
              onChange={(v) => updateField('telemetryEnabled', v)}
            />
          </SettingRow>
        </div>
      </Card>

      {/* Exclusions */}
      <Card>
        <h3 className="mb-4 text-sm font-semibold text-gray-300">Scan Exclusions</h3>
        <div className="space-y-2">
          {(cfg?.exclusions ?? []).map((exc, idx) => (
            <div
              key={`${exc}-${idx}`}
              className="flex items-center justify-between rounded-lg bg-surface-overlay px-3 py-2"
            >
              <span className="font-mono text-xs text-gray-300">{exc}</span>
              <button
                onClick={() => removeExclusion(idx)}
                className="text-gray-500 hover:text-red-400 transition-colors"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Add path or pattern (e.g., C:\Dev\*, *.log)"
              value={newExclusion}
              onChange={(e) => setNewExclusion(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addExclusion()}
              className="flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-phantom-500 focus:outline-none"
            />
            <Button variant="secondary" size="md" onClick={addExclusion}>
              <Plus className="h-4 w-4" /> Add
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
