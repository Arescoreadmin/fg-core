'use client';

import { useEffect, useState } from 'react';
import { config } from '@/lib/config';
import type { DashboardData, HealthData } from '@/lib/api';

interface ConnectionStatus {
  connected: boolean;
  error?: string;
  health?: HealthData;
}

export default function Dashboard() {
  const [status, setStatus] = useState<ConnectionStatus>({ connected: false });
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function checkConnection() {
      try {
        // Check health
        const healthRes = await fetch(`${config.apiUrl}/health`);
        if (!healthRes.ok) {
          throw new Error(`Health check failed: ${healthRes.status}`);
        }
        const health = await healthRes.json();

        // Fetch dashboard data
        const dashRes = await fetch(`${config.apiUrl}/api/v1/dashboard`);
        if (!dashRes.ok) {
          throw new Error(`Dashboard fetch failed: ${dashRes.status}`);
        }
        const dashData = await dashRes.json();

        setStatus({ connected: true, health });
        setDashboard(dashData);
      } catch (err) {
        setStatus({
          connected: false,
          error: err instanceof Error ? err.message : 'Unknown error',
        });
      } finally {
        setLoading(false);
      }
    }

    checkConnection();
    // Refresh every 30 seconds
    const interval = setInterval(checkConnection, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <main style={styles.main}>
      <header style={styles.header}>
        <h1 style={styles.title}>FrostGate Console</h1>
        <div style={styles.statusBadge}>
          <span
            style={{
              ...styles.statusDot,
              backgroundColor: status.connected ? '#22c55e' : '#ef4444',
            }}
          />
          {status.connected ? 'Connected' : 'Disconnected'}
        </div>
      </header>

      {loading ? (
        <div style={styles.loading}>Loading...</div>
      ) : status.error ? (
        <div style={styles.error}>
          <h2>Connection Error</h2>
          <p>{status.error}</p>
          <p style={styles.hint}>
            Make sure admin-gateway is running at {config.apiUrl}
          </p>
        </div>
      ) : (
        <div style={styles.content}>
          {/* Connection Info */}
          <section style={styles.section}>
            <h2 style={styles.sectionTitle}>Service Status</h2>
            <div style={styles.infoGrid}>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Service</span>
                <span style={styles.infoValue}>{status.health?.service}</span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>Version</span>
                <span style={styles.infoValue}>{status.health?.version}</span>
              </div>
              <div style={styles.infoItem}>
                <span style={styles.infoLabel}>API URL</span>
                <span style={styles.infoValue}>{config.apiUrl}</span>
              </div>
            </div>
          </section>

          {/* Dashboard Stats */}
          <section style={styles.section}>
            <h2 style={styles.sectionTitle}>Dashboard</h2>
            <div style={styles.statsGrid}>
              <div style={styles.statCard}>
                <span style={styles.statValue}>
                  {dashboard?.stats.total_requests ?? 0}
                </span>
                <span style={styles.statLabel}>Total Requests</span>
              </div>
              <div style={styles.statCard}>
                <span style={styles.statValue}>
                  {dashboard?.stats.blocked_requests ?? 0}
                </span>
                <span style={styles.statLabel}>Blocked Requests</span>
              </div>
              <div style={styles.statCard}>
                <span style={styles.statValue}>
                  {dashboard?.stats.active_tenants ?? 0}
                </span>
                <span style={styles.statLabel}>Active Tenants</span>
              </div>
              <div style={styles.statCard}>
                <span style={styles.statValue}>
                  {dashboard?.stats.active_keys ?? 0}
                </span>
                <span style={styles.statLabel}>Active Keys</span>
              </div>
            </div>
          </section>

          {/* Placeholder */}
          <section style={styles.section}>
            <h2 style={styles.sectionTitle}>Recent Events</h2>
            <p style={styles.placeholder}>
              No recent events. This is a placeholder dashboard.
            </p>
          </section>
        </div>
      )}
    </main>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  main: {
    minHeight: '100vh',
    padding: '2rem',
    maxWidth: '1200px',
    margin: '0 auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '2rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid var(--border)',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
  },
  statusBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.875rem',
    color: 'var(--muted)',
  },
  statusDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
  },
  loading: {
    textAlign: 'center',
    padding: '4rem',
    color: 'var(--muted)',
  },
  error: {
    padding: '2rem',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: '8px',
    textAlign: 'center',
  },
  hint: {
    marginTop: '1rem',
    color: 'var(--muted)',
    fontSize: '0.875rem',
  },
  content: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2rem',
  },
  section: {
    padding: '1.5rem',
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
  },
  sectionTitle: {
    fontSize: '1rem',
    fontWeight: 600,
    marginBottom: '1rem',
  },
  infoGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1rem',
  },
  infoItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  infoLabel: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
    textTransform: 'uppercase',
  },
  infoValue: {
    fontSize: '0.875rem',
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    gap: '1rem',
  },
  statCard: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    padding: '1.5rem',
    backgroundColor: 'rgba(37, 99, 235, 0.05)',
    borderRadius: '8px',
  },
  statValue: {
    fontSize: '2rem',
    fontWeight: 700,
    color: 'var(--primary)',
  },
  statLabel: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
    marginTop: '0.5rem',
  },
  placeholder: {
    color: 'var(--muted)',
    fontStyle: 'italic',
  },
};
