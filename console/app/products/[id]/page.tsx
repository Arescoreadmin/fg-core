'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  fetchProduct,
  updateProduct,
  testProductConnection,
  type Product,
  type TestConnectionResult,
} from '@/lib/api';

interface ProductState {
  product: Product | null;
  loading: boolean;
  error?: string;
}

interface ConnectionTestState {
  testing: boolean;
  result: TestConnectionResult | null;
  error?: string;
}

export default function ProductDetailPage() {
  const params = useParams();
  const router = useRouter();
  const productId = Number(params.id);

  const [state, setState] = useState<ProductState>({
    product: null,
    loading: true,
  });

  const [testState, setTestState] = useState<ConnectionTestState>({
    testing: false,
    result: null,
  });

  const [editing, setEditing] = useState(false);
  const [editForm, setEditForm] = useState({
    name: '',
    env: '',
    owner: '',
    enabled: true,
  });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    async function loadProduct() {
      try {
        const product = await fetchProduct(productId);
        setState({ product, loading: false });
        setEditForm({
          name: product.name,
          env: product.env,
          owner: product.owner || '',
          enabled: product.enabled,
        });
      } catch (err) {
        setState({
          product: null,
          loading: false,
          error: err instanceof Error ? err.message : 'Failed to load product',
        });
      }
    }
    loadProduct();
  }, [productId]);

  const handleTestConnection = async () => {
    setTestState({ testing: true, result: null });
    try {
      const result = await testProductConnection(productId);
      setTestState({ testing: false, result });
    } catch (err) {
      setTestState({
        testing: false,
        result: null,
        error: err instanceof Error ? err.message : 'Failed to test connection',
      });
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const updated = await updateProduct(productId, {
        name: editForm.name,
        env: editForm.env,
        owner: editForm.owner || undefined,
        enabled: editForm.enabled,
      });
      setState({ product: updated, loading: false });
      setEditing(false);
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to update product');
    } finally {
      setSaving(false);
    }
  };

  const handleToggleEnabled = async () => {
    if (!state.product) return;
    setSaving(true);
    try {
      const updated = await updateProduct(productId, {
        enabled: !state.product.enabled,
      });
      setState({ product: updated, loading: false });
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to update product');
    } finally {
      setSaving(false);
    }
  };

  if (state.loading) {
    return (
      <main style={styles.main}>
        <div style={styles.loading}>Loading product...</div>
      </main>
    );
  }

  if (state.error || !state.product) {
    return (
      <main style={styles.main}>
        <div style={styles.error}>
          <h2>Error</h2>
          <p>{state.error || 'Product not found'}</p>
          <Link href="/products" style={styles.backButton}>
            Back to Products
          </Link>
        </div>
      </main>
    );
  }

  const product = state.product;

  return (
    <main style={styles.main}>
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <Link href="/products" style={styles.backLink}>
            Back to Products
          </Link>
          <div style={styles.titleRow}>
            <h1 style={styles.title}>{product.name}</h1>
            <span
              style={{
                ...styles.statusBadge,
                backgroundColor: product.enabled ? '#dcfce7' : '#fee2e2',
                color: product.enabled ? '#166534' : '#991b1b',
              }}
            >
              {product.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <code style={styles.slug}>{product.slug}</code>
        </div>
        <div style={styles.headerActions}>
          <button
            onClick={handleToggleEnabled}
            disabled={saving}
            style={{
              ...styles.toggleButton,
              backgroundColor: product.enabled ? '#fee2e2' : '#dcfce7',
              color: product.enabled ? '#991b1b' : '#166534',
            }}
          >
            {product.enabled ? 'Disable' : 'Enable'}
          </button>
          <button
            onClick={() => setEditing(!editing)}
            style={styles.editButton}
          >
            {editing ? 'Cancel' : 'Edit'}
          </button>
        </div>
      </header>

      <div style={styles.content}>
        {/* Product Details */}
        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Product Details</h2>

          {editing ? (
            <div style={styles.editForm}>
              <div style={styles.formGroup}>
                <label style={styles.label}>Name</label>
                <input
                  type="text"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                  style={styles.input}
                />
              </div>
              <div style={styles.formGroup}>
                <label style={styles.label}>Environment</label>
                <select
                  value={editForm.env}
                  onChange={(e) => setEditForm({ ...editForm, env: e.target.value })}
                  style={styles.select}
                >
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                  <option value="test">Test</option>
                </select>
              </div>
              <div style={styles.formGroup}>
                <label style={styles.label}>Owner</label>
                <input
                  type="text"
                  value={editForm.owner}
                  onChange={(e) => setEditForm({ ...editForm, owner: e.target.value })}
                  style={styles.input}
                />
              </div>
              <button
                onClick={handleSave}
                disabled={saving}
                style={styles.saveButton}
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          ) : (
            <div style={styles.detailsGrid}>
              <div style={styles.detailItem}>
                <span style={styles.detailLabel}>Slug</span>
                <code style={styles.detailCode}>{product.slug}</code>
              </div>
              <div style={styles.detailItem}>
                <span style={styles.detailLabel}>Environment</span>
                <span style={styles.envBadge}>{product.env}</span>
              </div>
              <div style={styles.detailItem}>
                <span style={styles.detailLabel}>Owner</span>
                <span style={styles.detailValue}>{product.owner || '-'}</span>
              </div>
              <div style={styles.detailItem}>
                <span style={styles.detailLabel}>Tenant</span>
                <code style={styles.detailCode}>{product.tenant_id}</code>
              </div>
              <div style={styles.detailItem}>
                <span style={styles.detailLabel}>Created</span>
                <span style={styles.detailValue}>
                  {new Date(product.created_at).toLocaleString()}
                </span>
              </div>
              <div style={styles.detailItem}>
                <span style={styles.detailLabel}>Updated</span>
                <span style={styles.detailValue}>
                  {new Date(product.updated_at).toLocaleString()}
                </span>
              </div>
            </div>
          )}
        </section>

        {/* Endpoints */}
        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Endpoints</h2>
          {product.endpoints.length === 0 ? (
            <p style={styles.noEndpoints}>No endpoints configured for this product.</p>
          ) : (
            <div style={styles.endpointsList}>
              {product.endpoints.map((endpoint) => (
                <div key={endpoint.id} style={styles.endpointCard}>
                  <div style={styles.endpointHeader}>
                    <span style={styles.endpointKind}>{endpoint.kind.toUpperCase()}</span>
                  </div>
                  <div style={styles.endpointDetails}>
                    {endpoint.url && (
                      <div style={styles.endpointDetail}>
                        <span style={styles.endpointDetailLabel}>URL</span>
                        <code style={styles.endpointDetailValue}>{endpoint.url}</code>
                      </div>
                    )}
                    {endpoint.target && (
                      <div style={styles.endpointDetail}>
                        <span style={styles.endpointDetailLabel}>Target</span>
                        <code style={styles.endpointDetailValue}>{endpoint.target}</code>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Connection Test */}
        <section style={styles.section}>
          <div style={styles.testHeader}>
            <h2 style={styles.sectionTitle}>Connection Test</h2>
            <button
              onClick={handleTestConnection}
              disabled={testState.testing}
              style={styles.testButton}
            >
              {testState.testing ? 'Testing...' : 'Test Connection'}
            </button>
          </div>

          {testState.error && (
            <div style={styles.testError}>
              <strong>Error:</strong> {testState.error}
            </div>
          )}

          {testState.result && (
            <div
              style={{
                ...styles.testResult,
                borderColor: testState.result.success ? '#22c55e' : '#ef4444',
              }}
            >
              <div style={styles.testResultHeader}>
                <span
                  style={{
                    ...styles.testResultStatus,
                    backgroundColor: testState.result.success ? '#dcfce7' : '#fee2e2',
                    color: testState.result.success ? '#166534' : '#991b1b',
                  }}
                >
                  {testState.result.success ? 'SUCCESS' : 'FAILED'}
                </span>
                {testState.result.latency_ms && (
                  <span style={styles.testLatency}>
                    {testState.result.latency_ms.toFixed(2)} ms
                  </span>
                )}
              </div>

              <div style={styles.testResultDetails}>
                <div style={styles.testResultItem}>
                  <span style={styles.testResultLabel}>Endpoint</span>
                  <span style={styles.testResultValue}>
                    {testState.result.endpoint_kind.toUpperCase()}
                  </span>
                </div>
                {testState.result.endpoint_url && (
                  <div style={styles.testResultItem}>
                    <span style={styles.testResultLabel}>URL</span>
                    <code style={styles.testResultCode}>{testState.result.endpoint_url}</code>
                  </div>
                )}
                {testState.result.status_code && (
                  <div style={styles.testResultItem}>
                    <span style={styles.testResultLabel}>Status Code</span>
                    <span style={styles.testResultValue}>{testState.result.status_code}</span>
                  </div>
                )}
                {testState.result.error && (
                  <div style={styles.testResultItem}>
                    <span style={styles.testResultLabel}>Error</span>
                    <span style={{ ...styles.testResultValue, color: '#ef4444' }}>
                      {testState.result.error}
                    </span>
                  </div>
                )}
                <div style={styles.testResultItem}>
                  <span style={styles.testResultLabel}>Tested At</span>
                  <span style={styles.testResultValue}>
                    {new Date(testState.result.tested_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>
          )}

          {!testState.result && !testState.error && !testState.testing && (
            <p style={styles.testHint}>
              Click &quot;Test Connection&quot; to verify the product endpoint is reachable.
            </p>
          )}
        </section>
      </div>
    </main>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  main: {
    minHeight: '100vh',
    padding: '2rem',
    maxWidth: '1000px',
    margin: '0 auto',
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
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: '2rem',
    paddingBottom: '1rem',
    borderBottom: '1px solid var(--border)',
  },
  headerLeft: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  backLink: {
    fontSize: '0.875rem',
    color: 'var(--muted)',
    textDecoration: 'none',
  },
  titleRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
  },
  slug: {
    padding: '0.125rem 0.5rem',
    backgroundColor: 'rgba(0, 0, 0, 0.05)',
    borderRadius: '4px',
    fontSize: '0.875rem',
    fontFamily: 'monospace',
  },
  statusBadge: {
    display: 'inline-block',
    padding: '0.25rem 0.75rem',
    borderRadius: '9999px',
    fontSize: '0.75rem',
    fontWeight: 500,
  },
  headerActions: {
    display: 'flex',
    gap: '0.5rem',
  },
  toggleButton: {
    padding: '0.5rem 1rem',
    border: 'none',
    borderRadius: '6px',
    fontSize: '0.875rem',
    fontWeight: 500,
    cursor: 'pointer',
  },
  editButton: {
    padding: '0.5rem 1rem',
    backgroundColor: 'transparent',
    color: 'var(--primary)',
    border: '1px solid var(--primary)',
    borderRadius: '6px',
    fontSize: '0.875rem',
    cursor: 'pointer',
  },
  backButton: {
    display: 'inline-block',
    marginTop: '1rem',
    padding: '0.5rem 1rem',
    backgroundColor: 'var(--primary)',
    color: 'white',
    borderRadius: '6px',
    textDecoration: 'none',
  },
  content: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.5rem',
  },
  section: {
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
    padding: '1.5rem',
  },
  sectionTitle: {
    fontSize: '1.125rem',
    fontWeight: 600,
    marginBottom: '1rem',
  },
  editForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  label: {
    fontSize: '0.875rem',
    fontWeight: 500,
  },
  input: {
    padding: '0.625rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    backgroundColor: 'var(--background)',
  },
  select: {
    padding: '0.625rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    backgroundColor: 'var(--background)',
  },
  saveButton: {
    alignSelf: 'flex-start',
    padding: '0.625rem 1.25rem',
    backgroundColor: '#22c55e',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '0.875rem',
    fontWeight: 500,
    cursor: 'pointer',
  },
  detailsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '1rem',
  },
  detailItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  detailLabel: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
    textTransform: 'uppercase',
  },
  detailValue: {
    fontSize: '0.9375rem',
  },
  detailCode: {
    padding: '0.125rem 0.375rem',
    backgroundColor: 'rgba(0, 0, 0, 0.05)',
    borderRadius: '4px',
    fontSize: '0.875rem',
    fontFamily: 'monospace',
  },
  envBadge: {
    display: 'inline-block',
    padding: '0.125rem 0.5rem',
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    color: 'var(--primary)',
    borderRadius: '9999px',
    fontSize: '0.75rem',
    fontWeight: 500,
  },
  noEndpoints: {
    color: 'var(--muted)',
    fontStyle: 'italic',
  },
  endpointsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  endpointCard: {
    padding: '1rem',
    backgroundColor: 'rgba(0, 0, 0, 0.02)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
  },
  endpointHeader: {
    marginBottom: '0.75rem',
  },
  endpointKind: {
    display: 'inline-block',
    padding: '0.125rem 0.5rem',
    backgroundColor: 'var(--primary)',
    color: 'white',
    borderRadius: '4px',
    fontSize: '0.6875rem',
    fontWeight: 600,
  },
  endpointDetails: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
  },
  endpointDetail: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
  },
  endpointDetailLabel: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
    width: '60px',
  },
  endpointDetailValue: {
    fontFamily: 'monospace',
    fontSize: '0.875rem',
  },
  testHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
  },
  testButton: {
    padding: '0.5rem 1rem',
    backgroundColor: 'var(--primary)',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '0.875rem',
    cursor: 'pointer',
  },
  testError: {
    padding: '1rem',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: '6px',
    color: '#991b1b',
  },
  testResult: {
    padding: '1rem',
    border: '2px solid',
    borderRadius: '8px',
  },
  testResultHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
  },
  testResultStatus: {
    padding: '0.25rem 0.75rem',
    borderRadius: '4px',
    fontSize: '0.75rem',
    fontWeight: 600,
  },
  testLatency: {
    fontSize: '0.875rem',
    color: 'var(--muted)',
  },
  testResultDetails: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '0.75rem',
  },
  testResultItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  testResultLabel: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
    textTransform: 'uppercase',
  },
  testResultValue: {
    fontSize: '0.875rem',
  },
  testResultCode: {
    padding: '0.125rem 0.375rem',
    backgroundColor: 'rgba(0, 0, 0, 0.05)',
    borderRadius: '4px',
    fontSize: '0.8125rem',
    fontFamily: 'monospace',
  },
  testHint: {
    color: 'var(--muted)',
    fontSize: '0.875rem',
  },
};
