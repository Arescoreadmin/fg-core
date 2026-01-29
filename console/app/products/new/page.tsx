'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { createProduct, type ProductCreateRequest } from '@/lib/api';

type EndpointKind = 'rest' | 'grpc' | 'nats';

interface EndpointForm {
  kind: EndpointKind;
  url: string;
  target: string;
}

type WizardStep = 'basics' | 'endpoints' | 'review';

export default function NewProductPage() {
  const router = useRouter();
  const [step, setStep] = useState<WizardStep>('basics');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [env, setEnv] = useState('production');
  const [owner, setOwner] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [tenantId, setTenantId] = useState('');
  const [endpoints, setEndpoints] = useState<EndpointForm[]>([
    { kind: 'rest', url: '', target: '' },
  ]);

  // Validation
  const isBasicsValid =
    slug.length > 0 &&
    name.length > 0 &&
    tenantId.length > 0 &&
    /^[a-z0-9][a-z0-9-]*$/.test(slug);
  const isEndpointsValid = endpoints.every(
    (ep) => ep.kind === 'nats' ? ep.target.length > 0 : ep.url.length > 0
  );

  const addEndpoint = () => {
    setEndpoints([...endpoints, { kind: 'rest', url: '', target: '' }]);
  };

  const removeEndpoint = (index: number) => {
    setEndpoints(endpoints.filter((_, i) => i !== index));
  };

  const updateEndpoint = (index: number, field: keyof EndpointForm, value: string) => {
    const updated = [...endpoints];
    updated[index] = { ...updated[index], [field]: value };
    setEndpoints(updated);
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    setError(null);

    try {
      const data: ProductCreateRequest = {
        slug,
        name,
        env,
        owner: owner || undefined,
        enabled,
        endpoints: endpoints
          .filter((ep) => (ep.kind === 'nats' ? ep.target : ep.url))
          .map((ep) => ({
            kind: ep.kind,
            url: ep.kind !== 'nats' ? ep.url : undefined,
            target: ep.kind === 'nats' ? ep.target : undefined,
          })),
      };

      const product = await createProduct(data, tenantId);
      router.push(`/products/${product.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create product');
      setSubmitting(false);
    }
  };

  return (
    <main style={styles.main}>
      <header style={styles.header}>
        <Link href="/products" style={styles.backLink}>
          Back to Products
        </Link>
        <h1 style={styles.title}>Add New Product</h1>
      </header>

      {/* Progress Steps */}
      <div style={styles.progress}>
        <div
          style={{
            ...styles.progressStep,
            ...(step === 'basics' ? styles.progressStepActive : {}),
            ...(step !== 'basics' ? styles.progressStepComplete : {}),
          }}
        >
          1. Basic Info
        </div>
        <div style={styles.progressLine} />
        <div
          style={{
            ...styles.progressStep,
            ...(step === 'endpoints' ? styles.progressStepActive : {}),
            ...(step === 'review' ? styles.progressStepComplete : {}),
          }}
        >
          2. Endpoints
        </div>
        <div style={styles.progressLine} />
        <div
          style={{
            ...styles.progressStep,
            ...(step === 'review' ? styles.progressStepActive : {}),
          }}
        >
          3. Review
        </div>
      </div>

      {error && (
        <div style={styles.error}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Step 1: Basics */}
      {step === 'basics' && (
        <div style={styles.stepContent}>
          <h2 style={styles.stepTitle}>Basic Information</h2>

          <div style={styles.formGroup}>
            <label style={styles.label}>
              Product Slug <span style={styles.required}>*</span>
            </label>
            <input
              type="text"
              value={slug}
              onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
              placeholder="my-product"
              style={styles.input}
            />
            <span style={styles.hint}>
              Lowercase letters, numbers, and hyphens only. Must start with letter or number.
            </span>
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>
              Tenant ID <span style={styles.required}>*</span>
            </label>
            <input
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="tenant-id"
              style={styles.input}
            />
            <span style={styles.hint}>Provide the tenant for this product.</span>
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>
              Product Name <span style={styles.required}>*</span>
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Product"
              style={styles.input}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>Environment</label>
            <select
              value={env}
              onChange={(e) => setEnv(e.target.value)}
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
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              placeholder="team@example.com"
              style={styles.input}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                style={styles.checkbox}
              />
              Enable this product
            </label>
          </div>

          <div style={styles.actions}>
            <Link href="/products" style={styles.cancelButton}>
              Cancel
            </Link>
            <button
              onClick={() => setStep('endpoints')}
              disabled={!isBasicsValid}
              style={{
                ...styles.nextButton,
                opacity: isBasicsValid ? 1 : 0.5,
              }}
            >
              Next: Endpoints
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Endpoints */}
      {step === 'endpoints' && (
        <div style={styles.stepContent}>
          <h2 style={styles.stepTitle}>Configure Endpoints</h2>
          <p style={styles.stepDescription}>
            Add one or more endpoints for this product. FrostGate will use these to connect to your service.
          </p>

          {endpoints.map((endpoint, index) => (
            <div key={index} style={styles.endpointCard}>
              <div style={styles.endpointHeader}>
                <span style={styles.endpointTitle}>Endpoint {index + 1}</span>
                {endpoints.length > 1 && (
                  <button
                    onClick={() => removeEndpoint(index)}
                    style={styles.removeButton}
                  >
                    Remove
                  </button>
                )}
              </div>

              <div style={styles.formGroup}>
                <label style={styles.label}>Type</label>
                <select
                  value={endpoint.kind}
                  onChange={(e) => updateEndpoint(index, 'kind', e.target.value)}
                  style={styles.select}
                >
                  <option value="rest">REST API</option>
                  <option value="grpc">gRPC</option>
                  <option value="nats">NATS</option>
                </select>
              </div>

              {endpoint.kind === 'nats' ? (
                <div style={styles.formGroup}>
                  <label style={styles.label}>NATS Subject</label>
                  <input
                    type="text"
                    value={endpoint.target}
                    onChange={(e) => updateEndpoint(index, 'target', e.target.value)}
                    placeholder="my.product.events"
                    style={styles.input}
                  />
                </div>
              ) : (
                <div style={styles.formGroup}>
                  <label style={styles.label}>
                    {endpoint.kind === 'rest' ? 'Base URL' : 'gRPC Address'}
                  </label>
                  <input
                    type="text"
                    value={endpoint.url}
                    onChange={(e) => updateEndpoint(index, 'url', e.target.value)}
                    placeholder={
                      endpoint.kind === 'rest'
                        ? 'https://api.example.com'
                        : 'grpc.example.com:443'
                    }
                    style={styles.input}
                  />
                </div>
              )}
            </div>
          ))}

          <button onClick={addEndpoint} style={styles.addEndpointButton}>
            + Add Another Endpoint
          </button>

          <div style={styles.actions}>
            <button onClick={() => setStep('basics')} style={styles.backButton}>
              Back
            </button>
            <button
              onClick={() => setStep('review')}
              disabled={!isEndpointsValid}
              style={{
                ...styles.nextButton,
                opacity: isEndpointsValid ? 1 : 0.5,
              }}
            >
              Next: Review
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Review */}
      {step === 'review' && (
        <div style={styles.stepContent}>
          <h2 style={styles.stepTitle}>Review & Create</h2>
          <p style={styles.stepDescription}>
            Review your product configuration before creating.
          </p>

          <div style={styles.reviewSection}>
            <h3 style={styles.reviewSectionTitle}>Basic Information</h3>
            <div style={styles.reviewGrid}>
              <div style={styles.reviewItem}>
                <span style={styles.reviewLabel}>Slug</span>
                <code style={styles.reviewCode}>{slug}</code>
              </div>
              <div style={styles.reviewItem}>
                <span style={styles.reviewLabel}>Name</span>
                <span style={styles.reviewValue}>{name}</span>
              </div>
              <div style={styles.reviewItem}>
                <span style={styles.reviewLabel}>Environment</span>
                <span style={styles.reviewValue}>{env}</span>
              </div>
              <div style={styles.reviewItem}>
                <span style={styles.reviewLabel}>Owner</span>
                <span style={styles.reviewValue}>{owner || '-'}</span>
              </div>
              <div style={styles.reviewItem}>
                <span style={styles.reviewLabel}>Status</span>
                <span style={styles.reviewValue}>{enabled ? 'Enabled' : 'Disabled'}</span>
              </div>
            </div>
          </div>

          <div style={styles.reviewSection}>
            <h3 style={styles.reviewSectionTitle}>Endpoints</h3>
            {endpoints.filter((ep) => (ep.kind === 'nats' ? ep.target : ep.url)).map((endpoint, index) => (
              <div key={index} style={styles.reviewEndpoint}>
                <span style={styles.reviewEndpointKind}>{endpoint.kind.toUpperCase()}</span>
                <span style={styles.reviewEndpointUrl}>
                  {endpoint.kind === 'nats' ? endpoint.target : endpoint.url}
                </span>
              </div>
            ))}
          </div>

          <div style={styles.actions}>
            <button onClick={() => setStep('endpoints')} style={styles.backButton}>
              Back
            </button>
            <button
              onClick={handleSubmit}
              disabled={submitting}
              style={{
                ...styles.submitButton,
                opacity: submitting ? 0.5 : 1,
              }}
            >
              {submitting ? 'Creating...' : 'Create Product'}
            </button>
          </div>
        </div>
      )}
    </main>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  main: {
    minHeight: '100vh',
    padding: '2rem',
    maxWidth: '800px',
    margin: '0 auto',
  },
  header: {
    marginBottom: '2rem',
  },
  backLink: {
    fontSize: '0.875rem',
    color: 'var(--muted)',
    textDecoration: 'none',
    display: 'block',
    marginBottom: '0.5rem',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
  },
  progress: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: '2rem',
    padding: '1rem',
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
  },
  progressStep: {
    fontSize: '0.875rem',
    color: 'var(--muted)',
    padding: '0.5rem 1rem',
  },
  progressStepActive: {
    color: 'var(--primary)',
    fontWeight: 600,
  },
  progressStepComplete: {
    color: '#22c55e',
  },
  progressLine: {
    width: '40px',
    height: '1px',
    backgroundColor: 'var(--border)',
    margin: '0 0.5rem',
  },
  error: {
    padding: '1rem',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: '8px',
    marginBottom: '1rem',
    color: '#991b1b',
  },
  stepContent: {
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
    padding: '2rem',
  },
  stepTitle: {
    fontSize: '1.25rem',
    fontWeight: 600,
    marginBottom: '0.5rem',
  },
  stepDescription: {
    color: 'var(--muted)',
    marginBottom: '1.5rem',
  },
  formGroup: {
    marginBottom: '1.5rem',
  },
  label: {
    display: 'block',
    fontSize: '0.875rem',
    fontWeight: 500,
    marginBottom: '0.5rem',
  },
  required: {
    color: '#ef4444',
  },
  input: {
    width: '100%',
    padding: '0.625rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    backgroundColor: 'var(--background)',
  },
  select: {
    width: '100%',
    padding: '0.625rem 0.75rem',
    fontSize: '0.875rem',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    backgroundColor: 'var(--background)',
  },
  hint: {
    display: 'block',
    fontSize: '0.75rem',
    color: 'var(--muted)',
    marginTop: '0.25rem',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.875rem',
    cursor: 'pointer',
  },
  checkbox: {
    width: '16px',
    height: '16px',
  },
  actions: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '1rem',
    marginTop: '2rem',
    paddingTop: '1.5rem',
    borderTop: '1px solid var(--border)',
  },
  cancelButton: {
    padding: '0.625rem 1.25rem',
    fontSize: '0.875rem',
    color: 'var(--muted)',
    textDecoration: 'none',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    backgroundColor: 'transparent',
  },
  backButton: {
    padding: '0.625rem 1.25rem',
    fontSize: '0.875rem',
    color: 'var(--foreground)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    backgroundColor: 'transparent',
    cursor: 'pointer',
  },
  nextButton: {
    padding: '0.625rem 1.25rem',
    fontSize: '0.875rem',
    color: 'white',
    backgroundColor: 'var(--primary)',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  submitButton: {
    padding: '0.625rem 1.5rem',
    fontSize: '0.875rem',
    color: 'white',
    backgroundColor: '#22c55e',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: 500,
  },
  endpointCard: {
    padding: '1.25rem',
    backgroundColor: 'rgba(0, 0, 0, 0.02)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
    marginBottom: '1rem',
  },
  endpointHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '1rem',
  },
  endpointTitle: {
    fontWeight: 500,
    fontSize: '0.9375rem',
  },
  removeButton: {
    padding: '0.25rem 0.75rem',
    fontSize: '0.75rem',
    color: '#ef4444',
    backgroundColor: 'transparent',
    border: '1px solid #ef4444',
    borderRadius: '4px',
    cursor: 'pointer',
  },
  addEndpointButton: {
    padding: '0.75rem 1rem',
    fontSize: '0.875rem',
    color: 'var(--primary)',
    backgroundColor: 'transparent',
    border: '1px dashed var(--primary)',
    borderRadius: '8px',
    cursor: 'pointer',
    width: '100%',
  },
  reviewSection: {
    marginBottom: '1.5rem',
  },
  reviewSectionTitle: {
    fontSize: '1rem',
    fontWeight: 600,
    marginBottom: '0.75rem',
    color: 'var(--muted)',
  },
  reviewGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1rem',
  },
  reviewItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
  },
  reviewLabel: {
    fontSize: '0.75rem',
    color: 'var(--muted)',
    textTransform: 'uppercase',
  },
  reviewValue: {
    fontSize: '0.9375rem',
  },
  reviewCode: {
    padding: '0.125rem 0.375rem',
    backgroundColor: 'rgba(0, 0, 0, 0.05)',
    borderRadius: '4px',
    fontSize: '0.875rem',
    fontFamily: 'monospace',
  },
  reviewEndpoint: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    padding: '0.75rem',
    backgroundColor: 'rgba(0, 0, 0, 0.02)',
    borderRadius: '6px',
    marginBottom: '0.5rem',
  },
  reviewEndpointKind: {
    padding: '0.125rem 0.5rem',
    backgroundColor: 'var(--primary)',
    color: 'white',
    borderRadius: '4px',
    fontSize: '0.6875rem',
    fontWeight: 600,
  },
  reviewEndpointUrl: {
    fontFamily: 'monospace',
    fontSize: '0.875rem',
  },
};
