'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { fetchProducts, type Product } from '@/lib/api';

interface ProductsState {
  products: Product[];
  loading: boolean;
  error?: string;
}

export default function ProductsPage() {
  const [state, setState] = useState<ProductsState>({
    products: [],
    loading: true,
  });

  useEffect(() => {
    async function loadProducts() {
      try {
        const data = await fetchProducts();
        setState({ products: data.products, loading: false });
      } catch (err) {
        setState({
          products: [],
          loading: false,
          error: err instanceof Error ? err.message : 'Failed to load products',
        });
      }
    }
    loadProducts();
  }, []);

  return (
    <main style={styles.main}>
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <Link href="/" style={styles.backLink}>
            Back to Dashboard
          </Link>
          <h1 style={styles.title}>Products Registry</h1>
        </div>
        <Link href="/products/new" style={styles.addButton}>
          + Add Product
        </Link>
      </header>

      {state.loading ? (
        <div style={styles.loading}>Loading products...</div>
      ) : state.error ? (
        <div style={styles.error}>
          <h2>Error</h2>
          <p>{state.error}</p>
        </div>
      ) : state.products.length === 0 ? (
        <div style={styles.empty}>
          <h2>No Products</h2>
          <p>No products have been registered yet.</p>
          <Link href="/products/new" style={styles.addButton}>
            + Add Your First Product
          </Link>
        </div>
      ) : (
        <div style={styles.content}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Name</th>
                <th style={styles.th}>Slug</th>
                <th style={styles.th}>Environment</th>
                <th style={styles.th}>Owner</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Endpoints</th>
                <th style={styles.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {state.products.map((product) => (
                <tr key={product.id} style={styles.tr}>
                  <td style={styles.td}>
                    <Link href={`/products/${product.id}`} style={styles.productLink}>
                      {product.name}
                    </Link>
                  </td>
                  <td style={styles.td}>
                    <code style={styles.code}>{product.slug}</code>
                  </td>
                  <td style={styles.td}>
                    <span style={styles.envBadge}>{product.env}</span>
                  </td>
                  <td style={styles.td}>{product.owner || '-'}</td>
                  <td style={styles.td}>
                    <span
                      style={{
                        ...styles.statusBadge,
                        backgroundColor: product.enabled ? '#dcfce7' : '#fee2e2',
                        color: product.enabled ? '#166534' : '#991b1b',
                      }}
                    >
                      {product.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td style={styles.td}>
                    {product.endpoints.length > 0 ? (
                      <span style={styles.endpointCount}>
                        {product.endpoints.map((ep) => ep.kind).join(', ')}
                      </span>
                    ) : (
                      <span style={styles.noEndpoints}>None</span>
                    )}
                  </td>
                  <td style={styles.td}>
                    <Link href={`/products/${product.id}`} style={styles.viewButton}>
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

const styles: { [key: string]: React.CSSProperties } = {
  main: {
    minHeight: '100vh',
    padding: '2rem',
    maxWidth: '1400px',
    margin: '0 auto',
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
  title: {
    fontSize: '1.5rem',
    fontWeight: 600,
  },
  addButton: {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '0.5rem 1rem',
    backgroundColor: 'var(--primary)',
    color: 'white',
    borderRadius: '6px',
    textDecoration: 'none',
    fontSize: '0.875rem',
    fontWeight: 500,
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
  empty: {
    padding: '4rem',
    textAlign: 'center',
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
  },
  content: {
    backgroundColor: 'var(--background)',
    border: '1px solid var(--border)',
    borderRadius: '8px',
    overflow: 'hidden',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
  },
  th: {
    padding: '0.75rem 1rem',
    textAlign: 'left',
    fontSize: '0.75rem',
    fontWeight: 600,
    textTransform: 'uppercase',
    color: 'var(--muted)',
    backgroundColor: 'rgba(0, 0, 0, 0.02)',
    borderBottom: '1px solid var(--border)',
  },
  tr: {
    borderBottom: '1px solid var(--border)',
  },
  td: {
    padding: '0.75rem 1rem',
    fontSize: '0.875rem',
  },
  productLink: {
    color: 'var(--primary)',
    textDecoration: 'none',
    fontWeight: 500,
  },
  code: {
    padding: '0.125rem 0.375rem',
    backgroundColor: 'rgba(0, 0, 0, 0.05)',
    borderRadius: '4px',
    fontSize: '0.8125rem',
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
  statusBadge: {
    display: 'inline-block',
    padding: '0.125rem 0.5rem',
    borderRadius: '9999px',
    fontSize: '0.75rem',
    fontWeight: 500,
  },
  endpointCount: {
    fontSize: '0.8125rem',
    color: 'var(--muted)',
  },
  noEndpoints: {
    fontSize: '0.8125rem',
    color: 'var(--muted)',
    fontStyle: 'italic',
  },
  viewButton: {
    display: 'inline-block',
    padding: '0.25rem 0.75rem',
    backgroundColor: 'transparent',
    color: 'var(--primary)',
    border: '1px solid var(--primary)',
    borderRadius: '4px',
    textDecoration: 'none',
    fontSize: '0.8125rem',
  },
};
