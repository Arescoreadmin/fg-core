/**
 * API client for admin-gateway
 */

import { apiUrl } from './config';

export interface DashboardStats {
  total_requests: number;
  blocked_requests: number;
  active_tenants: number;
  active_keys: number;
}

export interface DashboardData {
  stats: DashboardStats;
  recent_events: unknown[];
}

export interface HealthData {
  status: string;
  service: string;
  version: string;
  timestamp: string;
  request_id?: string;
}

// Products Registry types
export interface ProductEndpoint {
  id: number;
  product_id: number;
  kind: 'rest' | 'grpc' | 'nats';
  url: string | null;
  target: string | null;
  meta: Record<string, unknown> | null;
  created_at: string;
}

export interface Product {
  id: number;
  slug: string;
  name: string;
  env: string;
  owner: string | null;
  enabled: boolean;
  tenant_id: string;
  created_at: string;
  updated_at: string;
  endpoints: ProductEndpoint[];
}

export interface ProductListResponse {
  products: Product[];
  total: number;
}

export interface ApiKeyInfo {
  prefix: string;
  name?: string | null;
  scopes: string[];
  enabled: boolean;
  tenant_id?: string | null;
  created_at?: string | null;
  expires_at?: string | number | null;
  last_used_at?: string | number | null;
  use_count?: number | null;
}

export interface ApiKeyListResponse {
  keys: ApiKeyInfo[];
  total: number;
}

export interface ApiKeyCreateRequest {
  name?: string;
  scopes: string[];
  tenant_id: string;
  ttl_seconds: number;
}

export interface ApiKeyCreateResponse {
  key: string;
  prefix: string;
  scopes: string[];
  tenant_id?: string | null;
  ttl_seconds: number;
  expires_at: number;
}

export interface ApiKeyRotateResponse {
  new_key: string;
  new_prefix: string;
  old_prefix: string;
  scopes: string[];
  tenant_id?: string | null;
  expires_at: number;
  old_key_revoked: boolean;
}

export interface ProductCreateRequest {
  slug: string;
  name: string;
  env?: string;
  owner?: string;
  enabled?: boolean;
  endpoints?: Array<{
    kind: 'rest' | 'grpc' | 'nats';
    url?: string;
    target?: string;
    meta?: Record<string, unknown>;
  }>;
}

export interface ProductUpdateRequest {
  name?: string;
  env?: string;
  owner?: string;
  enabled?: boolean;
  endpoints?: Array<{
    kind: 'rest' | 'grpc' | 'nats';
    url?: string;
    target?: string;
    meta?: Record<string, unknown>;
  }>;
}

export interface TestConnectionResult {
  product_id: number;
  product_name: string;
  endpoint_id: number | null;
  endpoint_kind: string;
  endpoint_url: string | null;
  success: boolean;
  status_code: number | null;
  latency_ms: number | null;
  error: string | null;
  tested_at: string;
}

/**
 * Get default headers for API requests
 */
function getHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  // Add tenant ID header (dev mode uses default)
  headers['X-Tenant-ID'] = 'default';
  return headers;
}

async function fetchCsrfToken(): Promise<{ token: string; headerName: string }> {
  const response = await fetch(apiUrl('/admin/csrf-token'), {
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch CSRF token: ${response.status}`);
  }
  const data = await response.json();
  return { token: data.csrf_token, headerName: data.header_name };
}

/**
 * Fetch dashboard data from admin-gateway
 */
export async function fetchDashboard(): Promise<DashboardData> {
  const response = await fetch(apiUrl('/api/v1/dashboard'));
  if (!response.ok) {
    throw new Error(`Failed to fetch dashboard: ${response.status}`);
  }
  return response.json();
}

/**
 * Fetch health status from admin-gateway
 */
export async function fetchHealth(): Promise<HealthData> {
  const response = await fetch(apiUrl('/health'));
  if (!response.ok) {
    throw new Error(`Failed to fetch health: ${response.status}`);
  }
  return response.json();
}

/**
 * Fetch all products for the current tenant
 */
export async function fetchProducts(): Promise<ProductListResponse> {
  const response = await fetch(apiUrl('/admin/products'), {
    headers: getHeaders(),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch products: ${response.status}`);
  }
  return response.json();
}

export async function fetchApiKeys(tenantId: string): Promise<ApiKeyListResponse> {
  const params = new URLSearchParams({ tenant_id: tenantId });
  const response = await fetch(apiUrl(`/admin/keys?${params.toString()}`), {
    headers: getHeaders(),
    credentials: 'include',
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch API keys: ${response.status}`);
  }
  return response.json();
}

export async function createApiKey(
  data: ApiKeyCreateRequest
): Promise<ApiKeyCreateResponse> {
  const csrf = await fetchCsrfToken();
  const response = await fetch(apiUrl('/admin/keys'), {
    method: 'POST',
    headers: {
      ...getHeaders(),
      [csrf.headerName]: csrf.token,
    },
    credentials: 'include',
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to create API key: ${response.status}`);
  }
  return response.json();
}

export async function rotateApiKey(
  prefix: string,
  tenantId: string,
  ttlSeconds: number
): Promise<ApiKeyRotateResponse> {
  const csrf = await fetchCsrfToken();
  const params = new URLSearchParams({ tenant_id: tenantId });
  const response = await fetch(
    apiUrl(`/admin/keys/${prefix}/rotate?${params.toString()}`),
    {
      method: 'POST',
      headers: {
        ...getHeaders(),
        [csrf.headerName]: csrf.token,
      },
      credentials: 'include',
      body: JSON.stringify({ ttl_seconds: ttlSeconds, revoke_old: true }),
    }
  );
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to rotate API key: ${response.status}`);
  }
  return response.json();
}

export async function revokeApiKey(
  prefix: string,
  tenantId: string
): Promise<{ revoked: boolean }> {
  const csrf = await fetchCsrfToken();
  const params = new URLSearchParams({ tenant_id: tenantId });
  const response = await fetch(
    apiUrl(`/admin/keys/${prefix}/revoke?${params.toString()}`),
    {
      method: 'POST',
      headers: {
        ...getHeaders(),
        [csrf.headerName]: csrf.token,
      },
      credentials: 'include',
    }
  );
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to revoke API key: ${response.status}`);
  }
  return response.json();
}

/**
 * Fetch a single product by ID
 */
export async function fetchProduct(id: number): Promise<Product> {
  const response = await fetch(apiUrl(`/admin/products/${id}`), {
    headers: getHeaders(),
  });
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Product not found');
    }
    throw new Error(`Failed to fetch product: ${response.status}`);
  }
  return response.json();
}

/**
 * Create a new product
 */
export async function createProduct(data: ProductCreateRequest): Promise<Product> {
  const response = await fetch(apiUrl('/admin/products'), {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to create product: ${response.status}`);
  }
  return response.json();
}

/**
 * Update an existing product
 */
export async function updateProduct(id: number, data: ProductUpdateRequest): Promise<Product> {
  const response = await fetch(apiUrl(`/admin/products/${id}`), {
    method: 'PATCH',
    headers: getHeaders(),
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to update product: ${response.status}`);
  }
  return response.json();
}

/**
 * Test connection to a product's endpoint
 */
export async function testProductConnection(id: number): Promise<TestConnectionResult> {
  const response = await fetch(apiUrl(`/admin/products/${id}/test-connection`), {
    method: 'POST',
    headers: getHeaders(),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.detail || `Failed to test connection: ${response.status}`);
  }
  return response.json();
}
