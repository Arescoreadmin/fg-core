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
