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
