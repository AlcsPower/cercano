// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

export type UserRole = 'admin' | 'operator' | 'auditor';

export interface User {
  id: string;
  username: string;
  role: UserRole;
  created_at?: string;
}

export interface AuthResponse {
  token: string;
  expires_at: string;
  user: User;
}

export interface Device {
  id: string;
  name: string;
  hostname?: string | null;
  os?: string | null;
  version?: string | null;
  ip_address?: string | null;
  status: 'online' | 'offline';
  last_seen_at?: string | null;
  created_at: string;
}

export interface ServerPublicKeyResponse {
  public_key: string;
  key_type: string;
  fingerprint?: string;
}

export interface RotateKeysResponse {
  status: string;
  public_key: string;
  key_type: string;
  rotated_at: string;
  backup_path?: string;
}

export interface ServerPortService {
  name: string;
  port: number;
  protocol: 'TCP' | 'UDP' | 'TCP/UDP';
  role: string;
  description: string;
  status: 'operational' | 'idle' | 'warning' | 'stopped';
}

export interface SystemMetrics {
  uptime_seconds: number;
  cpu_percent: number;
  memory_used_mb: number;
  memory_total_mb: number;
  total_devices: number;
  online_devices: number;
  active_sessions: number;
  network_in_mbps: number;
  network_out_mbps: number;
  services: ServerPortService[];
}

export type ActiveTab = 'dashboard' | 'devices' | 'security' | 'network';
