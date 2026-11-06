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
  requires_restart?: boolean;
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
  uptime_seconds?: number | null;
  cpu_percent?: number | null;
  memory_used_mb?: number | null;
  memory_total_mb?: number | null;
  total_devices: number;
  online_devices: number;
  active_sessions?: number | null;
  network_in_mbps?: number | null;
  network_out_mbps?: number | null;
  services: ServerPortService[];
}

export interface CustomClientProfile {
  name: string;
  company_name: string;
  logo_data?: string;
  accent_color: string;
  support_info: string;
  rendezvous_server: string;
  relay_server: string;
  api_server: string;
  public_key: string;
  lock_settings: boolean;
  portable_mode: boolean;
  unattended_access: boolean;
  lan_only: boolean;
  allow_file_transfer: boolean;
  allow_terminal: boolean;
}

export type ActiveTab = 'dashboard' | 'devices' | 'builder' | 'security' | 'network';
