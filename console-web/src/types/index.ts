// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

export type UserRole = 'admin' | 'operator' | 'auditor' | 'user';

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

export type LoginResponse = AuthResponse;

export interface MfaChallengeResponse {
  mfa_required: boolean;
  mfa_token: string;
  expires_at: string;
}

export type LoginResult =
  | { kind: 'success'; response: LoginResponse; user: User; token: string }
  | { kind: 'mfa_required'; challenge: MfaChallengeResponse; user: null; token: null };

export interface TwoFactorVerifyRequest {
  mfa_token: string;
  totp_code?: string;
  recovery_code?: string;
}

export interface TwoFactorEnrollResponse {
  otpauth_uri: string;
  totp_secret_base32: string;
}

export interface TwoFactorConfirmResponse {
  status: string;
  recovery_codes: string[];
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

export type BuildRole = 'soporte' | 'tecnico';
export type BuildJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'revoked';

export interface BuildJobRecord {
  id: string;
  user_id: string;
  role: BuildRole;
  profile_id: string;
  status: BuildJobStatus;
  artifact_path?: string | null;
  error_message?: string | null;
  logs?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  expires_at?: string | null;
}

export interface EnqueueBuildResponse {
  id: string;
  user_id: string;
  role: string;
  profile_id: string;
  status: string;
  created_at: string;
  expires_at?: string | null;
}

export interface BuildServerConfig {
  rendezvous_server: string;
  relay_server: string;
  api_server: string;
  server_public_key: string;
}

export interface BuildIdentityConfig {
  app_name?: string;
  about_text?: string;
  icon?: string;
}

export interface BuildPolicyConfig {
  allow_incoming: boolean;
  allow_outgoing: boolean;
  unattended_access: boolean;
  require_approval: boolean;
  allow_file_transfer?: boolean;
  allow_clipboard?: boolean;
  allow_audio?: boolean;
  allow_terminal?: boolean;
  allow_port_forward?: boolean;
  hide_network_settings?: boolean;
  enable_elevation?: boolean;
  unattended_elevation?: boolean;
}

export interface BuildInstallationConfig {
  mode: 'installed' | 'portable';
  install_path?: string | null;
  auto_start: boolean;
  create_desktop_shortcut: boolean;
  silent: boolean;
}

export interface BuildIdentificationConfig {
  device_group?: string;
  default_owner?: string;
}

export interface BuildExpirationConfig {
  expires_at?: string | null;
  max_uses?: number | null;
}

export interface CercanoProfilePayload {
  schema_version: string;
  profile_id: string;
  created_at?: string;
  role: BuildRole;
  server: BuildServerConfig;
  identity?: BuildIdentityConfig;
  policy: BuildPolicyConfig;
  installation: BuildInstallationConfig;
  identification?: BuildIdentificationConfig;
  expiration?: BuildExpirationConfig;
}

export interface EnqueueBuildRequest {
  profile: CercanoProfilePayload;
}

export type ChatStatus = 'waiting' | 'assigned' | 'active' | 'closed';
export type ChatSenderType = 'client' | 'technician' | 'system';

export interface ChatAttachment {
  id: string;
  name: string;
  mime: string;
  size_bytes: number;
  sha256: string;
}

export interface ChatMessage {
  id: string;
  conversation_id: string;
  sender_type: ChatSenderType;
  sender_id?: string | null;
  sender_name?: string | null;
  body: string;
  attachment?: ChatAttachment | null;
  created_at: string;
}

export interface ChatConversation {
  id: string;
  device_id: string;
  device_name: string | null;
  device_hostname?: string | null;
  device_os?: string | null;
  status: ChatStatus;
  assigned_user_id?: string | null;
  assigned_username?: string | null;
  contact_first_name?: string | null;
  contact_last_name?: string | null;
  created_at: string;
  updated_at: string;
  last_message_at?: string | null;
  last_message_preview?: string | null;
  unread_count: number;
}

export interface ChatConversationDetail extends ChatConversation {
  closed_at?: string | null;
  closed_by?: string | null;
  messages: ChatMessage[];
  next_before?: string | null;
  other_last_read_at?: string | null;
}

export interface ChatBranding {
  organization_name?: string | null;
  support_name: string;
  logo_url?: string | null;
  accent_color: string;
  welcome_text?: string | null;
  info_text?: string | null;
  privacy_text?: string | null;
}

export interface ChatAgent {
  id: string;
  username: string;
}

export interface ChatSummary {
  waiting: number;
  assigned_to_me: number;
  active: number;
  unread: number;
}

export type ActiveTab = 'dashboard' | 'devices' | 'chat' | 'builder' | 'users' | 'roles' | 'audit' | 'settings' | 'security' | 'network' | 'twofa';

export interface UserDetail extends User {
  is_active: boolean;
  totp_enabled: boolean;
  is_2fa_required: boolean;
}

export interface RoleDetail {
  role: UserRole;
  description: string;
  permissions: string[];
}

export interface AuditEventItem {
  event_id: string;
  timestamp: string;
  category: string;
  action: string;
  outcome: 'success' | 'failure' | 'denied';
  actor?: {
    actor_id: string;
    actor_type: string;
  };
  details?: Record<string, unknown>;
  prev_hash?: string;
  hash?: string;
}

export interface Settings {
  organization_name?: string;
  support_email?: string;
  allow_registration?: boolean;
  default_role?: UserRole;
  session_timeout_minutes?: number;
  enforce_2fa_all?: boolean;
  lan_discovery_enabled?: boolean;
  [key: string]: unknown;
}

export interface GeneralSettings extends Settings {}
