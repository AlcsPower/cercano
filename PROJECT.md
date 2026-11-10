# Project: Cercano F4 y F4.5 (Consola, RBAC, 2FA y Cercano Chat)

## Architecture
- **Control Plane (`control-plane/cercano-api`)**:
  - Rust / Axum backend running on SQLite with WAL mode.
  - Authentication: User sessions via Bearer token (`cercano_sess_<64 hex>`), 2FA TOTP (RFC 6238) challenges via `mfa_challenges` table (`mfa_token`, 5 min TTL, single use), single-use recovery code hashes (SHA-256).
  - RBAC: Static role-to-permission matrix in `permissions.rs` (`admin`, `operator`, `auditor`, `user`), route enforcement middleware in Axum, `authz.denied` audit events.
  - Cercano Chat: Device authentication using Ed25519 keypair and TOFU key pinning, challenge nonce (120s TTL) -> 15-min bearer token (`cercano_chat_<64 hex>`).
  - Chat Real-Time: SSE `ChatHub` (`GET /api/chat/events`) broadcasting content-free `poke` events (`message`, `status`, `queue`, `resync`) segregated by audience.
  - Chat Storage & Privacy: Schema migrations 007 (`007_console_rbac_2fa`) and 008 (`008_chat_schema`). Zero Secrets: message bodies, contact names, and file names strictly excluded from audit logs and telemetry.
- **Web Console (`console-web`)**:
  - React + TypeScript + Vite + Tailwind CSS.
  - Design tokens compliance (`lint:design`), accessibility (`aria-live`), responsive layouts.
  - Views: Users, Roles, Audit, Settings, 2FA Self-Service, Builder integration, Chat View, Chat Branding form.
- **Client & Patches (`client/`, `patches/`)**:
  - Rust client chat module and Flutter UI for support chat.
  - Patch assignment: `patches/008-client-support-chat.patch`.
  - Dynamic branding from `/api/chat/branding` without binary re-installation.
- **Git Branching Strategy**:
  - `main` is STRICTLY PROTECTED (commit `b41d79b`).
  - Active coordination branch: `docs/F0-01-gobernanza`.
  - Integration branch: `chore/integrate-f4-f4.5` (rebased and fast-forward merged to `docs/F0-01-gobernanza`).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | F4-01: RBAC & 2FA Spec | Matrix, 2FA flows, audit events specification | M1 | Survey |
| 2 | F4-02: Migration 007 | Database schema for TOTP, recovery codes, challenges | M1 | Survey |
| 3 | F4-03: Users/Roles/Settings API | CRUD for users, roles inspection, system settings | M1 | Survey |
| 4 | F4.5-01: Chat Spec & ADR | Spec, ADR-010, operational guides for chat | M1 | Survey |
| 5 | F4.5-02: Migration 008 & Models | Chat tables, indices, and Rust models | M1 | Survey |
| 6 | F4.5-08: Console Chat View (Mock) | Chat UI components and branding form in console-web | M1 | Survey |
| 7 | Baseline Clippy & Hygiene | Resolve collapsible_if warnings, clean temp files | M1 | Survey |
| 8 | F4-04: 2FA TOTP Implementation | Enroll, confirm, verify, revoke, 2-step login, recovery codes, lockout | M2 | Survey |
| 9 | F4-05: RBAC Middleware | Axum route extractor/middleware, chat:* permissions, authz.denied | M2 | Survey |
| 10 | F4-06: Console Web Management Views | UsersView, RolesView, AuditView, SettingsView, TwoFAView, Login 2FA | M1 | Survey |
| 11 | F4-07: Console Builder Integration | BuilderView wired to /api/builds for job dispatch and artifact download | M2 | Survey |
| 12 | F4-08: Security Tests F4 | IDOR, 2FA lockout, recovery reuse, session invalidation tests | M3 | Survey |
| 13 | F4-09: E2E Gate F4 | E2E validation of Phase 4 deliverables | M3 | Survey |
| 14 | F4-10: Closure & Docs F4 | Operator manual and formal sign-off for Phase 4 | M3 | Survey |
| 15 | F4.5-03: Device Auth | Headless Ed25519 challenge-response auth, 15m bearer token | M4 | Survey |
| 16 | F4.5-04: Chat REST API | Conversations and messages endpoints, pagination, state | M4 | Survey |
| 17 | F4.5-05: File Attachments | Magic bytes MIME validation, SHA-256, quota limits, atomic writes | M4 | Survey |
| 18 | F4.5-06: SSE ChatHub | Real-time event streaming, content-free poke events, resync | M4 | Survey |
| 19 | F4.5-07: Chat Audit & Limits | Audit logging with zero message leaks, rate limits, retention | M4 | Survey |
| 20 | F4.5-16: Dynamic Chat Branding | Backend API GET/PUT /api/chat/branding and persistence | M4 | Survey |
| 21 | F4.5-08w: Console Chat Live Wiring | Connect ChatView and ChatBrandingForm to live REST & SSE APIs | M5 | Survey |
| 22 | F4.5-09: Console Chat UX & Badges | Unread badges, audio/desktop notification, reconnect banner, a11y | M5 | Survey |
| 23 | F4.5-10: Client Rust Support Chat | Rust module and patches/008-client-support-chat.patch | M5 | Survey |
| 24 | F4.5-11: Client Flutter Chat UI | Flutter support chat screen, contact input, attachments, i18n | M5 | Survey |
| 25 | F4.5-12: Remote Session Escalation | Escalate chat session to attended remote desktop session | M5 | Survey |
| 26 | F4.5-13: Server Policy Profile | Profile policy.chat enforcement on server and client | M5 | Survey |
| 27 | F4.5-14: Chat E2E, Security & Gate | E2E test suite, load testing, privacy audit, phase gate | M6 | Survey |
| 28 | F4.5-15: Chat Operational Guide | Finalize deployment and operational runbooks | M6 | Survey |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Integration & Console Web Management | F4-06 (Console views for users, roles, audit, settings, 2FA login) & baseline hardening | none | DONE |
| M2 | F4-07: Console Builder Integration | BuilderView wired to /api/builds for job dispatch, RBAC enforcement, automated polling, and artifact download | M1 | DONE |
| M3 | F4 Security Tests & Gate | F4-08 (Security & IDOR tests), F4-09 (E2E gate), F4-10 (Documentation & closure) | M2 | PLANNED |
| M4 | F4.5 Backend Chat Services | F4.5-03 (Device Auth), F4.5-04 (Chat REST), F4.5-05 (Attachments), F4.5-06 (SSE ChatHub), F4.5-07 (Audit & limits), F4.5-16 (Branding backend) | M2 | PLANNED |
| M5 | F4.5 Frontend & Client Integration | F4.5-08w (Live console wiring), F4.5-09 (UX badges & notifications), F4.5-10 (Rust client patch 008), F4.5-11 (Flutter UI), F4.5-12 (Remote escalation), F4.5-13 (policy.chat) | M4 | PLANNED |
| M6 | F4.5 E2E Gate & Final Closure | F4.5-14 (E2E gate & load testing), F4.5-15 (Deployment guide), final phase push | M5, M3 | PLANNED |

## Key Milestone Outputs
### Milestone M2 (F4-07):
- `console-web/src/types/index.ts`: BuildRole, BuildJobStatus, BuildJobRecord, EnqueueBuildResponse, profile schema sync.
- `console-web/src/api/client.ts`: enqueueBuild, getBuildJob, listBuildJobs, downloadBuildArtifact, revokeBuildJob, offline/demo fallback with monotonic state transitions.
- `console-web/src/components/views/BuilderView.tsx`: Complete overhaul with role selector, RBAC protection (non-admin tecnico guard), 2.5s polling loop, direct zip blob download, and recent jobs table.
- `console-web/src/App.tsx`: Dynamic code-splitting for BuilderView chunk.

## Interface Contracts
### Auth & 2FA (`cercano-api`)
- `POST /api/auth/login`: `{ username, password }` -> 200 `{ token, user }` OR 202 `{ mfa_required: true, mfa_token, expires_at }`.
- `POST /api/auth/2fa/enroll`: Bearer session -> 200 `{ otpauth_uri, totp_secret_base32 }`.
- `POST /api/auth/2fa/confirm`: Bearer session + `{ totp_code }` -> 200 `{ status: "confirmed", recovery_codes: [string] }`.
- `POST /api/auth/2fa/verify`: `{ mfa_token, totp_code?, recovery_code? }` -> 200 `{ token, user }` OR 401 / 429.
- `POST /api/auth/2fa/revoke`: Bearer session + `{ user_id? }` -> 200 `{ status: "revoked" }`.

### RBAC (`cercano-api`)
- Permissions: `users:*`, `roles:read`, `audit:read`, `settings:*`, `2fa:*`, `builder:*`, `chat:*`.
- Extractor: `RequirePermission(Permission)` returns 403 `authz.denied` on unauthorized request.

### Chat Services (`cercano-api`)
- `POST /api/chat/auth/nonce`: `{ device_id }` -> 200 `{ nonce, expires_at }`.
- `POST /api/chat/auth/verify`: `{ device_id, public_key, signature }` -> 200 `{ token: "cercano_chat_<64hex>", expires_at }`.
- `GET /api/chat/events`: SSE stream with events `message`, `status`, `queue`, `resync`.
- `POST /api/chat/conversations`: Create conversation -> 201 `{ conversation_id, ... }`.
- `POST /api/chat/conversations/:id/messages`: Send message -> 201 `{ message_id, ... }`.
- `POST /api/chat/conversations/:id/attachments`: Upload attachment (multipart) -> 201 `{ attachment_id, sha256, ... }`.
- `GET/PUT /api/chat/branding`: `{ brand_name, primary_color, logo_url?, welcome_message? }`.

## Code Layout
- `control-plane/cercano-api/src/`:
  - `db.rs`: Migrations 001..008.
  - `permissions.rs`: RBAC role matrix and permissions.
  - `routes/auth.rs`: Session login and 2FA handlers.
  - `routes/admin.rs`: Users, roles, and settings handlers.
  - `routes/builds.rs`: Build generator API.
  - `chat/`: Chat domain models, db queries, SSE hub, REST handlers.
- `console-web/src/`:
  - `components/views/`: UsersView, RolesView, AuditView, SettingsView, TwoFAView, BuilderView, ChatView.
  - `components/chat/`: ChatBrandingForm, ChatList, MessageThread.
- `client/`: Support chat client Rust bindings and Flutter widgets.
- `patches/`: `008-client-support-chat.patch`.
