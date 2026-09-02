-- C-Guard PostgreSQL alignment draft
-- Target DB schema: cstrike (PostgreSQL 16)
-- Purpose: persist current RuntimeState model in server-authoritative form.

CREATE SCHEMA IF NOT EXISTS cstrike;

CREATE TABLE IF NOT EXISTS cstrike.cguard_users (
  user_id uuid PRIMARY KEY,
  username varchar(255) NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_teams (
  team_id uuid PRIMARY KEY,
  name varchar(255) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_clients (
  client_instance_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  team_id uuid NULL REFERENCES cstrike.cguard_teams(team_id) ON DELETE SET NULL,
  device_id varchar(255) NOT NULL,
  os varchar(64) NULL,
  os_version varchar(64) NULL,
  app_version varchar(64) NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cguard_clients_user_device
  ON cstrike.cguard_clients(user_id, device_id);

CREATE TABLE IF NOT EXISTS cstrike.cguard_sessions (
  session_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  team_id uuid NULL REFERENCES cstrike.cguard_teams(team_id) ON DELETE SET NULL,
  client_instance_id uuid NOT NULL REFERENCES cstrike.cguard_clients(client_instance_id) ON DELETE CASCADE,
  status varchar(20) NOT NULL,
  policy_version varchar(64) NOT NULL,
  last_heartbeat_at timestamptz NULL,
  health_firewall_state varchar(32) NULL,
  health_observer_state varchar(32) NULL,
  health_client_agent_state varchar(32) NULL,
  health_kernel_bridge_state varchar(32) NULL,
  health_kernel_driver_loaded boolean NOT NULL DEFAULT false,
  discord_user_id varchar(50) NULL,
  discord_display_name varchar(128) NULL,
  discord_username varchar(128) NULL,
  discord_link_state varchar(16) NULL,
  identity_source varchar(16) NULL,
  session_binding_device_id varchar(255) NULL,
  last_ip varchar(64) NULL,
  last_user_agent text NULL,
  decision_status varchar(20) NULL,
  decision_reason_code varchar(128) NULL,
  decision_reason text NULL,
  risk_score numeric(10,3) NULL,
  session_meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  ended_at timestamptz NULL,
  CONSTRAINT chk_cguard_sessions_status CHECK (status IN ('ACTIVE','RESTRICTED','BLOCKED','OFFLINE'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cguard_sessions_active_user
  ON cstrike.cguard_sessions(user_id)
  WHERE status = 'ACTIVE';

CREATE UNIQUE INDEX IF NOT EXISTS ux_cguard_sessions_active_client
  ON cstrike.cguard_sessions(client_instance_id)
  WHERE status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS ix_cguard_sessions_discord_user_id
  ON cstrike.cguard_sessions(discord_user_id);

ALTER TABLE cstrike.cguard_sessions
  ADD COLUMN IF NOT EXISTS discord_display_name varchar(128) NULL;

ALTER TABLE cstrike.cguard_sessions
  ADD COLUMN IF NOT EXISTS discord_username varchar(128) NULL;

CREATE TABLE IF NOT EXISTS cstrike.cguard_client_heartbeats (
  client_instance_id uuid PRIMARY KEY REFERENCES cstrike.cguard_clients(client_instance_id) ON DELETE CASCADE,
  heartbeat_epoch_sec bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_events (
  event_id bigserial PRIMARY KEY,
  timestamp timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  event_type varchar(64) NOT NULL,
  severity varchar(16) NOT NULL,
  session_id uuid NOT NULL REFERENCES cstrike.cguard_sessions(session_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  client_version varchar(64) NOT NULL,
  evidence jsonb NOT NULL,
  event_meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_cguard_events_severity CHECK (severity IN ('low','medium','high','critical'))
);

CREATE INDEX IF NOT EXISTS ix_cguard_events_session_time
  ON cstrike.cguard_events(session_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS ix_cguard_events_type_time
  ON cstrike.cguard_events(event_type, timestamp DESC);

CREATE TABLE IF NOT EXISTS cstrike.cguard_event_rejections (
  rejection_id bigserial PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now(),
  session_id uuid NULL,
  user_id uuid NULL,
  event_type varchar(64) NULL,
  reject_code varchar(128) NOT NULL,
  reject_message text NOT NULL,
  raw_event jsonb NULL,
  rejection_meta jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_cguard_event_rejections_received_at
  ON cstrike.cguard_event_rejections(received_at DESC);

CREATE TABLE IF NOT EXISTS cstrike.cguard_session_decisions (
  decision_id bigserial PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES cstrike.cguard_sessions(session_id) ON DELETE CASCADE,
  status varchar(20) NOT NULL,
  reason_code varchar(128) NULL,
  reason text NULL,
  risk_score numeric(10,3) NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  decision_meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_cguard_session_decisions_status CHECK (status IN ('ok','warn','restricted','blocked'))
);

CREATE INDEX IF NOT EXISTS ix_cguard_session_decisions_session_time
  ON cstrike.cguard_session_decisions(session_id, decided_at DESC);

CREATE TABLE IF NOT EXISTS cstrike.cguard_review_notes (
  note_id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES cstrike.cguard_sessions(session_id) ON DELETE CASCADE,
  operator_id uuid NULL,
  note text NOT NULL,
  created_at timestamptz NOT NULL,
  note_meta jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_review_actions (
  action_row_id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES cstrike.cguard_sessions(session_id) ON DELETE CASCADE,
  operator_id uuid NULL,
  action_type varchar(64) NOT NULL,
  reason_code varchar(128) NULL,
  reason text NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_cguard_review_actions_session_time
  ON cstrike.cguard_review_actions(session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cstrike.cguard_discord_identity_links (
  user_id uuid PRIMARY KEY REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  discord_user_id varchar(50) NOT NULL UNIQUE,
  discord_display_name varchar(128) NULL,
  discord_username varchar(128) NULL,
  discord_link_state varchar(16) NOT NULL DEFAULT 'linked',
  identity_source varchar(16) NOT NULL DEFAULT 'oauth',
  verification_method varchar(64) NOT NULL DEFAULT 'oauth_pkce',
  linked_by varchar(128) NOT NULL,
  linked_at timestamptz NOT NULL,
  verified_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_cguard_discord_link_state CHECK (discord_link_state IN ('linked','unlinked','unknown','error')),
  CONSTRAINT chk_cguard_discord_identity_source CHECK (identity_source IN ('oauth','sdk_hint','unknown'))
);

ALTER TABLE cstrike.cguard_discord_identity_links
  ADD COLUMN IF NOT EXISTS discord_display_name varchar(128) NULL;

ALTER TABLE cstrike.cguard_discord_identity_links
  ADD COLUMN IF NOT EXISTS discord_username varchar(128) NULL;

CREATE TABLE IF NOT EXISTS cstrike.cguard_discord_actions (
  action_id varchar(128) PRIMARY KEY,
  action_type varchar(32) NOT NULL,
  status varchar(32) NOT NULL,
  discord_user_id varchar(50) NOT NULL,
  guild_id varchar(50) NULL,
  role_id varchar(50) NULL,
  reason_code varchar(128) NULL,
  reason_text text NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by varchar(128) NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  expires_at timestamptz NULL,
  callback_status varchar(32) NULL,
  callback_at timestamptz NULL,
  applied_at timestamptz NULL,
  failed_at timestamptz NULL,
  retry_after_at timestamptz NULL,
  attempt_count int NOT NULL DEFAULT 0,
  last_error jsonb NULL,
  idempotency_fingerprint text NOT NULL,
  CONSTRAINT chk_cguard_discord_action_type CHECK (action_type IN ('assign_role','remove_role','announce')),
  CONSTRAINT chk_cguard_discord_action_status CHECK (status IN ('pending','applied','failed','retrying','expired'))
);

CREATE INDEX IF NOT EXISTS ix_cguard_discord_actions_user_status
  ON cstrike.cguard_discord_actions(discord_user_id, status);

CREATE TABLE IF NOT EXISTS cstrike.cguard_discord_action_callbacks (
  callback_id varchar(128) PRIMARY KEY,
  action_id varchar(128) NOT NULL REFERENCES cstrike.cguard_discord_actions(action_id) ON DELETE CASCADE,
  status varchar(32) NOT NULL,
  callback_at timestamptz NOT NULL,
  retry_after_at timestamptz NULL,
  error_code varchar(128) NULL,
  error_message text NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  processed_by varchar(128) NOT NULL,
  processed_at timestamptz NOT NULL,
  idempotency_fingerprint text NOT NULL,
  CONSTRAINT chk_cguard_discord_callback_status CHECK (status IN ('applied','failed','retrying','expired'))
);

CREATE INDEX IF NOT EXISTS ix_cguard_discord_callbacks_action
  ON cstrike.cguard_discord_action_callbacks(action_id, processed_at DESC);

CREATE TABLE IF NOT EXISTS cstrike.cguard_bans (
  ban_id uuid PRIMARY KEY,
  scope varchar(16) NOT NULL,
  target_id varchar(128) NOT NULL,
  reason text NULL,
  reason_code varchar(128) NULL,
  created_by varchar(128) NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NULL,
  revoked_at timestamptz NULL,
  revoked_by varchar(128) NULL,
  status varchar(16) NOT NULL,
  CONSTRAINT chk_cguard_ban_scope CHECK (scope IN ('user','team','session')),
  CONSTRAINT chk_cguard_ban_status CHECK (status IN ('ACTIVE','EXPIRED','REVOKED'))
);

CREATE INDEX IF NOT EXISTS ix_cguard_bans_scope_target
  ON cstrike.cguard_bans(scope, target_id, status);

CREATE TABLE IF NOT EXISTS cstrike.cguard_audit_logs (
  audit_id uuid PRIMARY KEY,
  at timestamptz NOT NULL,
  actor varchar(128) NOT NULL,
  action varchar(128) NOT NULL,
  object_type varchar(64) NULL,
  object_id varchar(128) NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_cguard_audit_logs_at
  ON cstrike.cguard_audit_logs(at DESC);

CREATE INDEX IF NOT EXISTS ix_cguard_audit_logs_action
  ON cstrike.cguard_audit_logs(action, at DESC);

CREATE TABLE IF NOT EXISTS cstrike.cguard_submission_proof_consumptions (
  consumption_id bigserial PRIMARY KEY,
  proof_jti varchar(255) NOT NULL UNIQUE,
  proof_nonce varchar(255) NOT NULL UNIQUE,
  session_id uuid NOT NULL REFERENCES cstrike.cguard_sessions(session_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  client_instance_id uuid NOT NULL REFERENCES cstrike.cguard_clients(client_instance_id) ON DELETE CASCADE,
  device_id varchar(255) NULL,
  purpose varchar(32) NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  source_ip varchar(64) NULL,
  consume_meta jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT chk_cguard_submission_proof_purpose CHECK (purpose IN ('submit','download'))
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_refresh_tokens (
  token_hash varchar(128) PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  team_id uuid NULL REFERENCES cstrike.cguard_teams(team_id) ON DELETE SET NULL,
  session_id uuid NOT NULL REFERENCES cstrike.cguard_sessions(session_id) ON DELETE CASCADE,
  client_instance_id uuid NOT NULL REFERENCES cstrike.cguard_clients(client_instance_id) ON DELETE CASCADE,
  exp_epoch_sec bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_revoked_jti (
  jti varchar(255) PRIMARY KEY,
  exp_epoch_sec bigint NOT NULL,
  revoked_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cstrike.cguard_active_jti_by_user (
  user_id uuid PRIMARY KEY REFERENCES cstrike.cguard_users(user_id) ON DELETE CASCADE,
  jti varchar(255) NOT NULL,
  exp_epoch_sec bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
