-- Ethical Security Copilot — Etapa B: almacenamiento (SQLite MVP, portable a Postgres)

CREATE TABLE IF NOT EXISTS assessments (
  id TEXT NOT NULL,
  version INTEGER NOT NULL,
  state TEXT NOT NULL,
  content_json TEXT NOT NULL,        -- contenido canónico (inmutable por versión)
  content_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (id, version)
);

CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL,
  assessment_version INTEGER NOT NULL,
  module_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  targets_json TEXT NOT NULL,
  limits_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending_approval','approved','rejected','running','done','stopped')),
  approved_by TEXT,                  -- siempre un humano (operator/authorizer), nunca 'agent'
  approval_token_hash TEXT,          -- token de un solo uso emitido por canal separado
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  assessment_id TEXT NOT NULL,
  data_json TEXT NOT NULL,           -- ya redactado en ingesta
  triage TEXT NOT NULL DEFAULT 'unverified',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kill_switch (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  active INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  activated_at TEXT
);
INSERT OR IGNORE INTO kill_switch (id, active) VALUES (1, 0);

-- Auditoría append-only: sin UPDATE ni DELETE.
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  role TEXT NOT NULL,
  action TEXT NOT NULL,
  assessment_id TEXT,
  decision_id TEXT,
  payload_redacted TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log es append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log es append-only'); END;
