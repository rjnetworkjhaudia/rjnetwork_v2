PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS billing_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_key TEXT NOT NULL UNIQUE,
  billing_year INTEGER NOT NULL,
  billing_month INTEGER NOT NULL CHECK (billing_month BETWEEN 1 AND 12),
  trigger TEXT NOT NULL DEFAULT 'scheduled' CHECK (trigger IN ('scheduled','manual')),
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
  generated_count INTEGER NOT NULL DEFAULT 0,
  skipped_count INTEGER NOT NULL DEFAULT 0,
  overdue_count INTEGER NOT NULL DEFAULT 0,
  reconciled_count INTEGER NOT NULL DEFAULT 0,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TEXT,
  error_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_billing_runs_period ON billing_runs(billing_year,billing_month);
CREATE INDEX IF NOT EXISTS idx_billing_runs_status ON billing_runs(status);
