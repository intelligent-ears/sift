CREATE INDEX IF NOT EXISTS idx_findings_target_severity ON findings (target_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_scan_created ON findings (scan_id, created_at);
