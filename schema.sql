-- useaitree D1 schema
-- Run: paste this entire file into Cloudflare dashboard > D1 > your database > Console > Execute
--
-- This is purely a VISIT LOG + CONFUSION SIGNAL store, used for your own
-- analytics. It has nothing to do with how agents navigate the site --
-- navigation is pure markdown links, no database involved.

CREATE TABLE IF NOT EXISTS request_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  path TEXT NOT NULL,
  query_string TEXT,
  user_agent TEXT,
  matched_bot TEXT,
  referrer TEXT,
  country TEXT,
  continent TEXT,
  city TEXT,
  region TEXT,
  postal_code TEXT,
  timezone TEXT,
  latitude TEXT,
  longitude TEXT,
  ip TEXT,
  asn TEXT,
  as_organization TEXT,
  http_protocol TEXT,
  tls_version TEXT,
  accept_language TEXT,
  accept_header TEXT,
  origin_header TEXT,
  sec_fetch_site TEXT,
  cache_status TEXT,
  ray_id TEXT,
  method TEXT,
  response_bytes INTEGER,
  duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS missed_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  path TEXT NOT NULL,
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_logs_path ON request_logs(path);
CREATE INDEX IF NOT EXISTS idx_logs_bot ON request_logs(matched_bot);
CREATE INDEX IF NOT EXISTS idx_missed_path ON missed_requests(path);

-- Confusion signal tracking.
-- session_hash = sha256(ip + user-agent), truncated. Not personal data:
-- one-way hash, purged after 30 days. Groups requests likely to be the
-- same agent working one task in one window.
CREATE TABLE IF NOT EXISTS session_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_hash TEXT NOT NULL,
  path TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  matched_bot TEXT
);

CREATE INDEX IF NOT EXISTS idx_session_hash ON session_events(session_hash);
CREATE INDEX IF NOT EXISTS idx_session_path ON session_events(path);
CREATE INDEX IF NOT EXISTS idx_session_time ON session_events(timestamp);

-- Map-selection tracking: when a session fetches llms.txt or
-- manifest.json (the full site map) and then fetches a specific doc
-- shortly after, that doc is the one the agent CHOSE from the map. This
-- is a direct-intent signal, our clearest one.
CREATE TABLE IF NOT EXISTS map_selections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_hash TEXT NOT NULL,
  selected_path TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  matched_bot TEXT
);
CREATE INDEX IF NOT EXISTS idx_map_selections_path ON map_selections(selected_path);

-- PURGE POLICY: session_events and map_selections rows older than 30
-- days should be periodically deleted once their signal is no longer
-- needed, keeping raw session-linkable data short-lived.

-- Admin login sessions. Created when the admin logs in successfully via
-- /admin. The actual password is never stored here or in code -- it lives
-- only in Cloudflare's encrypted environment variables. This table only
-- stores short-lived session tokens after a successful login.
CREATE TABLE IF NOT EXISTS admin_sessions (
  token TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- Every login attempt, successful or not -- a real security signal, free
-- to collect, and useful to notice repeated failed attempts.
CREATE TABLE IF NOT EXISTS admin_login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  email_attempted TEXT,
  success INTEGER NOT NULL,
  ip TEXT
);

-- Skill-selection tracking: when a session fetches /skills/index.md and
-- then fetches a specific skill file shortly after, that's the skill the
-- agent chose -- tells you whether the skill-triage design is actually
-- working the way it's meant to.
CREATE TABLE IF NOT EXISTS skill_selections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_hash TEXT NOT NULL,
  selected_skill TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  matched_bot TEXT
);
CREATE INDEX IF NOT EXISTS idx_skill_selections ON skill_selections(selected_skill);
