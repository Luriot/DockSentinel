/**
 * Versioned schema migrations. Append only: never edit a migration that has shipped.
 * Each entry runs inside a transaction and is recorded in schema_migrations.
 */
export interface Migration {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
}

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'initial schema',
    sql: `
      CREATE TABLE users (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE sessions (
        token_hash TEXT PRIMARY KEY,
        csrf_token TEXT NOT NULL,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      ) STRICT;
      CREATE INDEX sessions_expires ON sessions(expires_at);

      CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE environments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL COLLATE NOCASE UNIQUE,
        kind TEXT NOT NULL CHECK (kind IN ('unix','tcp','tls')),
        address TEXT NOT NULL,
        tls_ca TEXT,
        tls_cert TEXT,
        tls_key TEXT,
        tls_skip_verify INTEGER NOT NULL DEFAULT 0 CHECK (tls_skip_verify IN (0,1)),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
        scan_enabled INTEGER NOT NULL DEFAULT 1 CHECK (scan_enabled IN (0,1)),
        quick_interval_hours INTEGER NOT NULL DEFAULT 24 CHECK (quick_interval_hours >= 0),
        standard_interval_hours INTEGER NOT NULL DEFAULT 168 CHECK (standard_interval_hours >= 0),
        min_alert_severity TEXT NOT NULL DEFAULT 'HIGH',
        status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','online','offline')),
        status_message TEXT,
        last_contact_at TEXT,
        last_discovery_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;

      CREATE TABLE images (
        image_id TEXT PRIMARY KEY,
        repo_digests TEXT NOT NULL DEFAULT '[]',
        size_bytes INTEGER,
        os_family TEXT,
        os_version TEXT,
        created_ts TEXT,
        first_seen_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_scan_at TEXT,
        last_scan_status TEXT,
        last_success_at TEXT,
        last_success_scan_id INTEGER,
        critical_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        medium_count INTEGER NOT NULL DEFAULT 0,
        low_count INTEGER NOT NULL DEFAULT 0,
        unknown_count INTEGER NOT NULL DEFAULT 0,
        fixable_count INTEGER NOT NULL DEFAULT 0
      ) STRICT;
      CREATE INDEX images_last_success ON images(last_success_at);

      CREATE TABLE image_locations (
        image_id TEXT NOT NULL REFERENCES images(image_id) ON DELETE CASCADE,
        environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
        reference TEXT NOT NULL,
        tag TEXT,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (image_id, environment_id, reference)
      ) STRICT;
      CREATE INDEX image_locations_env ON image_locations(environment_id);
      CREATE INDEX image_locations_tag ON image_locations(tag);

      CREATE TABLE containers (
        id TEXT NOT NULL,
        environment_id INTEGER NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        image_ref TEXT NOT NULL,
        image_id TEXT REFERENCES images(image_id) ON DELETE SET NULL,
        state TEXT NOT NULL,
        labels TEXT NOT NULL DEFAULT '{}',
        ports TEXT NOT NULL DEFAULT '[]',
        network_mode TEXT,
        exposure_state TEXT NOT NULL DEFAULT 'unknown' CHECK (exposure_state IN ('confirmed','potential','internal','unknown')),
        exposure_reason TEXT,
        created_ts TEXT,
        started_ts TEXT,
        present INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0,1)),
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (environment_id, id)
      ) STRICT;
      CREATE INDEX containers_image ON containers(image_id);
      CREATE INDEX containers_present ON containers(present);
      CREATE INDEX containers_env ON containers(environment_id);

      CREATE TABLE scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        environment_id INTEGER REFERENCES environments(id) ON DELETE SET NULL,
        image_id TEXT NOT NULL,
        image_ref TEXT NOT NULL,
        profile TEXT NOT NULL CHECK (profile IN ('quick','standard')),
        trigger TEXT NOT NULL CHECK (trigger IN ('manual','schedule','new_image','retry')),
        status TEXT NOT NULL CHECK (status IN ('queued','running','success','failed','cancelled')),
        priority INTEGER NOT NULL DEFAULT 0,
        queued_at TEXT NOT NULL,
        run_after TEXT,
        started_at TEXT,
        finished_at TEXT,
        duration_ms INTEGER,
        scanner TEXT NOT NULL DEFAULT 'trivy',
        scanner_version TEXT,
        db_version TEXT,
        db_updated_at TEXT,
        critical_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        medium_count INTEGER NOT NULL DEFAULT 0,
        low_count INTEGER NOT NULL DEFAULT 0,
        unknown_count INTEGER NOT NULL DEFAULT 0,
        total_count INTEGER NOT NULL DEFAULT 0,
        fixable_count INTEGER NOT NULL DEFAULT 0,
        error_code TEXT,
        error_message TEXT,
        exit_code INTEGER,
        attempts INTEGER NOT NULL DEFAULT 1,
        warnings TEXT NOT NULL DEFAULT '[]'
      ) STRICT;
      CREATE INDEX scans_image ON scans(image_id, queued_at DESC);
      CREATE INDEX scans_status ON scans(status, queued_at);
      CREATE INDEX scans_ready ON scans(status, run_after, queued_at);
      CREATE INDEX scans_env ON scans(environment_id, queued_at DESC);
      CREATE INDEX scans_queued ON scans(queued_at DESC);

      CREATE TABLE findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_id TEXT NOT NULL REFERENCES images(image_id) ON DELETE CASCADE,
        target TEXT NOT NULL,
        class TEXT,
        type TEXT,
        vuln_id TEXT NOT NULL,
        pkg_name TEXT NOT NULL,
        installed_version TEXT NOT NULL,
        fixed_version TEXT,
        severity TEXT NOT NULL,
        status TEXT,
        title TEXT,
        primary_url TEXT,
        cvss_score REAL,
        cvss_source TEXT,
        cvss_vector TEXT,
        published_at TEXT,
        modified_at TEXT,
        kev INTEGER NOT NULL DEFAULT -1 CHECK (kev IN (-1,0,1)),
        kev_added_at TEXT,
        episode INTEGER NOT NULL DEFAULT 1,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        last_scan_id INTEGER,
        resolved_at TEXT,
        UNIQUE (image_id, target, vuln_id, pkg_name, installed_version)
      ) STRICT;
      CREATE INDEX findings_image ON findings(image_id);
      CREATE INDEX findings_severity ON findings(severity, resolved_at);
      CREATE INDEX findings_vuln ON findings(vuln_id);
      CREATE INDEX findings_open ON findings(resolved_at) WHERE resolved_at IS NULL;

      CREATE TABLE finding_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        scan_id INTEGER,
        image_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        detail TEXT,
        created_at TEXT NOT NULL
      ) STRICT;
      CREATE INDEX finding_events_created ON finding_events(created_at DESC);
      CREATE INDEX finding_events_image ON finding_events(image_id, created_at DESC);
      CREATE INDEX finding_events_finding ON finding_events(finding_id, created_at DESC);

      CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dedupe_key TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        severity TEXT,
        environment_id INTEGER REFERENCES environments(id) ON DELETE SET NULL,
        image_id TEXT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),
        tags TEXT,
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','sent','failed')),
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        sent_at TEXT
      ) STRICT;
      CREATE INDEX alerts_status ON alerts(status, created_at);
      CREATE INDEX alerts_created ON alerts(created_at DESC);
      CREATE INDEX alerts_image ON alerts(image_id);

      CREATE TABLE kev (
        cve_id TEXT PRIMARY KEY,
        date_added TEXT,
        synced_at TEXT NOT NULL
      ) STRICT;
      CREATE INDEX kev_added ON kev(date_added DESC);

      CREATE TABLE kev_sync (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        status TEXT NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','ok','error')),
        synced_at TEXT,
        catalog_version TEXT,
        entry_count INTEGER,
        error TEXT
      ) STRICT;
      INSERT INTO kev_sync (id, status) VALUES (1, 'idle');
    `,
  },
  {
    version: 2,
    name: 'content scans and findings',
    sql: `
      ALTER TABLE scans ADD COLUMN kind TEXT NOT NULL DEFAULT 'vulnerability'
        CHECK (kind IN ('vulnerability','content'));
      CREATE INDEX scans_kind ON scans(kind, queued_at DESC);

      CREATE TABLE content_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_id TEXT NOT NULL REFERENCES images(image_id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('misconfiguration','secret')),
        scope TEXT NOT NULL CHECK (scope IN ('image','image-config')),
        identity TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        category TEXT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        target TEXT NOT NULL,
        message TEXT,
        resolution TEXT,
        primary_url TEXT,
        start_line INTEGER,
        end_line INTEGER,
        episode INTEGER NOT NULL DEFAULT 1,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        last_scan_id INTEGER,
        resolved_at TEXT,
        UNIQUE (image_id, identity)
      ) STRICT;
      CREATE INDEX content_findings_image ON content_findings(image_id, resolved_at);
      CREATE INDEX content_findings_state ON content_findings(resolved_at, severity);
      CREATE INDEX content_findings_kind ON content_findings(kind, resolved_at);
    `,
  },
];

export const SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1]?.version ?? 0;
