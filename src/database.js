import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { config } from "./config.js";

mkdirSync(dirname(config.databasePath), { recursive: true });

export const database = new Database(config.databasePath);
database.pragma("journal_mode = WAL");
database.pragma("foreign_keys = ON");
database.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    firebase_uid TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'engineer',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS provider_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    token_expires_at TEXT,
    account_id TEXT,
    account_name TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, provider),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS tracked_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    vercel_project_id TEXT NOT NULL,
    vercel_project_name TEXT NOT NULL,
    vercel_team_id TEXT,
    github_repository TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, vercel_project_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS render_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    render_service_id TEXT NOT NULL,
    render_service_name TEXT NOT NULL,
    render_owner_id TEXT,
    github_repository TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, render_service_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS monitored_repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    github_repository TEXT NOT NULL,
    repository_id TEXT,
    private INTEGER NOT NULL DEFAULT 0,
    default_branch TEXT,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 2,
    last_commit_sha TEXT,
    last_commit_at TEXT,
    github_etag TEXT,
    last_commit_checked_at TEXT,
    last_synced_at TEXT,
    last_sync_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, github_repository),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS commit_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    github_repository TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    commit_message TEXT,
    commit_url TEXT,
    status TEXT NOT NULL DEFAULT 'commit_detected',
    deployment_id TEXT,
    incident_id TEXT,
    pull_request_url TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, github_repository, commit_sha),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    code_verifier TEXT,
    nonce TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

for (const [table, column, definition] of [
  ["users", "firebase_uid", "TEXT"],
  ["provider_connections", "refresh_token", "TEXT"],
  ["provider_connections", "token_expires_at", "TEXT"],
  ["oauth_states", "nonce", "TEXT"],
  ["monitored_repositories", "poll_interval_seconds", "INTEGER NOT NULL DEFAULT 2"],
  ["monitored_repositories", "last_commit_sha", "TEXT"],
  ["monitored_repositories", "last_commit_at", "TEXT"],
  ["monitored_repositories", "github_etag", "TEXT"],
  ["monitored_repositories", "last_commit_checked_at", "TEXT"],
  ["monitored_repositories", "last_synced_at", "TEXT"],
  ["monitored_repositories", "last_sync_error", "TEXT"],
]) {
  const columns = database.prepare(`PRAGMA table_info(${table})`).all();
  if (!columns.some((item) => item.name === column)) {
    database.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

export function safeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.created_at,
  };
}
