import { app } from "./app.js";
import { issueToken } from "./app.js";
import { config } from "./config.js";
import { decryptSecret } from "./crypto.js";
import { database } from "./database.js";

app.listen(config.port, () => {
  console.log(`Node backend listening on http://localhost:${config.port}`);
});

let monitorRunning = false;
const githubHeaders = (token, etag = null) => ({
  Accept: "application/vnd.github+json",
  Authorization: `Bearer ${token}`,
  "User-Agent": "recallops-commit-monitor",
  "X-GitHub-Api-Version": "2022-11-28",
  ...(etag ? { "If-None-Match": etag } : {}),
});

function updateWorkflowFromSync(userId, payload) {
  const now = new Date().toISOString();
  for (const result of payload?.results || []) {
    const incident = result.incident;
    if (!incident?.repository || !incident?.commit_sha) continue;
    const status = incident.pull_request_url
      ? "pull_request_created"
      : incident.fixed_content
        ? "fix_generated"
        : "failure_detected";
    database.prepare(`
      UPDATE commit_workflows
      SET status = ?, deployment_id = ?, incident_id = ?,
          pull_request_url = ?, error = ?, updated_at = ?
      WHERE user_id = ? AND lower(github_repository) = lower(?) AND commit_sha = ?
    `).run(
      status,
      result.deployment_id || incident.deployment_id || null,
      incident.id || null,
      incident.pull_request_url || null,
      result.pull_request_error || result.fix_error || result.error || null,
      now,
      userId,
      incident.repository,
      incident.commit_sha,
    );
  }
}

async function triggerDeploymentInspection(user) {
  const authorization = `Bearer ${issueToken(user)}`;
  const endpoints = [];
  const vercel = database.prepare(`
    SELECT 1
    FROM provider_connections
    JOIN tracked_projects ON tracked_projects.user_id = provider_connections.user_id
    WHERE provider_connections.user_id = ?
      AND provider_connections.provider = 'vercel'
      AND tracked_projects.enabled = 1
    LIMIT 1
  `).get(user.id);
  const render = database.prepare(`
    SELECT 1
    FROM provider_connections
    JOIN render_services ON render_services.user_id = provider_connections.user_id
    WHERE provider_connections.user_id = ?
      AND provider_connections.provider = 'render'
      AND render_services.enabled = 1
    LIMIT 1
  `).get(user.id);
  if (vercel) endpoints.push("vercel");
  if (render) endpoints.push("render");
  if (!endpoints.length) {
    return {
      response: { ok: false, status: 409 },
      payload: { results: [], providers: [] },
    };
  }
  const attempts = await Promise.all(endpoints.map(async (provider) => {
    const response = await fetch(
      `${config.pythonBackendUrl.replace(/\/$/, "")}/api/integrations/${provider}/sync`,
      {
        method: "POST",
        headers: {
          Authorization: authorization,
          "Content-Type": "application/json",
        },
      },
    );
    const payload = await response.json().catch(() => ({}));
    return { provider, response, payload };
  }));
  const successful = attempts.filter((attempt) => attempt.response.ok);
  const payload = {
    results: successful.flatMap((attempt) => attempt.payload.results || []),
    providers: attempts.map((attempt) => ({
      provider: attempt.provider,
      ok: attempt.response.ok,
      error: attempt.response.ok
        ? null
        : attempt.payload.detail || attempt.payload.error || `Sync failed (${attempt.response.status})`,
    })),
  };
  if (successful.length) updateWorkflowFromSync(user.id, payload);
  const response = {
    ok: successful.length > 0,
    status: successful.length > 0 ? 200 : attempts[0]?.response.status || 502,
  };
  return { response, payload };
}

async function watchRepositoryCommits(now) {
  const repositories = database.prepare(`
    SELECT monitored_repositories.*, users.name, users.email, users.role,
           users.created_at AS user_created_at,
           provider_connections.access_token AS github_access_token
    FROM monitored_repositories
    JOIN users ON users.id = monitored_repositories.user_id
    JOIN provider_connections
      ON provider_connections.user_id = monitored_repositories.user_id
     AND provider_connections.provider = 'github'
  `).all();
  await Promise.allSettled(repositories.map(async (repository) => {
    const lastChecked = repository.last_commit_checked_at
      ? new Date(repository.last_commit_checked_at).getTime()
      : 0;
    if (now - lastChecked < Number(repository.poll_interval_seconds || 2) * 1000) return;
    const token = decryptSecret(repository.github_access_token);
    const response = await fetch(
      `https://api.github.com/repos/${repository.github_repository}/commits?per_page=1`,
      { headers: githubHeaders(token, repository.github_etag) },
    );
    const checkedAt = new Date().toISOString();
    if (response.status === 304) {
      database.prepare(`
        UPDATE monitored_repositories SET last_commit_checked_at = ?, updated_at = ?
        WHERE id = ?
      `).run(checkedAt, checkedAt, repository.id);
      return;
    }
    const payload = await response.json().catch(() => []);
    if (!response.ok) {
      database.prepare(`
        UPDATE monitored_repositories
        SET last_commit_checked_at = ?, last_sync_error = ?, updated_at = ?
        WHERE id = ?
      `).run(checkedAt, payload.message || `GitHub commit check failed (${response.status})`, checkedAt, repository.id);
      return;
    }
    const commit = payload[0];
    if (!commit?.sha) return;
    const etag = response.headers.get("etag");
    const isBaseline = !repository.last_commit_sha;
    database.prepare(`
      UPDATE monitored_repositories
      SET last_commit_sha = ?, last_commit_at = ?, github_etag = ?,
          last_commit_checked_at = ?, last_sync_error = NULL, updated_at = ?
      WHERE id = ?
    `).run(
      commit.sha,
      commit.commit?.author?.date || checkedAt,
      etag,
      checkedAt,
      checkedAt,
      repository.id,
    );
    if (isBaseline || commit.sha === repository.last_commit_sha) return;
    database.prepare(`
      INSERT OR IGNORE INTO commit_workflows
        (user_id, github_repository, commit_sha, commit_message, commit_url,
         status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'commit_detected', ?, ?)
    `).run(
      repository.user_id,
      repository.github_repository,
      commit.sha,
      commit.commit?.message?.split("\n")[0] || "Commit detected",
      commit.html_url || null,
      checkedAt,
      checkedAt,
    );
    const tracked = database.prepare(`
      SELECT id FROM tracked_projects
      WHERE user_id = ? AND lower(github_repository) = lower(?) AND enabled = 1
    `).get(repository.user_id, repository.github_repository);
    if (!tracked) {
      database.prepare(`
        UPDATE commit_workflows SET status = 'awaiting_deployment_access', updated_at = ?
        WHERE user_id = ? AND lower(github_repository) = lower(?) AND commit_sha = ?
      `).run(checkedAt, repository.user_id, repository.github_repository, commit.sha);
      return;
    }
    const user = {
      id: repository.user_id,
      name: repository.name,
      email: repository.email,
      role: repository.role,
      created_at: repository.user_created_at,
    };
    database.prepare(`
      UPDATE commit_workflows SET status = 'deployment_check_started', updated_at = ?
      WHERE user_id = ? AND lower(github_repository) = lower(?) AND commit_sha = ?
    `).run(checkedAt, repository.user_id, repository.github_repository, commit.sha);
    const { response: syncResponse, payload: syncPayload } = await triggerDeploymentInspection(user);
    if (!syncResponse.ok) {
      database.prepare(`
        UPDATE commit_workflows SET status = 'deployment_check_failed', error = ?, updated_at = ?
        WHERE user_id = ? AND lower(github_repository) = lower(?) AND commit_sha = ?
      `).run(
        syncPayload.detail || syncPayload.error || `Deployment check failed (${syncResponse.status})`,
        new Date().toISOString(),
        repository.user_id,
        repository.github_repository,
        commit.sha,
      );
    } else {
      const matched = (syncPayload.results || []).some(
        (result) => result.incident?.commit_sha === commit.sha,
      );
      if (!matched) {
        database.prepare(`
          UPDATE commit_workflows SET status = 'watching_deployment', updated_at = ?
          WHERE user_id = ? AND lower(github_repository) = lower(?) AND commit_sha = ?
        `).run(
          new Date().toISOString(),
          repository.user_id,
          repository.github_repository,
          commit.sha,
        );
      }
    }
  }));
}

async function monitorTrackedProjects() {
  if (monitorRunning) return;
  monitorRunning = true;
  try {
    const now = Date.now();
    await watchRepositoryCommits(now);
    const users = database.prepare(`
      SELECT users.*, MIN(monitored_repositories.poll_interval_seconds) AS poll_interval_seconds,
             MAX(monitored_repositories.last_synced_at) AS last_synced_at
      FROM users
      JOIN monitored_repositories ON monitored_repositories.user_id = users.id
      JOIN tracked_projects ON tracked_projects.user_id = users.id
      WHERE tracked_projects.enabled = 1
      GROUP BY users.id
    `).all();
    const dueUsers = users.filter((user) => {
      const last = user.last_synced_at ? new Date(user.last_synced_at).getTime() : 0;
      return now - last >= Number(user.poll_interval_seconds || 2) * 1000;
    });
    await Promise.allSettled(dueUsers.map(async (user) => {
      const { response } = await triggerDeploymentInspection(user);
      const syncedAt = new Date().toISOString();
      const error = response.ok ? null : `Sync failed (${response.status})`;
      database.prepare(`
        UPDATE monitored_repositories
        SET last_synced_at = ?, last_sync_error = ?, updated_at = ?
        WHERE user_id = ?
      `).run(syncedAt, error, syncedAt, user.id);
    }));
  } finally {
    monitorRunning = false;
  }
}

if (config.monitorIntervalMs > 0) {
  setTimeout(() => void monitorTrackedProjects(), 2_000);
  setInterval(() => void monitorTrackedProjects(), 2_000);
}
