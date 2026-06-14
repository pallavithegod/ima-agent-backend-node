import crypto from "node:crypto";
import express from "express";
import { z } from "zod";
import { authenticate } from "./auth.js";
import { config } from "./config.js";
import { decryptSecret, encryptSecret } from "./crypto.js";
import { database } from "./database.js";

export const integrationsRouter = express.Router();
integrationsRouter.use((request, response, next) => {
  if (request.path === "/vercel/callback") return next();
  return authenticate(request, response, next);
});

const githubHeaders = (token) => ({
  Accept: "application/vnd.github+json",
  Authorization: `Bearer ${token}`,
  "User-Agent": "incident-memory-agent",
  "X-GitHub-Api-Version": "2022-11-28",
});
const vercelHeaders = (token) => ({ Authorization: `Bearer ${token}` });

async function checkedFetch(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.message || payload.error?.message || `Provider request failed (${response.status})`);
  return payload;
}

async function optionalFetch(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, payload };
}

function upsertConnection(
  userId,
  provider,
  token,
  accountId,
  accountName,
  metadata = {},
  refreshToken = null,
  tokenExpiresAt = null,
) {
  const now = new Date().toISOString();
  database.prepare(`
    INSERT INTO provider_connections
      (user_id, provider, access_token, refresh_token, token_expires_at,
       account_id, account_name, metadata, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, provider) DO UPDATE SET
      access_token=excluded.access_token,
      refresh_token=COALESCE(excluded.refresh_token, provider_connections.refresh_token),
      token_expires_at=excluded.token_expires_at, account_id=excluded.account_id,
      account_name=excluded.account_name, metadata=excluded.metadata, updated_at=excluded.updated_at
  `).run(
    userId,
    provider,
    encryptSecret(token),
    refreshToken ? encryptSecret(refreshToken) : null,
    tokenExpiresAt,
    accountId,
    accountName,
    JSON.stringify(metadata),
    now,
    now,
  );
}

function connection(userId, provider) {
  return database.prepare("SELECT * FROM provider_connections WHERE user_id = ? AND provider = ?").get(userId, provider);
}

function repositoryShape(repo, imported = false, vercelProject = null) {
  return {
    id: String(repo.id),
    fullName: repo.full_name,
    name: repo.name,
    owner: repo.owner?.login || repo.full_name.split("/")[0],
    ownerAvatar: repo.owner?.avatar_url || null,
    private: Boolean(repo.private),
    url: repo.html_url,
    description: repo.description,
    language: repo.language,
    defaultBranch: repo.default_branch,
    updatedAt: repo.pushed_at || repo.updated_at,
    imported,
    vercelProject,
  };
}

function vercelProjectShape(project, teamId, scope) {
  const link = project.link || {};
  const owner = link.org || link.orgId || link.owner || null;
  const repo = link.repo || link.repoName || null;
  return {
    id: project.id,
    name: project.name,
    teamId,
    scope,
    framework: project.framework || null,
    updatedAt: project.updatedAt ? new Date(project.updatedAt).toISOString() : null,
    githubRepository: owner && repo ? `${owner}/${repo}` : repo,
  };
}

function projectFromDeployment(deployment) {
  const meta = deployment.meta || {};
  const owner = meta.githubOrg || meta.githubCommitOrg || null;
  const repo = meta.githubRepo || meta.githubCommitRepo || null;
  const projectId = deployment.projectId || deployment.project?.id || deployment.name;
  if (!projectId) return null;
  return {
    id: projectId,
    name: deployment.name || deployment.project?.name || projectId,
    teamId: deployment.teamId || deployment.team?.id || null,
    scope: deployment.team?.name || "Deployment access",
    framework: null,
    updatedAt: deployment.createdAt ? new Date(deployment.createdAt).toISOString() : null,
    githubRepository: owner && repo ? `${owner}/${repo}` : repo,
  };
}

async function vercelProjectsForUser(userId) {
  const token = await vercelAccessToken(userId);
  const personal = await optionalFetch("https://api.vercel.com/v9/projects?limit=100", {
    headers: vercelHeaders(token),
  });
  const projects = personal.ok
    ? (personal.payload.projects || []).map((project) => vercelProjectShape(project, null, "Personal"))
    : [];
  const teamsResult = await optionalFetch("https://api.vercel.com/v2/teams?limit=100", {
    headers: vercelHeaders(token),
  });
  const teams = teamsResult.ok ? teamsResult.payload.teams || [] : [];
  const groups = await Promise.all(teams.map(async (team) => {
    const scope = { id: team.id, name: team.name };
    const query = scope.id ? `?limit=100&teamId=${encodeURIComponent(scope.id)}` : "?limit=100";
    const result = await optionalFetch(`https://api.vercel.com/v9/projects${query}`, {
      headers: vercelHeaders(token),
    });
    return result.ok
      ? (result.payload.projects || []).map((project) => vercelProjectShape(project, scope.id, scope.name))
      : [];
  }));
  const deploymentResult = await optionalFetch(
    "https://api.vercel.com/v6/deployments?limit=100",
    { headers: vercelHeaders(token) },
  );
  const deploymentProjects = deploymentResult.ok
    ? (deploymentResult.payload.deployments || [])
      .map(projectFromDeployment)
      .filter(Boolean)
    : [];
  const uniqueProjects = new Map();
  for (const project of [...projects, ...groups.flat(), ...deploymentProjects]) {
    const key = `${project.teamId || "personal"}:${project.id}`;
    const current = uniqueProjects.get(key);
    uniqueProjects.set(key, {
      ...current,
      ...project,
      githubRepository: project.githubRepository || current?.githubRepository || null,
    });
  }
  return {
    projects: [...uniqueProjects.values()],
    teamAccessLimited: !teamsResult.ok,
    personalAccessLimited: !personal.ok,
    deploymentAccessLimited: !deploymentResult.ok,
  };
}

function matchImportedRepositories(userId, projects) {
  const repositories = database.prepare(
    "SELECT github_repository FROM monitored_repositories WHERE user_id = ?",
  ).all(userId);
  const now = new Date().toISOString();
  const matches = [];
  for (const repository of repositories) {
    const fullName = repository.github_repository.toLowerCase();
    const name = fullName.split("/").at(-1);
    let project = projects.find(
      (item) => item.githubRepository?.toLowerCase() === fullName,
    );
    if (!project) {
      const sameName = projects.filter(
        (item) => item.githubRepository?.split("/").at(-1)?.toLowerCase() === name,
      );
      project = sameName.length === 1 ? sameName[0] : null;
    }
    if (!project) continue;
    database.prepare(`
      INSERT INTO tracked_projects
        (user_id, vercel_project_id, vercel_project_name, vercel_team_id, github_repository, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, vercel_project_id) DO UPDATE SET
        vercel_project_name=excluded.vercel_project_name,
        vercel_team_id=excluded.vercel_team_id,
        github_repository=excluded.github_repository,
        enabled=1, updated_at=excluded.updated_at
    `).run(userId, project.id, project.name, project.teamId, repository.github_repository, now, now);
    matches.push({ repository: repository.github_repository, project });
  }
  return matches;
}

function tokenExpiry(expiresIn) {
  return new Date(Date.now() + Number(expiresIn || 3600) * 1000).toISOString();
}

async function exchangeVercelToken(body) {
  const credentials = Buffer.from(
    `${config.vercelClientId}:${config.vercelClientSecret}`,
  ).toString("base64");
  return checkedFetch("https://api.vercel.com/login/oauth/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(body),
  });
}

async function vercelAccessToken(userId) {
  const item = connection(userId, "vercel");
  if (!item) throw new Error("Connect Vercel first");
  const expiresAt = item.token_expires_at ? new Date(item.token_expires_at).getTime() : 0;
  if (!item.refresh_token || expiresAt > Date.now() + 60_000) {
    return decryptSecret(item.access_token);
  }
  const tokens = await exchangeVercelToken({
    grant_type: "refresh_token",
    refresh_token: decryptSecret(item.refresh_token),
  });
  upsertConnection(
    userId,
    "vercel",
    tokens.access_token,
    item.account_id,
    item.account_name,
    JSON.parse(item.metadata || "{}"),
    tokens.refresh_token,
    tokenExpiry(tokens.expires_in),
  );
  return tokens.access_token;
}

integrationsRouter.get("/status", (request, response) => {
  const connections = database.prepare(
    "SELECT provider, account_id, account_name, metadata, updated_at FROM provider_connections WHERE user_id = ?",
  ).all(request.auth.sub);
  const projects = database.prepare(
    "SELECT * FROM tracked_projects WHERE user_id = ? ORDER BY created_at DESC",
  ).all(request.auth.sub);
  const repositories = database.prepare(
    "SELECT * FROM monitored_repositories WHERE user_id = ? ORDER BY created_at DESC",
  ).all(request.auth.sub);
  const vercelConnection = connections.find((item) => item.provider === "vercel");
  const vercelMetadata = vercelConnection
    ? JSON.parse(vercelConnection.metadata || "{}")
    : {};
  response.json({
    connections: connections.map((item) => ({ ...item, metadata: JSON.parse(item.metadata) })),
    projects,
    repositories,
    monitorActive: projects.some((project) => project.enabled === 1),
    vercelProjectAccessEnabled:
      vercelMetadata.auth_mode === "access_token" || projects.length > 0,
    vercelAuthorizationConfigured: Boolean(config.vercelClientId && config.vercelClientSecret),
  });
});

integrationsRouter.get("/github/repositories", async (request, response, next) => {
  try {
    const item = connection(request.auth.sub, "github");
    if (!item) return response.status(409).json({ error: "Connect GitHub first" });
    const repos = await checkedFetch(
      "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
      { headers: githubHeaders(decryptSecret(item.access_token)) },
    );
    const imported = new Set(database.prepare(
      "SELECT github_repository FROM monitored_repositories WHERE user_id = ?",
    ).all(request.auth.sub).map((row) => row.github_repository.toLowerCase()));
    const tracked = database.prepare(
      "SELECT * FROM tracked_projects WHERE user_id = ? AND enabled = 1",
    ).all(request.auth.sub);
    const projects = new Map(tracked.map((project) => [
      project.github_repository.toLowerCase(),
      {
        id: project.vercel_project_id,
        name: project.vercel_project_name,
        teamId: project.vercel_team_id,
      },
    ]));
    response.json({
      repositories: repos.map((repo) => repositoryShape(
        repo,
        imported.has(repo.full_name.toLowerCase()),
        projects.get(repo.full_name.toLowerCase()) || null,
      )),
    });
  } catch (error) {
    next(error);
  }
});

integrationsRouter.get("/vercel/start", (request, response) => {
  if (!config.vercelClientId || !config.vercelClientSecret) {
    return response.status(503).json({ error: "Vercel authorization is not configured" });
  }
  const state = crypto.randomBytes(24).toString("base64url");
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const nonce = crypto.randomBytes(24).toString("base64url");
  const now = new Date();
  database.prepare(`
    INSERT INTO oauth_states
      (state, user_id, provider, code_verifier, nonce, expires_at, created_at)
    VALUES (?, ?, 'vercel', ?, ?, ?, ?)
  `).run(
    state,
    request.auth.sub,
    verifier,
    nonce,
    new Date(now.getTime() + 10 * 60_000).toISOString(),
    now.toISOString(),
  );
  const params = new URLSearchParams({
    client_id: config.vercelClientId,
    redirect_uri: config.vercelCallbackUrl,
    response_type: "code",
    scope: config.vercelScopes,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  response.json({ url: `https://vercel.com/oauth/authorize?${params}` });
});

integrationsRouter.post("/vercel/token", async (request, response, next) => {
  try {
    const input = z.object({ accessToken: z.string().min(20) }).parse(request.body);
    const result = await optionalFetch("https://api.vercel.com/v2/user", {
      headers: vercelHeaders(input.accessToken),
    });
    if (!result.ok) {
      return response.status(401).json({ error: "Vercel access token is invalid" });
    }
    const user = result.payload.user || result.payload;
    upsertConnection(
      request.auth.sub,
      "vercel",
      input.accessToken,
      user.id || user.uid || "vercel-user",
      user.name || user.username || user.email || "Vercel account",
      { auth_mode: "access_token", email: user.email },
    );
    database.prepare(`
      UPDATE provider_connections
      SET refresh_token = NULL, token_expires_at = NULL, updated_at = ?
      WHERE user_id = ? AND provider = 'vercel'
    `).run(new Date().toISOString(), request.auth.sub);
    const discovery = await vercelProjectsForUser(request.auth.sub);
    const matches = matchImportedRepositories(request.auth.sub, discovery.projects);
    response.status(201).json({
      connected: true,
      accountName: user.name || user.username || "Vercel account",
      projects: discovery.projects.length,
      matches: matches.length,
    });
  } catch (error) {
    next(error);
  }
});

integrationsRouter.get("/vercel/callback", async (request, response, next) => {
  try {
    const state = database.prepare(
      "SELECT * FROM oauth_states WHERE state = ? AND provider = 'vercel'",
    ).get(request.query.state);
    database.prepare("DELETE FROM oauth_states WHERE state = ?").run(request.query.state);
    if (!state || new Date(state.expires_at) < new Date()) {
      throw new Error("Invalid or expired Vercel authorization state");
    }
    if (request.query.error) {
      const params = new URLSearchParams({
        integration: "vercel",
        status: "error",
        error: String(request.query.error_description || request.query.error),
      });
      return response.redirect(`${config.frontendUrl}/?${params}`);
    }
    if (!request.query.code) {
      throw new Error("Vercel did not return an authorization code");
    }
    const tokens = await exchangeVercelToken({
      grant_type: "authorization_code",
      code: String(request.query.code),
      redirect_uri: config.vercelCallbackUrl,
      code_verifier: state.code_verifier,
    });
    const profile = await checkedFetch("https://api.vercel.com/login/oauth/userinfo", {
      headers: vercelHeaders(tokens.access_token),
    });
    upsertConnection(
      state.user_id,
      "vercel",
      tokens.access_token,
      profile.sub,
      profile.name || profile.preferred_username || profile.email,
      { email: profile.email, scope: tokens.scope },
      tokens.refresh_token,
      tokenExpiry(tokens.expires_in),
    );
    try {
      const discovery = await vercelProjectsForUser(state.user_id);
      matchImportedRepositories(state.user_id, discovery.projects);
    } catch (error) {
      console.warn("Vercel connected, but existing repositories could not be matched:", error.message);
    }
    response.redirect(`${config.frontendUrl}/?integration=vercel&status=connected`);
  } catch (error) {
    next(error);
  }
});

integrationsRouter.get("/vercel/projects", async (request, response, next) => {
  try {
    const item = connection(request.auth.sub, "vercel");
    if (!item) return response.status(409).json({ error: "Connect Vercel first" });
    response.json(await vercelProjectsForUser(request.auth.sub));
  } catch (error) {
    next(error);
  }
});

integrationsRouter.post("/repositories/rematch", async (request, response, next) => {
  try {
    if (!connection(request.auth.sub, "vercel")) {
      return response.status(409).json({ error: "Connect Vercel first" });
    }
    const discovery = await vercelProjectsForUser(request.auth.sub);
    const matches = matchImportedRepositories(request.auth.sub, discovery.projects);
    response.json({ ...discovery, matches });
  } catch (error) {
    next(error);
  }
});

integrationsRouter.post("/repositories/import", async (request, response, next) => {
  try {
    const input = z.object({
      fullName: z.string().regex(/^[^/]+\/[^/]+$/),
      id: z.string().optional(),
      private: z.boolean().optional(),
      defaultBranch: z.string().optional(),
    }).parse(request.body);
    const github = connection(request.auth.sub, "github");
    if (!github) return response.status(409).json({ error: "Connect GitHub first" });
    const repo = await checkedFetch(`https://api.github.com/repos/${input.fullName}`, {
      headers: githubHeaders(decryptSecret(github.access_token)),
    });
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO monitored_repositories
        (user_id, github_repository, repository_id, private, default_branch, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, github_repository) DO UPDATE SET
        repository_id=excluded.repository_id, private=excluded.private,
        default_branch=excluded.default_branch, updated_at=excluded.updated_at
    `).run(
      request.auth.sub,
      repo.full_name,
      String(repo.id),
      repo.private ? 1 : 0,
      repo.default_branch,
      now,
      now,
    );

    let matchedProject = null;
    if (connection(request.auth.sub, "vercel")) {
      const discovery = await vercelProjectsForUser(request.auth.sub);
      matchedProject = discovery.projects.find(
        (project) => project.githubRepository?.toLowerCase() === repo.full_name.toLowerCase(),
      ) || null;
      if (!matchedProject) {
        const sameName = discovery.projects.filter(
          (project) => project.githubRepository?.split("/").at(-1)?.toLowerCase() === repo.name.toLowerCase(),
        );
        matchedProject = sameName.length === 1 ? sameName[0] : null;
      }
      if (matchedProject) {
        database.prepare(`
          INSERT INTO tracked_projects
            (user_id, vercel_project_id, vercel_project_name, vercel_team_id, github_repository, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(user_id, vercel_project_id) DO UPDATE SET
            vercel_project_name=excluded.vercel_project_name,
            vercel_team_id=excluded.vercel_team_id,
            github_repository=excluded.github_repository,
            enabled=1, updated_at=excluded.updated_at
        `).run(
          request.auth.sub,
          matchedProject.id,
          matchedProject.name,
          matchedProject.teamId,
          repo.full_name,
          now,
          now,
        );
      }
    }
    response.status(201).json({
      repository: repositoryShape(repo, true, matchedProject),
      matchedProject,
      requiresProjectMapping: Boolean(connection(request.auth.sub, "vercel") && !matchedProject),
    });
  } catch (error) {
    next(error);
  }
});

integrationsRouter.patch("/repositories/:owner/:repo/settings", (request, response) => {
  const input = z.object({
    pollIntervalSeconds: z.number().int().min(2).max(3600),
  }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.issues[0].message });
  const fullName = `${request.params.owner}/${request.params.repo}`;
  const result = database.prepare(`
    UPDATE monitored_repositories
    SET poll_interval_seconds = ?, updated_at = ?
    WHERE user_id = ? AND lower(github_repository) = lower(?)
  `).run(input.data.pollIntervalSeconds, new Date().toISOString(), request.auth.sub, fullName);
  if (!result.changes) return response.status(404).json({ error: "Imported repository not found" });
  response.json({ updated: true, pollIntervalSeconds: input.data.pollIntervalSeconds });
});

integrationsRouter.post("/render/connect", async (request, response, next) => {
  try {
    const input = z.object({ apiKey: z.string().min(20) }).parse(request.body);
    const result = await optionalFetch("https://api.render.com/v1/owners?limit=1", {
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${input.apiKey}`,
      },
    });
    if (!result.ok) return response.status(401).json({ error: "Render API key is invalid or lacks account access" });
    const owner = Array.isArray(result.payload) ? result.payload[0]?.owner || result.payload[0] : null;
    upsertConnection(
      request.auth.sub,
      "render",
      input.apiKey,
      owner?.id || "render-account",
      owner?.name || owner?.email || "Render account",
      {},
    );
    response.status(201).json({ connected: true, accountName: owner?.name || "Render account" });
  } catch (error) {
    next(error);
  }
});

integrationsRouter.delete("/connections/:provider", (request, response) => {
  if (!["vercel", "render"].includes(request.params.provider)) {
    return response.status(400).json({ error: "This provider cannot be disconnected here" });
  }
  database.prepare(
    "DELETE FROM provider_connections WHERE user_id = ? AND provider = ?",
  ).run(request.auth.sub, request.params.provider);
  response.status(204).end();
});

integrationsRouter.get("/repositories/:owner/:repo/activity", async (request, response, next) => {
  try {
    const fullName = `${request.params.owner}/${request.params.repo}`;
    const github = connection(request.auth.sub, "github");
    if (!github) return response.status(409).json({ error: "Connect GitHub first" });
    const githubToken = decryptSecret(github.access_token);
    const [repository, commits] = await Promise.all([
      checkedFetch(`https://api.github.com/repos/${fullName}`, { headers: githubHeaders(githubToken) }),
      checkedFetch(`https://api.github.com/repos/${fullName}/commits?per_page=12`, { headers: githubHeaders(githubToken) }),
    ]);
    const tracked = database.prepare(
      "SELECT * FROM tracked_projects WHERE user_id = ? AND lower(github_repository) = lower(?) AND enabled = 1",
    ).get(request.auth.sub, fullName);
    let deployments = [];
    let latestLogs = [];
    const workflows = database.prepare(`
      SELECT commit_sha, commit_message, commit_url, status, deployment_id,
             incident_id, pull_request_url, error, created_at, updated_at
      FROM commit_workflows
      WHERE user_id = ? AND lower(github_repository) = lower(?)
      ORDER BY created_at DESC
      LIMIT 20
    `).all(request.auth.sub, fullName);
    if (tracked && connection(request.auth.sub, "vercel")) {
      const token = await vercelAccessToken(request.auth.sub);
      const params = new URLSearchParams({ projectId: tracked.vercel_project_id, limit: "12" });
      if (tracked.vercel_team_id) params.set("teamId", tracked.vercel_team_id);
      const payload = await checkedFetch(`https://api.vercel.com/v6/deployments?${params}`, {
        headers: vercelHeaders(token),
      });
      deployments = (payload.deployments || []).map((deployment) => ({
        id: deployment.uid || deployment.id,
        name: deployment.name,
        state: deployment.readyState || deployment.state || deployment.status,
        url: deployment.url ? `https://${deployment.url}` : null,
        createdAt: deployment.createdAt ? new Date(deployment.createdAt).toISOString() : null,
        commitSha: deployment.meta?.githubCommitSha || deployment.meta?.gitCommitSha || null,
        commitMessage: deployment.meta?.githubCommitMessage || deployment.meta?.gitCommitMessage || null,
      }));
      const latest = deployments[0];
      if (latest?.id) {
        const eventParams = new URLSearchParams({
          builds: "1",
          direction: "backward",
          limit: "160",
        });
        if (tracked.vercel_team_id) eventParams.set("teamId", tracked.vercel_team_id);
        const events = await checkedFetch(
          `https://api.vercel.com/v3/deployments/${latest.id}/events?${eventParams}`,
          { headers: vercelHeaders(token) },
        );
        const rows = Array.isArray(events) ? events : events.events || [];
        latestLogs = rows.map((event) => ({
          id: String(event.id || event.created || crypto.randomUUID()),
          createdAt: event.created ? new Date(event.created).toISOString() : null,
          level: event.type || event.payload?.level || "info",
          text: event.text || event.message || event.payload?.text || event.payload?.message || "",
        })).filter((event) => event.text).reverse().slice(-120);
      }
    }
    response.json({
      repository: repositoryShape(repository, true, tracked ? {
        id: tracked.vercel_project_id,
        name: tracked.vercel_project_name,
        teamId: tracked.vercel_team_id,
      } : null),
      commits: commits.map((commit) => ({
        sha: commit.sha,
        message: commit.commit?.message?.split("\n")[0] || "Commit",
        author: commit.author?.login || commit.commit?.author?.name || "Unknown",
        avatar: commit.author?.avatar_url || null,
        createdAt: commit.commit?.author?.date || null,
        url: commit.html_url,
      })),
      deployments,
      latestLogs,
      workflows,
    });
  } catch (error) {
    next(error);
  }
});

integrationsRouter.post("/tracked-projects", (request, response) => {
  const input = z.object({
    vercelProjectId: z.string().min(1),
    vercelProjectName: z.string().min(1),
    vercelTeamId: z.string().nullable().optional(),
    githubRepository: z.string().regex(/^[^/]+\/[^/]+$/),
  }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.issues[0].message });
  const now = new Date().toISOString();
  database.prepare(`
    INSERT INTO tracked_projects
      (user_id, vercel_project_id, vercel_project_name, vercel_team_id, github_repository, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, vercel_project_id) DO UPDATE SET
      vercel_project_name=excluded.vercel_project_name, vercel_team_id=excluded.vercel_team_id,
      github_repository=excluded.github_repository, enabled=1, updated_at=excluded.updated_at
  `).run(request.auth.sub, input.data.vercelProjectId, input.data.vercelProjectName, input.data.vercelTeamId || null, input.data.githubRepository, now, now);
  response.status(201).json({ tracked: true });
});

integrationsRouter.delete("/tracked-projects/:id", (request, response) => {
  database.prepare("DELETE FROM tracked_projects WHERE id = ? AND user_id = ?").run(request.params.id, request.auth.sub);
  response.status(204).end();
});

integrationsRouter.get("/runtime", async (request, response, next) => {
  try {
  const github = connection(request.auth.sub, "github");
  const vercel = connection(request.auth.sub, "vercel");
  const projects = database.prepare("SELECT * FROM tracked_projects WHERE user_id = ? AND enabled = 1").all(request.auth.sub);
  response.json({
    githubToken: github ? decryptSecret(github.access_token) : null,
    vercelToken: vercel ? await vercelAccessToken(request.auth.sub) : null,
    projects,
  });
  } catch (error) {
    next(error);
  }
});
