import crypto from "node:crypto";
import { decryptSecret, encryptSecret } from "./crypto.js";
import { database } from "./database.js";
import {
  deleteEncryptedProviderCredential,
  loadEncryptedProviderCredentials,
  saveEncryptedProviderCredential,
} from "./firebase.js";

const CLOUD_RETRY_DELAY_MS = 60_000;
let cloudUnavailableUntil = 0;
let lastCloudWarning = "";

function ownerId(user) {
  const identity = user.firebase_uid
    ? `firebase:${user.firebase_uid}`
    : `email:${String(user.email).toLowerCase()}`;
  return crypto.createHash("sha256").update(identity).digest("base64url");
}

function userById(userId) {
  return database.prepare("SELECT * FROM users WHERE id = ?").get(userId);
}

function warnCloudStore(error) {
  cloudUnavailableUntil = Date.now() + CLOUD_RETRY_DELAY_MS;
  const message = String(error.message || error).split("\n")[0];
  if (message !== lastCloudWarning) {
    console.warn(`Firebase credential store unavailable: ${message}`);
    lastCloudWarning = message;
  }
}

function cloudStoreAvailable() {
  return Date.now() >= cloudUnavailableUntil;
}

export function connection(userId, provider) {
  return database.prepare(
    "SELECT * FROM provider_connections WHERE user_id = ? AND provider = ?",
  ).get(userId, provider);
}

export async function upsertConnection(
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
  const encryptedAccessToken = encryptSecret(token);
  const encryptedRefreshToken = refreshToken ? encryptSecret(refreshToken) : null;
  database.prepare(`
    INSERT INTO provider_connections
      (user_id, provider, access_token, refresh_token, token_expires_at,
       account_id, account_name, metadata, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, provider) DO UPDATE SET
      access_token=excluded.access_token, refresh_token=excluded.refresh_token,
      token_expires_at=excluded.token_expires_at, account_id=excluded.account_id,
      account_name=excluded.account_name, metadata=excluded.metadata, updated_at=excluded.updated_at
  `).run(
    userId,
    provider,
    encryptedAccessToken,
    encryptedRefreshToken,
    tokenExpiresAt,
    accountId,
    accountName,
    JSON.stringify(metadata),
    now,
    now,
  );
  const user = userById(userId);
  if (!user) throw new Error("Credential owner was not found");
  if (!cloudStoreAvailable()) return false;
  try {
    await saveEncryptedProviderCredential(ownerId(user), provider, {
      accessToken: encryptedAccessToken,
      refreshToken: encryptedRefreshToken,
      tokenExpiresAt,
      accountId,
      accountName,
      metadata: JSON.stringify(metadata),
      createdAt: now,
      updatedAt: now,
    });
    return true;
  } catch (error) {
    warnCloudStore(error);
    return false;
  }
}

export async function syncProviderCredentials(userId) {
  const user = userById(userId);
  if (!user) return false;
  if (!cloudStoreAvailable()) return false;
  const owner = ownerId(user);
  let cloudCredentials;
  try {
    cloudCredentials = await loadEncryptedProviderCredentials(owner);
  } catch (error) {
    warnCloudStore(error);
    return false;
  }
  const cloudByProvider = new Map(cloudCredentials.map((item) => [item.provider, item]));
  const localCredentials = database.prepare(
    "SELECT * FROM provider_connections WHERE user_id = ?",
  ).all(userId);
  const localByProvider = new Map(localCredentials.map((item) => [item.provider, item]));

  for (const cloud of cloudCredentials) {
    const local = localByProvider.get(cloud.provider);
    if (local && new Date(local.updated_at) >= new Date(cloud.updatedAt || 0)) continue;
    try {
      decryptSecret(cloud.accessToken);
      if (cloud.refreshToken) decryptSecret(cloud.refreshToken);
    } catch {
      console.warn(`Ignored tampered or unreadable ${cloud.provider} cloud credential`);
      continue;
    }
    const now = new Date().toISOString();
    database.prepare(`
      INSERT INTO provider_connections
        (user_id, provider, access_token, refresh_token, token_expires_at,
         account_id, account_name, metadata, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, provider) DO UPDATE SET
        access_token=excluded.access_token, refresh_token=excluded.refresh_token,
        token_expires_at=excluded.token_expires_at, account_id=excluded.account_id,
        account_name=excluded.account_name, metadata=excluded.metadata,
        updated_at=excluded.updated_at
    `).run(
      userId,
      cloud.provider,
      cloud.accessToken,
      cloud.refreshToken || null,
      cloud.tokenExpiresAt || null,
      cloud.accountId || null,
      cloud.accountName || null,
      cloud.metadata || "{}",
      cloud.createdAt || now,
      cloud.updatedAt || now,
    );
  }

  for (const local of localCredentials) {
    const cloud = cloudByProvider.get(local.provider);
    if (cloud && new Date(cloud.updatedAt || 0) >= new Date(local.updated_at)) continue;
    try {
      await saveEncryptedProviderCredential(owner, local.provider, {
        accessToken: local.access_token,
        refreshToken: local.refresh_token || null,
        tokenExpiresAt: local.token_expires_at || null,
        accountId: local.account_id || null,
        accountName: local.account_name || null,
        metadata: local.metadata || "{}",
        createdAt: local.created_at,
        updatedAt: local.updated_at,
      });
    } catch (error) {
      warnCloudStore(error);
      return false;
    }
  }
  return true;
}

export async function deleteConnection(userId, provider) {
  const user = userById(userId);
  database.prepare(
    "DELETE FROM provider_connections WHERE user_id = ? AND provider = ?",
  ).run(userId, provider);
  if (user) {
    if (!cloudStoreAvailable()) return;
    try {
      await deleteEncryptedProviderCredential(ownerId(user), provider);
    } catch (error) {
      warnCloudStore(error);
    }
  }
}
