import { existsSync, readFileSync } from "node:fs";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { config } from "./config.js";

function firebaseCredential() {
  if (config.firebaseServiceAccountBase64) {
    try {
      const json = Buffer.from(config.firebaseServiceAccountBase64, "base64").toString("utf8");
      return cert(JSON.parse(json));
    } catch (error) {
      throw new Error(`FIREBASE_SERVICE_ACCOUNT_BASE64 is invalid: ${error.message}`);
    }
  }
  if (existsSync(config.firebaseServiceAccountPath)) {
    return cert(JSON.parse(readFileSync(config.firebaseServiceAccountPath, "utf8")));
  }
  if (config.firebaseProjectId && config.firebaseClientEmail && config.firebasePrivateKey) {
    return cert({
      projectId: config.firebaseProjectId,
      clientEmail: config.firebaseClientEmail,
      privateKey: config.firebasePrivateKey,
    });
  }
  throw new Error(
    "Firebase Admin credentials are not configured. Add FIREBASE_SERVICE_ACCOUNT_BASE64, service-account.json, or Firebase environment variables.",
  );
}

function firebaseApp() {
  if (getApps().length) return getApps()[0];
  return initializeApp({
    credential: firebaseCredential(),
  });
}

export function verifyFirebaseToken(token) {
  return getAuth(firebaseApp()).verifyIdToken(token, true);
}

function credentialDocument(ownerId, provider) {
  return getFirestore(firebaseApp())
    .collection("users")
    .doc(ownerId)
    .collection("providerCredentials")
    .doc(provider);
}

export async function saveEncryptedProviderCredential(ownerId, provider, credential) {
  await credentialDocument(ownerId, provider).set({
    ...credential,
    provider,
    encryption: "aes-256-gcm",
    version: 1,
  });
}

export async function loadEncryptedProviderCredentials(ownerId) {
  const snapshot = await getFirestore(firebaseApp())
    .collection("users")
    .doc(ownerId)
    .collection("providerCredentials")
    .get();
  return snapshot.docs.map((document) => ({
    provider: document.id,
    ...document.data(),
  }));
}

export async function deleteEncryptedProviderCredential(ownerId, provider) {
  await credentialDocument(ownerId, provider).delete();
}
