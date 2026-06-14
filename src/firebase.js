import { existsSync, readFileSync } from "node:fs";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { config } from "./config.js";

function firebaseCredential() {
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
    "Firebase Admin credentials are not configured. Add service-account.json or Firebase environment variables.",
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
