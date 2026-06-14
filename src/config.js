import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const serviceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
dotenv.config({ path: resolve(serviceRoot, ".env") });

export const config = {
  environment: process.env.NODE_ENV || "development",
  port: Number(process.env.NODE_PORT || 4000),
  databasePath: resolve(serviceRoot, process.env.NODE_DATABASE_PATH || "./storage/auth.db"),
  jwtSecret: process.env.AUTH_JWT_SECRET || "development-only-secret-change-me",
  credentialKey: process.env.CREDENTIAL_ENCRYPTION_KEY || "",
  frontendUrl: process.env.FRONTEND_URL || "http://localhost:5173",
  pythonBackendUrl: process.env.PYTHON_BACKEND_URL || "http://localhost:8000",
  monitorIntervalMs: Number(process.env.MONITOR_INTERVAL_MS || 60_000),
  vercelClientId: process.env.VERCEL_CLIENT_ID || "",
  vercelClientSecret: process.env.VERCEL_CLIENT_SECRET || "",
  vercelCallbackUrl:
    process.env.VERCEL_CALLBACK_URL
    || "http://localhost:4000/api/integrations/vercel/callback",
  vercelScopes:
    process.env.VERCEL_SCOPES
    || "openid profile email offline_access",
  firebaseProjectId: process.env.FIREBASE_PROJECT_ID || "",
  firebaseClientEmail: process.env.FIREBASE_CLIENT_EMAIL || "",
  firebasePrivateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
  firebaseServiceAccountPath: resolve(
    serviceRoot,
    process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "./service-account.json",
  ),
  corsOrigins: (process.env.NODE_CORS_ORIGINS || "http://localhost:5173")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean),
};

if (
  config.environment === "production"
  && (config.jwtSecret.length < 32 || config.jwtSecret.includes("development-only"))
) {
  throw new Error("AUTH_JWT_SECRET must be at least 32 characters in production");
}

if (config.environment === "production" && config.credentialKey.length < 32) {
  throw new Error("CREDENTIAL_ENCRYPTION_KEY must be at least 32 characters in production");
}
