import cors from "cors";
import express from "express";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import { rateLimit } from "express-rate-limit";
import { z } from "zod";
import { config } from "./config.js";
import { database, safeUser } from "./database.js";
import { hashPassword, verifyPassword } from "./password.js";
import { integrationsRouter } from "./integrations.js";
import { authenticate } from "./auth.js";
import { verifyFirebaseToken } from "./firebase.js";
import { syncProviderCredentials, upsertConnection } from "./providerCredentials.js";

const credentialsSchema = z.object({
  email: z.string().email().transform((value) => value.toLowerCase()),
  password: z.string().min(8).max(128),
});

const registerSchema = credentialsSchema.extend({
  name: z.string().min(2).max(80),
});

export function issueToken(user) {
  return jwt.sign(
    { sub: String(user.id), email: user.email, name: user.name, role: user.role },
    config.jwtSecret,
    {
      algorithm: "HS256",
      expiresIn: "12h",
      audience: "incident-memory-api",
      issuer: "incident-memory-auth",
    },
  );
}

export const app = express();
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || config.corsOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed"));
  },
  credentials: true,
}));
app.use(express.json({ limit: "32kb" }));
app.use("/api/auth", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-8",
  legacyHeaders: false,
}));

app.get("/health", (_request, response) => {
  response.json({ status: "ok" });
});

app.post("/api/auth/register", (request, response) => {
  const parsed = registerSchema.safeParse(request.body);
  if (!parsed.success) {
    return response.status(400).json({ error: parsed.error.issues[0].message });
  }
  const { name, email, password } = parsed.data;
  const existing = database.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return response.status(409).json({ error: "Email is already registered" });

  const result = database
    .prepare(
      "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .run(name, email, hashPassword(password), "engineer", new Date().toISOString());
  const user = database.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
  response.status(201).json({ token: issueToken(user), user: safeUser(user) });
});

app.post("/api/auth/login", async (request, response, next) => {
  try {
    const parsed = credentialsSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: parsed.error.issues[0].message });
    }
    const user = database.prepare("SELECT * FROM users WHERE email = ?").get(parsed.data.email);
    if (!user || !verifyPassword(parsed.data.password, user.password_hash)) {
      return response.status(401).json({ error: "Incorrect email or password" });
    }
    await syncProviderCredentials(user.id);
    response.json({ token: issueToken(user), user: safeUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/firebase", async (request, response, next) => {
  try {
    const parsed = z.object({
      idToken: z.string().min(20),
      githubAccessToken: z.string().min(10),
    }).parse(request.body);
    const identity = await verifyFirebaseToken(parsed.idToken);
    if (!identity.email) return response.status(400).json({ error: "GitHub must provide an email address" });
    const now = new Date().toISOString();
    const name = identity.name || identity.email.split("@")[0];
    database.prepare(`
      INSERT INTO users (name, email, firebase_uid, password_hash, role, created_at)
      VALUES (?, ?, ?, 'firebase-managed', 'engineer', ?)
      ON CONFLICT(email) DO UPDATE SET
        name=excluded.name, firebase_uid=excluded.firebase_uid
    `).run(name, identity.email.toLowerCase(), identity.uid, now);
    const user = database.prepare("SELECT * FROM users WHERE email = ?").get(identity.email.toLowerCase());
    await syncProviderCredentials(user.id);
    await upsertConnection(
      user.id,
      "github",
      parsed.githubAccessToken,
      identity.firebase?.identities?.["github.com"]?.[0] || identity.uid,
      name,
      {},
    );
    response.json({ token: issueToken(user), user: safeUser(user) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", authenticate, (request, response) => {
  const user = database.prepare("SELECT * FROM users WHERE id = ?").get(request.auth.sub);
  if (!user) return response.status(404).json({ error: "User not found" });
  response.json({ user: safeUser(user) });
});

app.use("/api/integrations", integrationsRouter);

app.use((error, _request, response, _next) => {
  console.error(error);
  response.status(500).json({ error: "Authentication service error" });
});
