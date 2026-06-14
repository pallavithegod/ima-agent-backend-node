import jwt from "jsonwebtoken";
import { config } from "./config.js";

export function authenticate(request, response, next) {
  const token = request.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token) return response.status(401).json({ error: "Authentication required" });
  try {
    request.auth = jwt.verify(token, config.jwtSecret, {
      algorithms: ["HS256"],
      audience: "incident-memory-api",
      issuer: "incident-memory-auth",
    });
    next();
  } catch {
    response.status(401).json({ error: "Invalid or expired token" });
  }
}
