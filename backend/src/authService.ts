import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { hash, verify } from "@node-rs/argon2";

export type UserRole = "administrator" | "operator" | "viewer";

export interface UserRecord {
  id: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  mustChangePassword: boolean;
  createdAt: string;
  updatedAt: string;
  lastLoginAt: string | null;
  disabled: boolean;
}

export interface SessionRecord {
  id: string;
  userId: string;
  csrfToken: string;
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
}

const dataDir = process.env.DRM_DATA_DIR ?? "/data";
const usersPath = `${dataDir}/users.json`;
const sessionsPath = `${dataDir}/sessions.json`;
const sessionTtlMs = Number(process.env.SESSION_TTL_MS ?? 8 * 60 * 60 * 1000);

const argonOptions = {
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

async function loadJson<T>(path: string, fallback: T): Promise<T> {
  try { return JSON.parse(await readFile(path, "utf8")) as T; }
  catch { return fallback; }
}

async function saveJson(path: string, value: unknown) {
  await mkdir(dataDir, { recursive: true });
  await writeFile(path, JSON.stringify(value, null, 2), { mode: 0o600 });
}

function publicUser(user: UserRecord) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    mustChangePassword: user.mustChangePassword,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    lastLoginAt: user.lastLoginAt,
    disabled: user.disabled,
  };
}

function validateUsername(username: string) {
  if (!/^[A-Za-z0-9._-]{3,32}$/.test(username)) {
    throw new Error("Username must be 3-32 characters: letters, digits, dot, underscore or dash");
  }
}

export function validatePassword(password: string) {
  if (password.length < 8) throw new Error("Password must contain at least 8 characters");
  if (password.length > 256) throw new Error("Password is too long");
}

async function ensureBootstrapAdmin() {
  await mkdir(dataDir, { recursive: true });
  const users = await loadJson<UserRecord[]>(usersPath, []);
  if (users.length) return;
  const now = new Date().toISOString();
  const admin: UserRecord = {
    id: randomUUID(),
    username: "admin",
    passwordHash: await hash("admin", argonOptions),
    role: "administrator",
    mustChangePassword: true,
    createdAt: now,
    updatedAt: now,
    lastLoginAt: null,
    disabled: false,
  };
  await saveJson(usersPath, [admin]);
}

export async function initializeAuth() {
  await ensureBootstrapAdmin();
  await cleanupSessions();
}

async function getUsersRaw() {
  await ensureBootstrapAdmin();
  return loadJson<UserRecord[]>(usersPath, []);
}

async function getSessionsRaw() {
  return loadJson<SessionRecord[]>(sessionsPath, []);
}

async function cleanupSessions() {
  const now = Date.now();
  const sessions = (await getSessionsRaw()).filter(s => new Date(s.expiresAt).getTime() > now);
  await saveJson(sessionsPath, sessions);
}

export async function authenticate(username: string, password: string) {
  const users = await getUsersRaw();
  const user = users.find(u => u.username.toLowerCase() === username.trim().toLowerCase());
  // Do one Argon2 verification even for an unknown user to reduce username timing differences.
  if (!user) {
    const dummy = await hash("dummy-password-for-timing", argonOptions);
    await verify(dummy, password).catch(() => false);
    throw new Error("Invalid username or password");
  }
  if (user.disabled) throw new Error("Account is disabled");
  if (!(await verify(user.passwordHash, password))) throw new Error("Invalid username or password");

  user.lastLoginAt = new Date().toISOString();
  user.updatedAt = new Date().toISOString();
  await saveJson(usersPath, users);

  const session = await createSession(user.id);
  return { user: publicUser(user), session };
}

export async function createSession(userId: string) {
  const sessions = (await getSessionsRaw()).filter(s => new Date(s.expiresAt).getTime() > Date.now());
  const now = Date.now();
  const session: SessionRecord = {
    id: randomBytes(32).toString("base64url"),
    userId,
    csrfToken: randomBytes(24).toString("base64url"),
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + sessionTtlMs).toISOString(),
    lastSeenAt: new Date(now).toISOString(),
  };
  sessions.push(session);
  await saveJson(sessionsPath, sessions);
  return session;
}

export async function getSession(sessionId: string | undefined) {
  if (!sessionId) return null;
  const sessions = await getSessionsRaw();
  const session = sessions.find(s => s.id === sessionId);
  if (!session || new Date(session.expiresAt).getTime() <= Date.now()) return null;
  const users = await getUsersRaw();
  const user = users.find(u => u.id === session.userId && !u.disabled);
  if (!user) return null;
  session.lastSeenAt = new Date().toISOString();
  await saveJson(sessionsPath, sessions);
  return { session, user, publicUser: publicUser(user) };
}

export async function destroySession(sessionId: string | undefined) {
  if (!sessionId) return;
  const sessions = (await getSessionsRaw()).filter(s => s.id !== sessionId);
  await saveJson(sessionsPath, sessions);
}

export function secureCompare(a: string, b: string) {
  const ab = Buffer.from(a); const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export async function listUsers() {
  return (await getUsersRaw()).map(publicUser).sort((a,b)=>a.username.localeCompare(b.username));
}

export async function createUser(input: {username:string; password:string; role:UserRole}) {
  const username = input.username.trim();
  validateUsername(username); validatePassword(input.password);
  if (!["administrator","operator","viewer"].includes(input.role)) throw new Error("Invalid role");
  const users = await getUsersRaw();
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) throw new Error("Username already exists");
  const now = new Date().toISOString();
  const user: UserRecord = {
    id: randomUUID(), username, passwordHash: await hash(input.password, argonOptions), role: input.role,
    mustChangePassword: true, createdAt: now, updatedAt: now, lastLoginAt: null, disabled: false,
  };
  users.push(user); await saveJson(usersPath, users); return publicUser(user);
}

export async function changeOwnPassword(userId:string, currentPassword:string, newPassword:string, keepSessionId?:string) {
  validatePassword(newPassword);
  const users = await getUsersRaw();
  const user = users.find(u => u.id === userId); if (!user) throw new Error("User not found");
  if (!(await verify(user.passwordHash, currentPassword))) throw new Error("Current password is incorrect");
  if (await verify(user.passwordHash, newPassword)) throw new Error("New password must be different");
  user.passwordHash = await hash(newPassword, argonOptions);
  user.mustChangePassword = false; user.updatedAt = new Date().toISOString();
  await saveJson(usersPath, users);
  // Revoke every other session after password change.
  const sessions = (await getSessionsRaw()).filter(s => s.userId !== userId || s.id === keepSessionId);
  await saveJson(sessionsPath, sessions);
  return publicUser(user);
}

export async function adminResetPassword(actorId:string, targetId:string, newPassword:string) {
  validatePassword(newPassword);
  const users = await getUsersRaw();
  const actor = users.find(u=>u.id===actorId); const target=users.find(u=>u.id===targetId);
  if (!actor || actor.role!=="administrator") throw new Error("Administrator permission required");
  if (!target) throw new Error("User not found");
  target.passwordHash=await hash(newPassword,argonOptions); target.mustChangePassword=true; target.updatedAt=new Date().toISOString();
  await saveJson(usersPath,users);
  const sessions=(await getSessionsRaw()).filter(s=>s.userId!==targetId); await saveJson(sessionsPath,sessions);
  return publicUser(target);
}

export async function updateUserRole(actorId:string,targetId:string,role:UserRole) {
  if (!["administrator","operator","viewer"].includes(role)) throw new Error("Invalid role");
  const users=await getUsersRaw(); const actor=users.find(u=>u.id===actorId); const target=users.find(u=>u.id===targetId);
  if (!actor || actor.role!=="administrator") throw new Error("Administrator permission required");
  if (!target) throw new Error("User not found");
  if (target.username==="admin" && role!=="administrator") throw new Error("Built-in admin role cannot be changed");
  if (target.role==="administrator" && role!=="administrator") {
    const admins=users.filter(u=>u.role==="administrator"&&!u.disabled);
    if (admins.length<=1) throw new Error("Cannot remove the last administrator");
  }
  target.role=role; target.updatedAt=new Date().toISOString(); await saveJson(usersPath,users); return publicUser(target);
}

export async function deleteUser(actorId:string,targetId:string) {
  const users=await getUsersRaw(); const actor=users.find(u=>u.id===actorId); const target=users.find(u=>u.id===targetId);
  if (!actor || actor.role!=="administrator") throw new Error("Administrator permission required");
  if (!target) throw new Error("User not found");
  if (target.username==="admin") throw new Error("Built-in admin cannot be deleted");
  if (target.id===actorId) throw new Error("You cannot delete your own account");
  if (target.role==="administrator") {
    const admins=users.filter(u=>u.role==="administrator"&&!u.disabled);
    if (admins.length<=1) throw new Error("Cannot delete the last administrator");
  }
  await saveJson(usersPath,users.filter(u=>u.id!==targetId));
  await saveJson(sessionsPath,(await getSessionsRaw()).filter(s=>s.userId!==targetId));
}
