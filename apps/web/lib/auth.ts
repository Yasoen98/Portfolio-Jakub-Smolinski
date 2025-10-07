import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";
import { cookies, headers } from "next/headers";
import { NextRequest } from "next/server";
import { prisma } from "@db";

const SESSION_COOKIE = "voxbook_session";
const JWT_ALG = "HS256";

function getSecretKey(): Uint8Array {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("JWT_SECRET is not configured");
  }
  return new TextEncoder().encode(secret);
}

export async function hashPassword(password: string) {
  return bcrypt.hash(password, 10);
}

export async function verifyPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}

export interface SessionPayload {
  sub: string;
  email: string;
}

export async function createSessionToken(payload: SessionPayload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: JWT_ALG })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(getSecretKey());
}

export async function verifySessionToken(token: string) {
  const { payload } = await jwtVerify(token, getSecretKey());
  return payload as SessionPayload;
}

export async function setSessionCookie(token: string) {
  const cookieStore = cookies();
  cookieStore.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  });
}

export function clearSessionCookie() {
  const cookieStore = cookies();
  cookieStore.delete(SESSION_COOKIE);
}

export async function getSessionFromRequest(request?: NextRequest) {
  const cookieStore = request ? request.cookies : cookies();
  const token = cookieStore.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  try {
    return await verifySessionToken(token);
  } catch (error) {
    console.error("Invalid session token", error);
    return null;
  }
}

export async function requireUser() {
  const session = await getSessionFromRequest();
  if (!session) return null;
  return prisma.user.findUnique({ where: { id: session.sub } });
}

export async function getAuthHeaders() {
  const requestHeaders = headers();
  return {
    authorization: requestHeaders.get("authorization")
  };
}
