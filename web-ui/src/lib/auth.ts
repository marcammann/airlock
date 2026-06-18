import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
  webcrypto,
} from "node:crypto";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { NextRequest, NextResponse } from "next/server";

export type WebPermission = "admin:read";
export type WebRole = "admin" | "viewer";

export type WebSession = {
  sub: string;
  issuer: string;
  email?: string;
  name?: string;
  groups: string[];
  roles: WebRole[];
  iat: number;
  exp: number;
};

type AuthzResult =
  | { status: "allowed"; session: WebSession }
  | { status: "unauthenticated" }
  | { status: "forbidden"; session: WebSession }
  | { status: "misconfigured"; error: string };

type OIDCState = {
  state: string;
  nonce: string;
  codeVerifier: string;
  next: string;
  exp: number;
};

type OIDCConfig = {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksURI: string;
  clientID: string;
  clientSecret?: string;
  redirectURI: string;
  scopes: string;
};

type TokenResponse = {
  id_token?: string;
  error?: string;
  error_description?: string;
};

type JWKS = {
  keys?: OIDCJWK[];
};

type OIDCJWK = JsonWebKey & {
  kid?: string;
};

type JWTHeader = {
  alg?: string;
  kid?: string;
};

const sessionCookieName = "airlock_web_session";
const oidcStateCookieName = "airlock_oidc_state";
const defaultSessionMaxAgeSeconds = 8 * 60 * 60;
const oidcStateMaxAgeSeconds = 10 * 60;

class AuthConfigError extends Error {}

export async function requirePagePermission(permission: WebPermission) {
  const result = await authorize(permission);
  switch (result.status) {
    case "allowed":
      return result.session;
    case "forbidden":
      redirect("/forbidden");
    case "misconfigured":
      redirect("/login?error=configuration");
    case "unauthenticated":
      redirect("/login");
  }
}

export async function requireApiPermission(
  permission: WebPermission,
): Promise<NextResponse | null> {
  const result = await authorize(permission);
  switch (result.status) {
    case "allowed":
      return null;
    case "forbidden":
      return NextResponse.json({ error: "forbidden" }, { status: 403 });
    case "misconfigured":
      return NextResponse.json(
        { error: "web auth is not configured" },
        { status: 503 },
      );
    case "unauthenticated":
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
}

export async function getCurrentWebSession(): Promise<WebSession | null> {
  const cookieStore = await cookies();
  const raw = cookieStore.get(sessionCookieName)?.value;
  if (!raw) {
    return null;
  }
  const session = verifySignedJSON<WebSession>(raw);
  if (!isWebSession(session) || session.exp <= nowSeconds()) {
    return null;
  }
  return session;
}

export async function startLogin(request: NextRequest): Promise<NextResponse> {
  try {
    const next = safeNextPath(request.nextUrl.searchParams.get("next"));
    switch (webAuthMode()) {
      case "none":
        return localRedirect(next);
      case "oidc":
        return createOIDCLoginResponse(request, next);
      default:
        throw new AuthConfigError("unsupported AIRLOCK_WEB_AUTH_MODE");
    }
  } catch (error) {
    return loginErrorRedirect(error);
  }
}

export async function finishOIDCLogin(
  request: NextRequest,
): Promise<NextResponse> {
  try {
    if (webAuthMode() !== "oidc") {
      throw new AuthConfigError("OIDC callback requires AIRLOCK_WEB_AUTH_MODE=oidc");
    }
    const code = request.nextUrl.searchParams.get("code");
    const state = request.nextUrl.searchParams.get("state");
    if (!code || !state) {
      throw new Error("OIDC callback is missing code or state");
    }

    const cookieStore = await cookies();
    const oidcState = verifySignedJSON<OIDCState>(
      cookieStore.get(oidcStateCookieName)?.value,
    );
    if (
      !isOIDCState(oidcState) ||
      oidcState.exp <= nowSeconds() ||
      oidcState.state !== state
    ) {
      throw new Error("OIDC state is invalid or expired");
    }

    const config = await loadOIDCConfig(request);
    const tokenResponse = await exchangeAuthorizationCode(
      config,
      code,
      oidcState.codeVerifier,
    );
    if (!tokenResponse.id_token) {
      throw new Error(
        tokenResponse.error_description ||
          tokenResponse.error ||
          "OIDC token response did not include an id_token",
      );
    }

    const claims = await verifyIDToken(
      tokenResponse.id_token,
      config,
      oidcState.nonce,
    );
    const session = sessionFromClaims(config.issuer, config.clientID, claims);
    const response = localRedirect(oidcState.next);
    setSessionCookie(response, session);
    clearCookie(response, oidcStateCookieName);
    return response;
  } catch (error) {
    return loginErrorRedirect(error);
  }
}

export function logoutResponse(): NextResponse {
  const response = localRedirect("/login");
  clearCookie(response, sessionCookieName);
  clearCookie(response, oidcStateCookieName);
  return response;
}

async function createOIDCLoginResponse(
  request: NextRequest,
  next: string,
): Promise<NextResponse> {
  const config = await loadOIDCConfig(request);
  const state: OIDCState = {
    state: randomToken(),
    nonce: randomToken(),
    codeVerifier: randomToken(64),
    next,
    exp: nowSeconds() + oidcStateMaxAgeSeconds,
  };
  const codeChallenge = base64URL(
    createHash("sha256").update(state.codeVerifier).digest(),
  );
  const authorizeURL = new URL(config.authorizationEndpoint);
  authorizeURL.searchParams.set("client_id", config.clientID);
  authorizeURL.searchParams.set("redirect_uri", config.redirectURI);
  authorizeURL.searchParams.set("response_type", "code");
  authorizeURL.searchParams.set("scope", config.scopes);
  authorizeURL.searchParams.set("state", state.state);
  authorizeURL.searchParams.set("nonce", state.nonce);
  authorizeURL.searchParams.set("code_challenge", codeChallenge);
  authorizeURL.searchParams.set("code_challenge_method", "S256");

  const response = NextResponse.redirect(authorizeURL);
  response.cookies.set(
    oidcStateCookieName,
    signJSON(state),
    cookieOptions(oidcStateMaxAgeSeconds),
  );
  return response;
}

async function exchangeAuthorizationCode(
  config: OIDCConfig,
  code: string,
  codeVerifier: string,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectURI,
    client_id: config.clientID,
    code_verifier: codeVerifier,
  });
  if (config.clientSecret) {
    body.set("client_secret", config.clientSecret);
  }

  const response = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
    cache: "no-store",
  });
  const parsed = (await response.json()) as TokenResponse;
  if (!response.ok) {
    throw new Error(
      parsed.error_description ||
        parsed.error ||
        `OIDC token endpoint returned ${response.status}`,
    );
  }
  return parsed;
}

async function verifyIDToken(
  idToken: string,
  config: OIDCConfig,
  expectedNonce: string,
): Promise<Record<string, unknown>> {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("id_token is not a JWT");
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  const header = decodeJWTPart<JWTHeader>(headerPart);
  if (header.alg !== "RS256") {
    throw new Error(`unsupported id_token signing algorithm ${header.alg || ""}`);
  }

  const jwks = await fetchJSON<JWKS>(config.jwksURI);
  const key = jwks.keys?.find((candidate) => candidate.kid === header.kid);
  if (!key) {
    throw new Error("id_token signing key was not found in JWKS");
  }

  const cryptoKey = await webcrypto.subtle.importKey(
    "jwk",
    key,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const verified = await webcrypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    Buffer.from(signaturePart, "base64url"),
    Buffer.from(`${headerPart}.${payloadPart}`),
  );
  if (!verified) {
    throw new Error("id_token signature verification failed");
  }

  const claims = decodeJWTPart<Record<string, unknown>>(payloadPart);
  const issuer = stringClaim(claims.iss);
  if (!issuer || normalizeIssuer(issuer) !== config.issuer) {
    throw new Error("id_token issuer is not trusted");
  }
  if (!audienceIncludes(claims.aud, config.clientID)) {
    throw new Error("id_token audience does not match the WebUI client");
  }
  const exp = numberClaim(claims.exp);
  if (!exp || exp <= nowSeconds()) {
    throw new Error("id_token is expired");
  }
  const nonce = stringClaim(claims.nonce);
  if (nonce !== expectedNonce) {
    throw new Error("id_token nonce mismatch");
  }
  return claims;
}

function sessionFromClaims(
  issuer: string,
  clientID: string,
  claims: Record<string, unknown>,
): WebSession {
  const sub = stringClaim(claims.sub);
  if (!sub) {
    throw new Error("id_token is missing subject");
  }
  const email = stringClaim(claims.email);
  const groups = claimValues(claims, groupsClaimName());
  const directRoles = parseRoleList(claimValues(claims, rolesClaimName()).join(","));
  const roles = resolveRoles(email, groups, directRoles);
  if (roles.length === 0) {
    throw new Error("signed-in user is not authorized for Airlock WebUI");
  }

  const tokenExp = numberClaim(claims.exp) || nowSeconds() + sessionMaxAgeSeconds();
  return {
    sub,
    issuer,
    email,
    name: stringClaim(claims.name) || email,
    groups,
    roles,
    iat: nowSeconds(),
    exp: Math.min(tokenExp, nowSeconds() + sessionMaxAgeSeconds()),
  };
}

async function authorize(permission: WebPermission): Promise<AuthzResult> {
  try {
    if (webAuthMode() === "none") {
      return { status: "allowed", session: noneModeSession() };
    }
    const session = await getCurrentWebSession();
    if (!session) {
      return { status: "unauthenticated" };
    }
    if (!session.roles.some((role) => roleAllows(role, permission))) {
      return { status: "forbidden", session };
    }
    return { status: "allowed", session };
  } catch (error) {
    if (error instanceof AuthConfigError) {
      return { status: "misconfigured", error: error.message };
    }
    return { status: "unauthenticated" };
  }
}

function noneModeSession(): WebSession {
  const now = nowSeconds();
  return {
    sub: "anonymous",
    issuer: "airlock-web-none",
    groups: [],
    roles: ["admin"],
    iat: now,
    exp: now + sessionMaxAgeSeconds(),
  };
}

function roleAllows(role: WebRole, permission: WebPermission) {
  switch (permission) {
    case "admin:read":
      return role === "admin" || role === "viewer";
  }
}

function resolveRoles(
  email: string | undefined,
  groups: string[],
  directRoles: WebRole[],
): WebRole[] {
  const roles = new Set<WebRole>(directRoles);
  const normalizedEmail = email?.toLowerCase();
  const emailDomain = normalizedEmail?.split("@")[1];

  if (normalizedEmail && parseStringList(env("AIRLOCK_WEB_ADMIN_EMAILS")).includes(normalizedEmail)) {
    roles.add("admin");
  }
  if (normalizedEmail && parseStringList(env("AIRLOCK_WEB_VIEWER_EMAILS")).includes(normalizedEmail)) {
    roles.add("viewer");
  }
  if (emailDomain && parseStringList(env("AIRLOCK_WEB_ALLOWED_DOMAINS")).includes(emailDomain)) {
    roles.add("viewer");
  }

  const adminGroups = new Set(parseStringList(env("AIRLOCK_WEB_ADMIN_GROUPS")));
  const viewerGroups = new Set(parseStringList(env("AIRLOCK_WEB_VIEWER_GROUPS")));
  for (const group of groups) {
    if (adminGroups.has(group)) {
      roles.add("admin");
    }
    if (viewerGroups.has(group)) {
      roles.add("viewer");
    }
  }

  if (roles.size === 0 && !accessRulesConfigured()) {
    roles.add("viewer");
  }
  return [...roles];
}

function accessRulesConfigured() {
  return [
    "AIRLOCK_WEB_ADMIN_EMAILS",
    "AIRLOCK_WEB_VIEWER_EMAILS",
    "AIRLOCK_WEB_ALLOWED_DOMAINS",
    "AIRLOCK_WEB_ADMIN_GROUPS",
    "AIRLOCK_WEB_VIEWER_GROUPS",
  ].some((name) => parseStringList(env(name)).length > 0);
}

async function loadOIDCConfig(request: NextRequest): Promise<OIDCConfig> {
  const issuer = normalizeIssuer(requiredEnv("AIRLOCK_WEB_OIDC_ISSUER"));
  const discovery = await fetchJSON<Record<string, unknown>>(
    `${issuer}/.well-known/openid-configuration`,
  );
  const discoveredIssuer = stringClaim(discovery.issuer);
  if (discoveredIssuer && normalizeIssuer(discoveredIssuer) !== issuer) {
    throw new AuthConfigError("OIDC discovery issuer does not match configuration");
  }

  return {
    issuer,
    authorizationEndpoint: requiredString(
      discovery.authorization_endpoint,
      "OIDC discovery is missing authorization_endpoint",
    ),
    tokenEndpoint: requiredString(
      discovery.token_endpoint,
      "OIDC discovery is missing token_endpoint",
    ),
    jwksURI: requiredString(discovery.jwks_uri, "OIDC discovery is missing jwks_uri"),
    clientID: requiredEnv("AIRLOCK_WEB_OIDC_CLIENT_ID"),
    clientSecret: env("AIRLOCK_WEB_OIDC_CLIENT_SECRET"),
    redirectURI:
      env("AIRLOCK_WEB_OIDC_REDIRECT_URI") ||
      new URL("/api/auth/callback", request.nextUrl.origin).toString(),
    scopes: env("AIRLOCK_WEB_OIDC_SCOPES") || "openid email profile",
  };
}

async function fetchJSON<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new AuthConfigError(`OIDC metadata request returned ${response.status}`);
  }
  return (await response.json()) as T;
}

function setSessionCookie(response: NextResponse, session: WebSession) {
  response.cookies.set(
    sessionCookieName,
    signJSON(session),
    cookieOptions(session.exp - nowSeconds()),
  );
}

function clearCookie(response: NextResponse, name: string) {
  response.cookies.set(name, "", { ...cookieOptions(0), maxAge: 0 });
}

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: cookieSecure(),
    path: "/",
    maxAge: Math.max(0, maxAge),
  };
}

function cookieSecure() {
  const configured = env("AIRLOCK_WEB_COOKIE_SECURE");
  if (configured) {
    return ["1", "true", "yes", "on"].includes(configured.toLowerCase());
  }
  return process.env.NODE_ENV === "production";
}

function signJSON(value: unknown) {
  const payload = base64URL(Buffer.from(JSON.stringify(value), "utf8"));
  const signature = base64URL(
    createHmac("sha256", sessionSecret()).update(payload).digest(),
  );
  return `${payload}.${signature}`;
}

function verifySignedJSON<T>(value: string | undefined): T | null {
  if (!value) {
    return null;
  }
  const [payload, signature] = value.split(".");
  if (!payload || !signature) {
    return null;
  }
  const expected = base64URL(
    createHmac("sha256", sessionSecret()).update(payload).digest(),
  );
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(signature);
  if (
    expectedBuffer.length !== actualBuffer.length ||
    !timingSafeEqual(expectedBuffer, actualBuffer)
  ) {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}

function sessionSecret() {
  const secret = env("AIRLOCK_WEB_SESSION_SECRET");
  if (secret) {
    return secret;
  }
  throw new AuthConfigError("AIRLOCK_WEB_SESSION_SECRET is required");
}

function sessionMaxAgeSeconds() {
  const configured = Number(env("AIRLOCK_WEB_SESSION_MAX_AGE_SECONDS"));
  return Number.isFinite(configured) && configured > 0
    ? configured
    : defaultSessionMaxAgeSeconds;
}

function loginErrorRedirect(error: unknown) {
  const target = new URLSearchParams({
    error: error instanceof AuthConfigError ? "configuration" : "login_failed",
  });
  return localRedirect(`/login?${target}`);
}

function localRedirect(path: string) {
  return new NextResponse(null, {
    status: 303,
    headers: {
      Location: path,
    },
  });
}

function webAuthMode() {
  return (env("AIRLOCK_WEB_AUTH_MODE") || "oidc").toLowerCase();
}

function groupsClaimName() {
  return env("AIRLOCK_WEB_RBAC_GROUPS_CLAIM") || "groups";
}

function rolesClaimName() {
  return env("AIRLOCK_WEB_RBAC_ROLES_CLAIM") || "roles";
}

function env(name: string) {
  return process.env[name]?.trim();
}

function requiredEnv(name: string) {
  const value = env(name);
  if (!value) {
    throw new AuthConfigError(`${name} is required`);
  }
  return value;
}

function requiredString(value: unknown, message: string) {
  const out = stringClaim(value);
  if (!out) {
    throw new AuthConfigError(message);
  }
  return out;
}

function safeNextPath(raw: string | null) {
  if (raw && raw.startsWith("/") && !raw.startsWith("//")) {
    return raw;
  }
  return "/";
}

function randomToken(bytes = 32) {
  return base64URL(randomBytes(bytes));
}

function base64URL(value: Buffer) {
  return value.toString("base64url");
}

function decodeJWTPart<T>(value: string): T {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as T;
}

function normalizeIssuer(value: string) {
  return value.replace(/\/+$/, "");
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function stringClaim(value: unknown) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

function numberClaim(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function claimValues(claims: Record<string, unknown>, name: string) {
  return parseUnknownStringList(claims[name]);
}

function parseUnknownStringList(value: unknown) {
  if (Array.isArray(value)) {
    return value
      .filter((entry): entry is string => typeof entry === "string")
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  if (typeof value === "string") {
    return parseStringList(value);
  }
  return [];
}

function parseStringList(value: string | undefined) {
  return (value || "")
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseRoleList(value: string | undefined) {
  return parseStringList(value).filter((role): role is WebRole =>
    role === "admin" || role === "viewer",
  );
}

function audienceIncludes(audience: unknown, expected: string) {
  if (typeof audience === "string") {
    return audience === expected;
  }
  if (Array.isArray(audience)) {
    return audience.includes(expected);
  }
  return false;
}

function isWebSession(value: unknown): value is WebSession {
  if (!value || typeof value !== "object") {
    return false;
  }
  const session = value as Partial<WebSession>;
  return (
    typeof session.sub === "string" &&
    typeof session.issuer === "string" &&
    Array.isArray(session.groups) &&
    Array.isArray(session.roles) &&
    session.roles.every((role) => role === "admin" || role === "viewer") &&
    typeof session.iat === "number" &&
    typeof session.exp === "number"
  );
}

function isOIDCState(value: unknown): value is OIDCState {
  if (!value || typeof value !== "object") {
    return false;
  }
  const state = value as Partial<OIDCState>;
  return (
    typeof state.state === "string" &&
    typeof state.nonce === "string" &&
    typeof state.codeVerifier === "string" &&
    typeof state.next === "string" &&
    typeof state.exp === "number"
  );
}
