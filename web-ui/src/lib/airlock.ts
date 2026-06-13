export type WorkloadIdentity = {
  spiffeId?: string;
  namespace?: string;
  serviceAccount?: string;
};

export type PolicyEgressSummary = {
  name: string;
  scheme: string;
  host: string;
  port?: number;
  rewriteCount: number;
};

export type PolicySummary = {
  name: string;
  version: string;
  workload: WorkloadIdentity;
  egress: PolicyEgressSummary[];
  egressCount: number;
  rewriteCount: number;
  secretProvider?: {
    provider: string;
  };
  source: string;
  managedBy: string;
};

export type PoliciesResponse = {
  policies: PolicySummary[];
  source: string;
};

export type ProxyStatus = {
  id: string;
  workloadIdentity: string;
  policyName?: string;
  policyVersion?: string;
  proxyType?: string;
  podNamespace?: string;
  podName?: string;
  status: string;
  lastPolicyFetchAt?: string;
  lastHeartbeatAt?: string;
};

export type ProxiesResponse = {
  proxies: ProxyStatus[];
  source: string;
  controlPlane: string;
};

type Result<T> = { ok: true; data: T } | { ok: false; error: string };

const defaultControlPlaneURL = "http://127.0.0.1:8080";

export function policyKey(policy: PolicySummary): string {
  const raw = policy.workload.spiffeId || policy.name;
  return Buffer.from(raw, "utf8").toString("base64url");
}

export function policyIdentityFromKey(key: string): string | null {
  try {
    return Buffer.from(key, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

export function destinationLabel(destination: {
  scheme: string;
  host: string;
  port?: number;
}) {
  return `${destination.scheme}://${destination.host}${
    destination.port ? `:${destination.port}` : ""
  }`;
}

export async function getPolicyByKey(
  key: string,
): Promise<Result<{ policy: PolicySummary; source: string }>> {
  const identity = policyIdentityFromKey(key);
  if (!identity) {
    return { ok: false, error: "Invalid policy key" };
  }

  const result = await listPolicies();
  if (!result.ok) {
    return result;
  }

  const policy = result.data.policies.find(
    (candidate) =>
      candidate.workload.spiffeId === identity ||
      (!candidate.workload.spiffeId && candidate.name === identity),
  );
  if (!policy) {
    return { ok: false, error: "Policy not found" };
  }

  return { ok: true, data: { policy, source: result.data.source } };
}

export async function listPolicies(): Promise<Result<PoliciesResponse>> {
  return fetchControlPlane<PoliciesResponse>("/v1/admin/policies", (body) => ({
    policies: Array.isArray(body.policies)
      ? (body.policies as PolicySummary[])
      : [],
    source: controlPlaneBaseURL(),
  }));
}

export async function listProxies(): Promise<Result<ProxiesResponse>> {
  return fetchControlPlane<ProxiesResponse>("/v1/admin/proxies", (body) => ({
    proxies: Array.isArray(body.proxies) ? (body.proxies as ProxyStatus[]) : [],
    source: typeof body.source === "string" ? body.source : "unknown",
    controlPlane: controlPlaneBaseURL(),
  }));
}

function controlPlaneBaseURL() {
  return (
    process.env.AIRLOCK_CONTROL_PLANE_URL?.replace(/\/+$/, "") ??
    defaultControlPlaneURL
  );
}

async function fetchControlPlane<T>(
  path: string,
  parse: (body: Record<string, unknown>) => T,
): Promise<Result<T>> {
  const baseURL =
    process.env.AIRLOCK_CONTROL_PLANE_URL?.replace(/\/+$/, "") ??
    defaultControlPlaneURL;
  const token = process.env.AIRLOCK_CONTROL_PLANE_TOKEN;

  const headers: HeadersInit = {
    Accept: "application/json",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${baseURL}${path}`, {
      headers,
      cache: "no-store",
    });

    if (!response.ok) {
      return {
        ok: false,
        error: `Control plane returned ${response.status} ${response.statusText}`,
      };
    }

    const body = (await response.json()) as Record<string, unknown>;
    return {
      ok: true,
      data: parse(body),
    };
  } catch (error) {
    return {
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Unable to reach the Airlock control plane",
    };
  }
}
