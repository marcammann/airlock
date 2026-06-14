export type WorkloadIdentity = {
  spiffeId?: string;
  namespace?: string;
  serviceAccount?: string;
};

export type WorkloadEgressSummary = {
  name: string;
  scheme: string;
  host: string;
  port?: number;
  rewriteCount: number;
};

export type PolicySummary = {
  name: string;
  namespace?: string;
  version: string;
  egress: WorkloadEgressSummary[];
  egressCount: number;
  rewriteCount: number;
  source: string;
  managedBy: string;
};

export type WorkloadSummary = {
  name: string;
  namespace?: string;
  version: string;
  workload: WorkloadIdentity;
  policyRefs?: {
    name: string;
    namespace?: string;
  }[];
  egress: WorkloadEgressSummary[];
  egressCount: number;
  rewriteCount: number;
  secretProvider?: {
    provider: string;
  };
  source: string;
  managedBy: string;
  status: string;
  instanceCount: number;
  activeInstances: number;
  lastHeartbeatAt?: string;
  lastDecisionAt?: string;
  decisions?: {
    allowed: number;
    denied: number;
    proxyError: number;
  };
  alerts?: {
    denied: number;
    proxyError: number;
    total: number;
  };
  instances: ProxyInstanceStatus[];
};

export type PoliciesResponse = {
  policies: PolicySummary[];
  source: string;
};

export type WorkloadsResponse = {
  workloads: WorkloadSummary[];
  source: string;
};

export type ProxyInstanceStatus = {
  id: string;
  proxyType?: string;
  policyFetched: boolean;
  heartbeatInterval: string;
  podNamespace?: string;
  podName?: string;
  status: string;
  lastPolicyFetchAt?: string;
  lastHeartbeatAt?: string;
  lastDecisionAt?: string;
  decisions?: {
    allowed: number;
    denied: number;
    proxyError: number;
  };
};

export type ProxyStatus = {
  id: string;
  workloadIdentity: string;
  workloadName?: string;
  effectivePolicyVersion?: string;
  proxyType?: string;
  status: string;
  instanceCount: number;
  activeInstances: number;
  lastPolicyFetchAt?: string;
  lastHeartbeatAt?: string;
  lastDecisionAt?: string;
  decisions?: {
    allowed: number;
    denied: number;
    proxyError: number;
  };
  instances: ProxyInstanceStatus[];
};

export type ProxyEvent = {
  id: string;
  observedAt: string;
  type:
    | "egress.denied"
    | "proxy.error"
    | "policy.fetch_failed"
    | "secret.resolve_failed"
    | "control_plane.auth_failed"
    | "event.suppressed";
  severity: "warning" | "error";
  message: string;
  count: number;
  firstObservedAt?: string;
  lastObservedAt?: string;
  proxyId: string;
  proxyType?: string;
  workloadIdentity: string;
  workloadName?: string;
  workloadNamespace?: string;
  effectivePolicyVersion?: string;
  sourcePolicyName?: string;
  sourcePolicyNamespace?: string;
  destination?: {
    scheme?: string;
    host: string;
    port?: number;
  };
  reason?: string;
  attributes?: Record<string, string>;
};

export type AdminEventsResponse = {
  events: ProxyEvent[];
  nextCursor?: string;
  source: string;
  suppressed?: {
    proxyId: string;
    count: number;
  }[];
};

export type ProxiesResponse = {
  proxies: ProxyStatus[];
  source: string;
  controlPlane: string;
};

type Result<T> = { ok: true; data: T } | { ok: false; error: string };

const defaultControlPlaneURL = "http://127.0.0.1:8080";

export function workloadKey(workload: WorkloadSummary): string {
  const raw = workload.workload.spiffeId || workload.name;
  return Buffer.from(raw, "utf8").toString("base64url");
}

export function policyKey(policy: PolicySummary): string {
  return Buffer.from(
    `${policy.namespace || ""}/${policy.name}`,
    "utf8",
  ).toString("base64url");
}

export function proxyKey(proxy: ProxyStatus): string {
  return Buffer.from(proxy.id, "utf8").toString("base64url");
}

export function workloadIdentityFromKey(key: string): string | null {
  try {
    return Buffer.from(key, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

export function policyIdentityFromKey(key: string): string | null {
  try {
    return Buffer.from(key, "base64url").toString("utf8");
  } catch {
    return null;
  }
}

export function proxyIdFromKey(key: string): string | null {
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

export async function getWorkloadByKey(
  key: string,
): Promise<Result<{ workload: WorkloadSummary; source: string }>> {
  const identity = workloadIdentityFromKey(key);
  if (!identity) {
    return { ok: false, error: "Invalid workload key" };
  }

  const result = await listWorkloads();
  if (!result.ok) {
    return result;
  }

  const workload = result.data.workloads.find(
    (candidate) =>
      candidate.workload.spiffeId === identity ||
      (!candidate.workload.spiffeId && candidate.name === identity),
  );
  if (!workload) {
    return { ok: false, error: "Workload not found" };
  }

  return { ok: true, data: { workload, source: result.data.source } };
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
    (candidate) => `${candidate.namespace || ""}/${candidate.name}` === identity,
  );
  if (!policy) {
    return { ok: false, error: "Policy not found" };
  }

  return { ok: true, data: { policy, source: result.data.source } };
}

export async function getProxyByKey(
  key: string,
  cursor?: string,
): Promise<
  Result<{
    proxy: ProxyStatus;
    source: string;
    controlPlane: string;
    events: ProxyEvent[];
    eventSource: string;
    nextEventCursor?: string;
  }>
> {
  const id = proxyIdFromKey(key);
  if (!id) {
    return { ok: false, error: "Invalid proxy key" };
  }

  const result = await listProxies();
  if (!result.ok) {
    return result;
  }

  const proxy = result.data.proxies.find((candidate) => candidate.id === id);
  if (!proxy) {
    return { ok: false, error: "Proxy not found" };
  }
  const instanceIds = new Set(proxy.instances.map((instance) => instance.id));
  const eventResult = await listEvents({
    proxyId: proxy.instances.length === 1 ? proxy.instances[0].id : undefined,
    cursor,
    limit: 100,
  });
  if (!eventResult.ok) {
    return eventResult;
  }
  const events =
    proxy.instances.length === 1
      ? eventResult.data.events
      : eventResult.data.events
          .filter((event) => instanceIds.has(event.proxyId))
          .slice(0, 25);

  return {
    ok: true,
    data: {
      proxy,
      source: result.data.source,
      controlPlane: result.data.controlPlane,
      events,
      eventSource: eventResult.data.source,
      nextEventCursor: eventResult.data.nextCursor,
    },
  };
}

export async function listPolicies(): Promise<Result<PoliciesResponse>> {
  return fetchControlPlane<PoliciesResponse>("/v1/admin/policies", (body) => ({
    policies: Array.isArray(body.policies)
      ? (body.policies as PolicySummary[])
      : [],
    source: controlPlaneBaseURL(),
  }));
}

export async function listWorkloads(): Promise<Result<WorkloadsResponse>> {
  return fetchControlPlane<WorkloadsResponse>("/v1/admin/workloads", (body) => ({
    workloads: Array.isArray(body.workloads)
      ? (body.workloads as WorkloadSummary[])
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

export async function listEvents({
  proxyId,
  cursor,
  limit,
  type,
  severity,
}: {
  proxyId?: string;
  cursor?: string;
  limit?: number;
  type?: ProxyEvent["type"];
  severity?: ProxyEvent["severity"];
} = {}): Promise<Result<AdminEventsResponse>> {
  const params = new URLSearchParams();
  if (proxyId) {
    params.set("proxy_id", proxyId);
  }
  if (cursor) {
    params.set("cursor", cursor);
  }
  if (limit) {
    params.set("limit", `${limit}`);
  }
  if (type) {
    params.set("type", type);
  }
  if (severity) {
    params.set("severity", severity);
  }
  const suffix = params.size > 0 ? `?${params}` : "";
  return fetchControlPlane<AdminEventsResponse>(
    `/v1/admin/events${suffix}`,
    (body) => ({
      events: Array.isArray(body.events)
        ? (body.events as ProxyEvent[])
        : [],
      nextCursor:
        typeof body.nextCursor === "string" ? body.nextCursor : undefined,
      source: typeof body.source === "string" ? body.source : "unknown",
      suppressed: Array.isArray(body.suppressed)
        ? (body.suppressed as AdminEventsResponse["suppressed"])
        : undefined,
    }),
  );
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
