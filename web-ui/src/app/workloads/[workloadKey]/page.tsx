import { notFound } from "next/navigation";
import { destinationLabel, getWorkloadByKey } from "@/lib/airlock";
import { requirePagePermission } from "@/lib/auth";
import type { ReactNode } from "react";

type WorkloadDetailPageProps = {
  params: Promise<{
    workloadKey: string;
  }>;
};

export default async function WorkloadDetailPage({
  params,
}: WorkloadDetailPageProps) {
  await requirePagePermission("admin:read");

  const { workloadKey } = await params;
  const result = await getWorkloadByKey(workloadKey);

  if (!result.ok) {
    if (
      result.error === "Workload not found" ||
      result.error === "Invalid workload key"
    ) {
      notFound();
    }
    return (
      <main className="px-6 pb-12 pt-9 text-slate-950 sm:px-8 lg:px-[72px]">
        <section className="mx-auto max-w-6xl">
          <div className="border border-rose-200 bg-rose-50 px-5 py-4 text-sm text-rose-950">
            {result.error}
          </div>
        </section>
      </main>
    );
  }

  const { workload, source } = result.data;

  return (
    <main className="px-6 pb-12 pt-9 text-slate-950 sm:px-8 lg:px-[72px]">
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <header className="border-b border-slate-200 pb-6">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-sm font-semibold uppercase tracking-wide text-teal-700">
                Workload
              </p>
              <h1 className="mt-2 text-3xl font-semibold">{workload.name}</h1>
              <p className="mt-2 font-mono text-xs text-slate-500">
                {workload.workload.spiffeId || "unassigned"}
              </p>
            </div>
            <div className="grid grid-cols-3 gap-3 text-sm">
              <Metric label="Egress" value={workload.egressCount} />
              <Metric label="Rewrites" value={workload.rewriteCount} />
              <Metric label="Version" value={workload.version} />
            </div>
          </div>
        </header>

        <section className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
          <div className="overflow-hidden border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-4 py-3">
              <h2 className="text-sm font-semibold text-slate-800">
                Effective egress
              </h2>
            </div>
            {workload.egress.length === 0 ? (
              <div className="px-4 py-10 text-sm text-slate-500">
                No egress destinations are allowed.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <TableHeader>Name</TableHeader>
                      <TableHeader>Destination</TableHeader>
                      <TableHeader>Rewrites</TableHeader>
                    </tr>
                  </thead>
                  <tbody>
                    {workload.egress.map((egress) => (
                      <tr key={egress.name}>
                        <td className="border-t border-slate-100 px-4 py-4 align-top font-medium text-slate-950">
                          {egress.name}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-700">
                          {destinationLabel(egress)}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top tabular-nums">
                          {egress.rewriteCount}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="overflow-hidden border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-4 py-3">
              <h2 className="text-sm font-semibold text-slate-800">
                Instances
              </h2>
            </div>
            {workload.instances.length === 0 ? (
              <div className="px-4 py-10 text-sm text-slate-500">
                No proxy instances have reported heartbeats.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <TableHeader>Instance</TableHeader>
                      <TableHeader>Mode</TableHeader>
                      <TableHeader>Pod</TableHeader>
                      <TableHeader>Heartbeat</TableHeader>
                      <TableHeader>Decisions</TableHeader>
                      <TableHeader>Status</TableHeader>
                    </tr>
                  </thead>
                  <tbody>
                    {workload.instances.map((instance) => (
                      <tr key={instance.id}>
                        <td className="border-t border-slate-100 px-4 py-4 align-top font-mono text-xs text-slate-800">
                          {instance.id}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top">
                          {instance.proxyType || "-"}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top">
                          {[instance.podNamespace, instance.podName]
                            .filter(Boolean)
                            .join("/") || "-"}
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top">
                          <div>{formatDate(instance.lastHeartbeatAt)}</div>
                          <div className="mt-1 text-xs text-slate-500">
                            {instance.heartbeatInterval || "-"}
                          </div>
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top">
                          <DecisionCounts decisions={instance.decisions} />
                        </td>
                        <td className="border-t border-slate-100 px-4 py-4 align-top">
                          <span className="inline-flex border border-slate-200 bg-slate-50 px-2 py-1 text-xs text-slate-700">
                            {instance.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <aside className="flex flex-col gap-4">
            <InfoPanel title="Identity">
              <InfoRow label="Namespace" value={workload.workload.namespace || "-"} />
              <InfoRow
                label="Service account"
                value={workload.workload.serviceAccount || "-"}
              />
              <InfoRow label="SPIFFE ID" value={workload.workload.spiffeId || "-"} mono />
            </InfoPanel>

            <InfoPanel title="Management">
              <InfoRow label="Status" value={workload.status} />
              <InfoRow
                label="Instances"
                value={`${workload.activeInstances}/${workload.instanceCount}`}
              />
              <InfoRow label="Managed by" value={workload.managedBy} />
              <InfoRow label="Source" value={workload.source} />
              <InfoRow label="Control plane" value={source} mono />
            </InfoPanel>

            <InfoPanel title="Secrets">
              <InfoRow
                label="Provider"
                value={workload.secretProvider?.provider || "none"}
              />
              <InfoRow label="Rewrite metadata" value="redacted" />
            </InfoPanel>
          </aside>
        </section>
      </section>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-24 border border-slate-200 bg-white px-4 py-3">
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
    </div>
  );
}

function DecisionCounts({
  decisions,
}: {
  decisions?: {
    allowed: number;
    denied: number;
    proxyError: number;
  };
}) {
  const counts = decisions ?? { allowed: 0, denied: 0, proxyError: 0 };
  return (
    <div className="grid gap-1 text-xs text-slate-600">
      <div>
        <span className="font-medium text-emerald-700 tabular-nums">
          {counts.allowed}
        </span>{" "}
        allowed
      </div>
      <div>
        <span className="font-medium text-rose-700 tabular-nums">
          {counts.denied}
        </span>{" "}
        denied
      </div>
      <div>
        <span className="font-medium text-amber-700 tabular-nums">
          {counts.proxyError}
        </span>{" "}
        proxy error
      </div>
    </div>
  );
}

function formatDate(value?: string) {
  if (!value) {
    return "-";
  }
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function InfoPanel({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-800">{title}</h2>
      </div>
      <div className="divide-y divide-slate-100">{children}</div>
    </section>
  );
}

function InfoRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid gap-1 px-4 py-3 text-sm">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div
        className={
          mono
            ? "break-all font-mono text-xs text-slate-800"
            : "break-words text-slate-900"
        }
      >
        {value}
      </div>
    </div>
  );
}

function TableHeader({ children }: { children: ReactNode }) {
  return (
    <th className="border-b border-slate-200 px-4 py-3 font-semibold">
      {children}
    </th>
  );
}
