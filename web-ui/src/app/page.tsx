import Link from "next/link";
import { listPolicies, listWorkloads, policyKey } from "@/lib/airlock";
import { requirePagePermission } from "@/lib/auth";
import type { ReactNode } from "react";

const accent = "#5200CC";

export default async function Home() {
  await requirePagePermission("admin:read");

  const [policiesResult, workloadsResult] = await Promise.all([
    listPolicies(),
    listWorkloads(),
  ]);

  if (!policiesResult.ok || !workloadsResult.ok) {
    const error = !policiesResult.ok
      ? policiesResult.error
      : !workloadsResult.ok
        ? workloadsResult.error
        : "Unable to load admin data";

    return (
      <main className="px-6 pb-12 pt-9 text-black sm:px-10 lg:px-[72px]">
        <Shell>
          <div className="border border-black/15 px-5 py-4 text-sm">
            {error}
          </div>
        </Shell>
      </main>
    );
  }

  const policies = policiesResult.data.policies;
  const workloads = workloadsResult.data.workloads;
  const workloadCountByPolicy = new Map<string, number>();
  for (const workload of workloads) {
    for (const ref of workload.policyRefs ?? []) {
      const key = policyRefKey(ref.namespace || workload.namespace, ref.name);
      workloadCountByPolicy.set(key, (workloadCountByPolicy.get(key) ?? 0) + 1);
    }
  }

  return (
    <main className="px-6 pb-12 pt-9 text-black sm:px-10 lg:px-[72px]">
      <Shell>
        <section className="border-t border-black/15">
          {policies.length === 0 ? (
            <div className="border-b border-black/10 py-10 text-sm text-black/60">
              No policies are currently loaded.
            </div>
          ) : (
            <table className="w-full border-separate border-spacing-0 text-left">
              <thead>
                <tr className="font-medium">
                  <TableHeader>Policy</TableHeader>
                  <TableHeader align="right">Rules</TableHeader>
                  <TableHeader align="right">Workloads</TableHeader>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => {
                  const workloadCount =
                    workloadCountByPolicy.get(
                      policyRefKey(policy.namespace, policy.name),
                    ) ?? 0;

                  return (
                    <tr key={`${policy.namespace}:${policy.name}`}>
                      <td className="border-b border-black/10 py-[26px] pr-4 text-[16px] leading-none">
                        <Link
                          href={`/policies/${policyKey(policy)}`}
                          className="font-semi-mono font-medium underline underline-offset-2"
                          style={{ color: accent }}
                        >
                          {policy.name}
                        </Link>
                      </td>
                      <td className="border-b border-black/10 py-[26px] pl-4 text-right text-[16px] tabular-nums">
                        {policy.egressCount}
                      </td>
                      <td className="border-b border-black/10 py-[26px] pl-4 text-right text-[16px] tabular-nums">
                        {workloadCount}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      </Shell>
    </main>
  );
}

function Shell({ children }: { children: ReactNode }) {
  return <section className="mx-auto max-w-[1358px]">{children}</section>;
}

function TableHeader({
  children,
  align = "left",
}: {
  children: ReactNode;
  align?: "left" | "right";
}) {
  return (
    <th
      className={`pt-10 pb-0 text-[14px] font-medium ${align === "right" ? "text-right" : "text-left"}`}
    >
      {children}
    </th>
  );
}

function policyRefKey(namespace: string | undefined, name: string) {
  return `${namespace || ""}/${name}`;
}
