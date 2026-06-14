import Link from "next/link";
import { listWorkloads, workloadKey } from "@/lib/airlock";
import { requirePagePermission } from "@/lib/auth";
import type { ReactNode } from "react";

const accent = "#5200CC";

export default async function WorkloadsPage() {
  await requirePagePermission("admin:read");

  const result = await listWorkloads();

  if (!result.ok) {
    return (
      <main className="px-6 pb-12 pt-9 text-black sm:px-10 lg:px-[72px]">
        <Shell>
          <div className="border border-black/15 px-5 py-4 text-sm">
            {result.error}
          </div>
        </Shell>
      </main>
    );
  }

  const workloads = result.data.workloads;

  return (
    <main className="px-6 pb-12 pt-9 text-black sm:px-10 lg:px-[72px]">
      <Shell>
        <section className="border-t border-black/15">
          {workloads.length === 0 ? (
            <div className="border-b border-black/10 py-10 text-sm text-black/60">
              No workloads are currently loaded.
            </div>
          ) : (
            <table className="w-full border-separate border-spacing-0 text-left">
              <thead>
                <tr className="font-medium">
                  <TableHeader>Workload</TableHeader>
                  <TableHeader align="right">Policies</TableHeader>
                  <TableHeader align="right">Active</TableHeader>
                  <TableHeader align="right">Alerts</TableHeader>
                </tr>
              </thead>
              <tbody>
                {workloads.map((workload) => (
                  <tr key={`${workload.workload.spiffeId}:${workload.name}`}>
                    <td className="border-b border-black/10 py-[26px] pr-4 text-[16px] leading-none">
                      <Link
                        href={`/workloads/${workloadKey(workload)}`}
                        className="font-semi-mono font-medium underline underline-offset-2"
                        style={{ color: accent }}
                      >
                        {workload.name}
                      </Link>
                    </td>
                    <td className="border-b border-black/10 py-[26px] pl-4 text-right text-[16px] tabular-nums">
                      {(workload.policyRefs ?? []).length}
                    </td>
                    <td className="border-b border-black/10 py-[26px] pl-4 text-right text-[16px] tabular-nums">
                      {workload.activeInstances}
                    </td>
                    <td className="border-b border-black/10 py-[26px] pl-4 text-right text-[16px] tabular-nums">
                      {workload.alerts?.total ?? 0}
                    </td>
                  </tr>
                ))}
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
