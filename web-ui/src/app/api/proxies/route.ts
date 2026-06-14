import { NextResponse } from "next/server";
import { listProxies } from "@/lib/airlock";
import { requireApiPermission } from "@/lib/auth";

export async function GET() {
  const denied = await requireApiPermission("admin:read");
  if (denied) {
    return denied;
  }

  const result = await listProxies();
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: 502 });
  }
  return NextResponse.json(result.data);
}
