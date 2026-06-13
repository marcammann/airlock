import { NextResponse } from "next/server";
import { listProxies } from "@/lib/airlock";

export async function GET() {
  const result = await listProxies();
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: 502 });
  }
  return NextResponse.json(result.data);
}
