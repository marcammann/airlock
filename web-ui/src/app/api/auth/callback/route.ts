import { finishOIDCLogin } from "@/lib/auth";
import type { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  return finishOIDCLogin(request);
}
