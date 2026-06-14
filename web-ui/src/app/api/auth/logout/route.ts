import { logoutResponse } from "@/lib/auth";

export async function GET() {
  return logoutResponse();
}
