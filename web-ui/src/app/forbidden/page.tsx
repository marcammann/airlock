import Link from "next/link";
import { getCurrentWebSession } from "@/lib/auth";

const accent = "#5200CC";

export default async function ForbiddenPage() {
  const session = await getSession();

  return (
    <main className="min-h-screen bg-[#b8b8b8] px-6 py-12 text-black sm:px-10 lg:px-[72px]">
      <section className="mx-auto max-w-[620px]">
        <p className="brand-semi-mono leading-none">
          <span className="font-medium" style={{ color: accent }}>
            AIRLOCK
          </span>{" "}
          <span className="font-light" style={{ color: accent }}>
            Console
          </span>
        </p>

        <div className="mt-10 border-t border-black/15 pt-8">
          <h1 className="text-[22px] font-medium leading-none">Access denied</h1>
          <p className="mt-5 text-sm leading-6 text-black/65">
            Your WebUI session does not include a role that can read Airlock
            admin data.
          </p>
          {session ? (
            <p className="mt-5 text-sm text-black/65">
              Signed in as {session.email || session.sub}.
            </p>
          ) : null}
          <div className="mt-8 flex gap-4">
            <a
              href="/api/auth/logout"
              className="inline-flex border border-black px-4 py-2 text-sm font-medium"
            >
              Sign out
            </a>
            <Link
              href="/login"
              className="inline-flex border border-black/30 px-4 py-2 text-sm font-medium text-black/70"
            >
              Sign in
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}

async function getSession() {
  try {
    return await getCurrentWebSession();
  } catch {
    return null;
  }
}
