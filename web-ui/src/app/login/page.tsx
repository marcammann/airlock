import Link from "next/link";
import { getCurrentWebSession } from "@/lib/auth";

const accent = "#5200CC";

type LoginPageProps = {
  searchParams: Promise<{
    error?: string;
    next?: string;
  }>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const params = await searchParams;
  const session = await getSession();
  const next = safeNext(params.next);
  const loginHref = `/api/auth/login?next=${encodeURIComponent(next)}`;

  return (
    <main className="min-h-screen bg-[#b8b8b8] px-6 py-12 text-black sm:px-10 lg:px-[72px]">
      <section className="mx-auto max-w-[520px]">
        <p className="brand-semi-mono leading-none">
          <span className="font-medium" style={{ color: accent }}>
            AIRLOCK
          </span>{" "}
          <span className="font-light" style={{ color: accent }}>
            Console
          </span>
        </p>

        <div className="mt-10 border-t border-black/15 pt-8">
          <h1 className="text-[22px] font-medium leading-none">Sign in</h1>
          <p className="mt-5 text-sm leading-6 text-black/65">
            Use your configured WebUI identity provider to access Airlock admin
            data.
          </p>

          {params.error ? (
            <div className="mt-6 border border-black/15 px-4 py-3 text-sm text-black">
              {errorMessage(params.error)}
            </div>
          ) : null}

          {session ? (
            <div className="mt-8 grid gap-4">
              <div className="text-sm text-black/65">
                Signed in as {session.email || session.sub}.
              </div>
              <Link
                href={next}
                className="inline-flex w-fit border border-black px-4 py-2 text-sm font-medium"
              >
                Continue
              </Link>
            </div>
          ) : (
            <a
              href={loginHref}
              className="mt-8 inline-flex border border-black px-4 py-2 text-sm font-medium"
            >
              Sign in
            </a>
          )}
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

function safeNext(raw: string | undefined) {
  if (raw && raw.startsWith("/") && !raw.startsWith("//")) {
    return raw;
  }
  return "/";
}

function errorMessage(error: string) {
  if (error === "configuration") {
    return "WebUI authentication is not configured.";
  }
  return "The sign-in attempt failed.";
}
