"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/workloads", label: "Workloads", active: (path: string) => path.startsWith("/workloads") },
  { href: "/", label: "Policies", active: (path: string) => path === "/" || path.startsWith("/policies") },
];

export function ConsoleHeader() {
  const pathname = usePathname();

  if (pathname === "/login" || pathname === "/forbidden") {
    return null;
  }

  return (
    <header className="px-6 pt-12 text-black sm:px-10 lg:px-[72px]">
      <section className="mx-auto max-w-[1358px]">
        <Link href="/" className="brand-semi-mono inline-flex leading-none">
          <span className="font-medium" style={{ color: "var(--accent)" }}>
            AIRLOCK
          </span>
          <span className="ml-1 font-light" style={{ color: "var(--accent)" }}>
            Console
          </span>
        </Link>
        <nav className="mt-5 flex items-baseline gap-12">
          {navItems.map((item) => {
            const active = item.active(pathname);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={
                  active
                    ? "text-[22px] font-medium leading-none text-black"
                    : "text-[22px] font-light leading-none text-black/50 hover:text-black"
                }
              >
                {item.label}
              </Link>
            );
          })}
        </nav>
      </section>
    </header>
  );
}
