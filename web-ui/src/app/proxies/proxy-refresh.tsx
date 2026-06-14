"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

export function ProxyRefresh({ intervalMs }: { intervalMs: number }) {
  const router = useRouter();

  useEffect(() => {
    if (intervalMs <= 0) {
      return;
    }
    const timer = window.setInterval(() => {
      router.refresh();
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [intervalMs, router]);

  return null;
}
