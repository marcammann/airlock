import type { Metadata } from "next";
import { ConsoleHeader } from "./console-header";
import "./globals.css";

export const metadata: Metadata = {
  title: "Airlock Console",
  description: "Read-only Airlock policy console",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col bg-background text-foreground">
        <ConsoleHeader />
        <div className="flex-1">{children}</div>
      </body>
    </html>
  );
}
