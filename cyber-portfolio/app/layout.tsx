import type { Metadata } from "next";
import { Inter, Space_Grotesk } from "next/font/google";
import "./globals.css";
import { siteConfig } from "@/lib/site-config";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space",
});

export const metadata: Metadata = {
  title: {
    default: `${siteConfig.name} — Portfolio`,
    template: `%s | ${siteConfig.name}`,
  },
  description: `${siteConfig.title}. ${siteConfig.intro}`,
  openGraph: {
    title: `${siteConfig.name} — Portfolio`,
    description: siteConfig.intro,
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${spaceGrotesk.variable}`}>
      <body className="font-sans min-h-screen cyber-scan">
        {children}
      </body>
    </html>
  );
}
