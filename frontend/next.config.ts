import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8400";
    const cguardApiUrl = process.env.CGUARD_API_URL || "http://localhost:8080";
    return [
      {
        source: "/cguard-api/:path*",
        destination: `${cguardApiUrl}/:path*`,
      },
      {
        source: "/api/:path*",
        destination: `${apiUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
