"use client";

export const dynamic = "force-dynamic"; // Ensures dynamic rendering in Next.js App Router

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { checkUserInstallation } from "@/lib/api/github";

export default function OAuthCallback() {
  const [status, setStatus] = useState("Initializing authentication...");
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const processOAuth = async () => {
      try {
        const error = searchParams.get("error");

        // ?? Case 1: OAuth error returned from GitHub or backend
        if (error) {
          console.error("OAuth Error:", error);
          setStatus(`Error: ${error}`);
          router.push(`/login?error=${encodeURIComponent(error)}`);
          return;
        }

        // ?? Case 2: OAuth success (cookie already set by backend)
        setStatus("Authentication successful. Validating installation...");

        try {
          // ?? Step 1: Check GitHub installation status
          const hasInstallation = await checkUserInstallation();

          // ?? Step 2: Conditional redirection
          if (hasInstallation) {
            setStatus("Redirecting to dashboard...");
            router.push("/dashboard");
          } else {
            setStatus("No installations found. Redirecting to setup...");
            router.push("/home");
          }
        } catch (installationError) {
          // If GitHub installation check fails (e.g., non-GitHub login), redirect to home
          setStatus("Redirecting to home...");
          router.push("/home");
        }
      } catch (err) {
        console.error("OAuth processing error:", err);
        setStatus(`Error: ${err.message || "Unexpected error"}`);
        router.push("/login?error=OAuth+Processing+Failed");
      }
    };

    processOAuth();
  }, [searchParams, router]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center p-6">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
        <p className="text-gray-700 font-medium mb-2">{status}</p>
        <p className="text-sm text-muted-foreground">
          Finalizing authentication & environment sync...
        </p>
      </div>
    </div>
  );
}
