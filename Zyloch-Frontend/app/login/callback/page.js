import { Suspense } from "react";
import OAuthCallback from "../components/OAuthCallbackClient";
export default function OAuthCallbackPage() {
  return (
    <Suspense fallback={<div>Loading authentication...</div>}>
      <OAuthCallback />
    </Suspense>
  );
}
