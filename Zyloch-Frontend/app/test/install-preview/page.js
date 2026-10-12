import React from "react";
import SecureCodeAgent from "@/app/home/install/SecureCodeAgent";

export default function InstallPreviewPage() {
    return (
        <div className="h-screen w-screen overflow-y-auto overflow-x-hidden bg-[var(--bg)]">
            <SecureCodeAgent />
        </div>
    );
}
