"use client";

import ProtectedLayout from "@/components/ProtectedLayout";

export default function HomeLayout({ children }) {
  return <ProtectedLayout>{children}</ProtectedLayout>;
}
