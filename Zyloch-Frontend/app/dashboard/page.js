import React from "react";
import Repo from "./components/Repo";

export const metadata = {
  title: "Dashboard",
  description: "Your Zyloch security dashboard — monitor findings, repository health, and CI/CD pipeline status.",
  robots: { index: false, follow: false },
};
const Page = () => {
  return <Repo />;
};

export default Page;