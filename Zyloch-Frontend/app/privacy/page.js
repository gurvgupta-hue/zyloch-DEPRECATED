import fs from "fs";
import path from "path";
import LegalPage from "@/components/LegalPage";

export const metadata = {
  title: "Privacy Policy | Zyloch",
  description:
    "Read the Privacy Policy for Zyloch to understand how Secure Code LLC collects, uses, and safeguards personal data.",
};

export default function PrivacyPage() {
  const filePath = path.join(process.cwd(), "data", "privacy.mdx");
  const content = fs.readFileSync(filePath, "utf8");

  return <LegalPage content={content} type="privacy" />;
}
