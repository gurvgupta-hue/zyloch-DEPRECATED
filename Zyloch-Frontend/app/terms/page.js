import fs from "fs";
import path from "path";
import LegalPage from "@/components/LegalPage";

export const metadata = {
  title: "Terms and Conditions | Zyloch",
  description:
    "Review the Terms and Conditions governing the use of Zyloch services and software platforms operated by Secure Code LLC.",
};

export default function TermsPage() {
  const filePath = path.join(process.cwd(), "data", "terms.mdx");
  const content = fs.readFileSync(filePath, "utf8");

  return <LegalPage content={content} type="terms" />;
}
