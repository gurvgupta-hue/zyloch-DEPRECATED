import fs from "fs";
import path from "path";
import LegalPage from "@/components/LegalPage";

export const metadata = {
  title: "Cookie Policy | Zyloch",
  description:
    "Learn about how Secure Code LLC uses cookies and similar tracking technologies across Zyloch services.",
};

export default function CookiesPage() {
  const filePath = path.join(process.cwd(), "data", "cookies.mdx");
  const content = fs.readFileSync(filePath, "utf8");

  return <LegalPage content={content} type="cookies" />;
}
