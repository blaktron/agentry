import { redirect } from "next/navigation";
import { SITE } from "@/lib/site";

// Documentation is a SEPARATE deployment (docs.secureagentry.net). This route
// stays only so existing /docs links resolve; it forwards to the docs site.
export const dynamic = "force-dynamic";

export default function DocsRedirect() {
  redirect(SITE.docsUrl);
}
