import { redirect } from "next/navigation";
import { getSessionFromRequest } from "@/lib/auth";

export default async function HomePage() {
  const session = await getSessionFromRequest();
  if (session) {
    redirect("/dashboard");
  }
  redirect("/login");
}
