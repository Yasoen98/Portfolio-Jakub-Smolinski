import Link from "next/link";
import { redirect } from "next/navigation";
import { getSessionFromRequest } from "@/lib/auth";
import { RegisterForm } from "@/components/forms/register-form";

export default async function RegisterPage() {
  const session = await getSessionFromRequest();
  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-8 px-4">
      <div>
        <h1 className="text-3xl font-semibold text-slate-900">Załóż konto VoxBook</h1>
        <p className="mt-2 text-slate-500">
          Masz już konto? <Link href="/login" className="text-indigo-600">Zaloguj się</Link>
        </p>
      </div>
      <RegisterForm />
    </main>
  );
}
