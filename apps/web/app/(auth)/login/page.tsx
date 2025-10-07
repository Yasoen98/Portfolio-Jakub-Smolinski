import Link from "next/link";
import { redirect } from "next/navigation";
import { getSessionFromRequest } from "@/lib/auth";
import { LoginForm } from "@/components/forms/login-form";

export default async function LoginPage() {
  const session = await getSessionFromRequest();
  if (session) {
    redirect("/dashboard");
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-8 px-4">
      <div>
        <h1 className="text-3xl font-semibold text-slate-900">Zaloguj się do VoxBook</h1>
        <p className="mt-2 text-slate-500">
          Nie masz konta? <Link href="/register" className="text-indigo-600">Zarejestruj się</Link>
        </p>
      </div>
      <LoginForm />
    </main>
  );
}
