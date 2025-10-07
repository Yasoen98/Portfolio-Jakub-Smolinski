import Link from "next/link";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DocumentGrid } from "@/components/library/document-grid";
import { VoiceModelPanel } from "@/components/voice/voice-model-panel";

export default async function DashboardPage() {
  const session = await getSessionFromRequest();
  if (!session) {
    return null;
  }

  const user = await prisma.user.findUnique({
    where: { id: session.sub },
    include: {
      VoiceModel: {
        orderBy: { createdAt: "desc" },
        include: { samples: true }
      },
      Document: {
        include: { chunks: { take: 1 } }
      }
    }
  });

  if (!user) {
    return null;
  }

  return (
    <main className="mx-auto flex max-w-5xl flex-col gap-8 px-4 py-12">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-slate-900">Witaj, {user.email}</h1>
          <p className="text-slate-500">Zarządzaj swoim głosem i biblioteką.</p>
        </div>
        <form action="/api/auth/logout" method="post">
          <Button type="submit" variant="outline">
            Wyloguj
          </Button>
        </form>
      </header>
      <section className="grid gap-6 md:grid-cols-2">
        <VoiceModelPanel user={user} />
        <Card>
          <CardHeader>
            <CardTitle>Twoje dokumenty</CardTitle>
            <CardDescription>
              Dodawaj pliki PDF i przekształcaj je w audiobooka na żywo.
            </CardDescription>
          </CardHeader>
          <div className="flex flex-col gap-3">
            <Link href="/library/upload">
              <Button className="w-full">Wgraj nowy PDF</Button>
            </Link>
            <Link href="/library">
              <Button variant="outline" className="w-full">
                Przejdź do biblioteki
              </Button>
            </Link>
          </div>
        </Card>
      </section>
      <section>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-xl font-semibold">Ostatnie książki</h2>
          <Link href="/library" className="text-sm text-indigo-600">
            Zobacz wszystkie
          </Link>
        </div>
        <DocumentGrid documents={user.Document} />
      </section>
    </main>
  );
}
