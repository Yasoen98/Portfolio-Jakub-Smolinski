import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { DocumentGrid } from "@/components/library/document-grid";
import { Button } from "@/components/ui/button";
import Link from "next/link";

export default async function LibraryPage() {
  const session = await getSessionFromRequest();
  if (!session) {
    return null;
  }

  const documents = await prisma.document.findMany({
    where: { userId: session.sub },
    orderBy: { createdAt: "desc" },
    include: { chunks: { take: 1 } }
  });

  return (
    <main className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-12">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-slate-900">Biblioteka</h1>
          <p className="text-slate-500">Wszystkie Twoje książki i dokumenty.</p>
        </div>
        <Link href="/library/upload">
          <Button>Dodaj PDF</Button>
        </Link>
      </header>
      <DocumentGrid documents={documents} />
    </main>
  );
}
