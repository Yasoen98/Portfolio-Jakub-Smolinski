import { notFound } from "next/navigation";
import Link from "next/link";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { Button } from "@/components/ui/button";

interface DocumentPageProps {
  params: { id: string };
}

export default async function DocumentPage({ params }: DocumentPageProps) {
  const session = await getSessionFromRequest();
  if (!session) {
    return null;
  }

  const document = await prisma.document.findFirst({
    where: { id: params.id, userId: session.sub },
    include: {
      chunks: {
        orderBy: { order: "asc" },
        take: 10
      }
    }
  });

  if (!document) {
    notFound();
  }

  return (
    <main className="mx-auto flex max-w-4xl flex-col gap-6 px-4 py-12">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-500">Autor: {document.author ?? "Nieznany"}</p>
          <h1 className="text-3xl font-semibold text-slate-900">{document.title}</h1>
          <p className="text-sm text-slate-500">{document.pages ?? "?"} stron • {(document.bytes / (1024 * 1024)).toFixed(2)} MB</p>
        </div>
        <div className="flex gap-3">
          <Link href={`/reader/${document.id}`}>
            <Button> Czytaj na żywo</Button>
          </Link>
          <Link href="/library">
            <Button variant="outline">Powrót</Button>
          </Link>
        </div>
      </div>
      <section className="space-y-4">
        <h2 className="text-xl font-semibold">Podgląd</h2>
        <div className="space-y-3 rounded-lg border border-slate-200 bg-white p-4">
          {document.chunks.map((chunk) => (
            <p key={chunk.id} className="text-sm text-slate-700">
              <span className="font-semibold text-slate-500">[Strona {chunk.page}]</span> {chunk.text.slice(0, 400)}
              {chunk.text.length > 400 ? "..." : ""}
            </p>
          ))}
        </div>
      </section>
    </main>
  );
}
