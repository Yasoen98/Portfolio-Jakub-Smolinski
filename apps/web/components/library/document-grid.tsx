import Link from "next/link";
import type { Document, DocumentChunk } from "@prisma/client";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";

export interface DocumentWithChunks extends Document {
  chunks: DocumentChunk[];
}

export const DocumentGrid = ({ documents }: { documents: DocumentWithChunks[] }) => {
  if (!documents.length) {
    return <p className="text-slate-500">Brak dokumentów. Wgraj pierwszy PDF.</p>;
  }
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {documents.map((doc) => (
        <Link key={doc.id} href={`/library/${doc.id}`}>
          <Card className="hover:border-indigo-200">
            <CardTitle className="line-clamp-1">{doc.title}</CardTitle>
            <CardDescription className="mt-2">
              {doc.author ? `${doc.author} • ` : ""}
              {doc.pages ?? "?"} stron
            </CardDescription>
            <p className="mt-4 text-sm text-slate-500">
              {doc.chunks[0]?.text.slice(0, 120) ?? "Brak podglądu"}...
            </p>
          </Card>
        </Link>
      ))}
    </div>
  );
};
