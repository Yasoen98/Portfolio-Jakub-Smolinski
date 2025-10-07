import { notFound } from "next/navigation";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { PlaybackInitializer } from "@/components/reader/playback-initializer";
import { ChunkList } from "@/components/reader/chunk-list";

interface ReaderPageProps {
  params: { id: string };
}

export default async function ReaderPage({ params }: ReaderPageProps) {
  const session = await getSessionFromRequest();
  if (!session) {
    return null;
  }

  const [document, playbackState, model] = await Promise.all([
    prisma.document.findFirst({
      where: { id: params.id, userId: session.sub },
      include: {
        chunks: {
          orderBy: { order: "asc" }
        }
      }
    }),
    prisma.playbackState.findUnique({ where: { userId: session.sub } }),
    prisma.voiceModel.findFirst({ where: { userId: session.sub, status: "succeeded" } })
  ]);

  if (!document) {
    notFound();
  }

  return (
    <main className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-12">
      <div>
        <p className="text-sm text-slate-500">Autor: {document.author ?? "Nieznany"}</p>
        <h1 className="text-3xl font-semibold text-slate-900">{document.title}</h1>
      </div>
      <PlaybackInitializer
        documentId={document.id}
        modelId={model?.id ?? "demo-voice"}
        initialOrder={playbackState?.documentId === document.id ? playbackState.chunkOrder : 0}
        initialSpeed={playbackState?.speed ?? 1}
      />
      <ChunkList chunks={document.chunks} />
    </main>
  );
}
