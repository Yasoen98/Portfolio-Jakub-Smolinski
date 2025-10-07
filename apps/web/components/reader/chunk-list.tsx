"use client";

import type { DocumentChunk } from "@prisma/client";
import { usePlayerStore } from "@/lib/player-store";
import { Button } from "@/components/ui/button";

export const ChunkList = ({ chunks }: { chunks: DocumentChunk[] }) => {
  const { currentOrder, setOrder, setPlaying } = usePlayerStore();

  return (
    <div className="space-y-3">
      {chunks.map((chunk) => (
        <article
          key={chunk.id}
          className={`rounded-md border p-4 text-sm transition ${
            chunk.order === currentOrder ? "border-indigo-400 bg-indigo-50" : "border-slate-200 bg-white"
          }`}
        >
          <header className="mb-2 flex items-center justify-between text-xs text-slate-500">
            <span>Strona {chunk.page}</span>
            <Button
              size="sm"
              variant={chunk.order === currentOrder ? "default" : "outline"}
              onClick={() => {
                setOrder(chunk.order);
                setPlaying(true);
              }}
            >
              {chunk.order === currentOrder ? "Odtwarzanie" : "Odtwórz"}
            </Button>
          </header>
          <p className="leading-relaxed text-slate-700">{chunk.text}</p>
        </article>
      ))}
    </div>
  );
};
