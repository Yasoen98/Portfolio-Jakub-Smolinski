import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { getTtsEngine } from "@/lib/tts";
import { z } from "zod";

const requestSchema = z.object({
  documentId: z.string(),
  chunkOrder: z.number().int().nonnegative(),
  modelId: z.string(),
  speed: z.number().min(0.75).max(1.5).default(1)
});

export async function POST(request: Request) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const data = await request.json();
  const parsed = requestSchema.safeParse(data);
  if (!parsed.success) {
    return NextResponse.json({ error: "Nieprawidłowe dane" }, { status: 400 });
  }

  const { documentId, chunkOrder, modelId, speed } = parsed.data;

  const document = await prisma.document.findFirst({
    where: { id: documentId, userId: session.sub }
  });

  if (!document) {
    return NextResponse.json({ error: "Nie znaleziono dokumentu" }, { status: 404 });
  }

  const voiceModel = await prisma.voiceModel.findFirst({
    where: { id: modelId, userId: session.sub }
  });

  if (!voiceModel) {
    return NextResponse.json({ error: "Nie znaleziono modelu głosu" }, { status: 404 });
  }

  const chunk = await prisma.documentChunk.findFirst({
    where: { documentId, order: chunkOrder }
  });

  if (!chunk) {
    return NextResponse.json({ error: "Brak chunku" }, { status: 404 });
  }

  const engine = getTtsEngine();
  const synthesis = await engine.synthesize(chunk.text, modelId, { speed });
  const iterator = synthesis.audioStream[Symbol.asyncIterator]();

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { value, done } = await iterator.next();
      if (done) {
        controller.close();
        return;
      }
      controller.enqueue(value);
    }
  });

  const headers = new Headers({
    "Content-Type": "audio/wav",
    "Cache-Control": "no-store",
    "x-transcript-timestamps": JSON.stringify(synthesis.transcriptTimestamps)
  });

  return new Response(stream, { headers });
}
