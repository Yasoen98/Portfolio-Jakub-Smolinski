import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { z } from "zod";

const schema = z.object({
  documentId: z.string(),
  chunkOrder: z.number().int().nonnegative(),
  offsetMs: z.number().int().nonnegative(),
  speed: z.number().min(0.5).max(2)
});

export async function POST(request: Request) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const data = await request.json();
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    return NextResponse.json({ error: "Nieprawidłowe dane" }, { status: 400 });
  }

  const { documentId, chunkOrder, offsetMs, speed } = parsed.data;

  const document = await prisma.document.findFirst({
    where: { id: documentId, userId: session.sub }
  });

  if (!document) {
    return NextResponse.json({ error: "Nie znaleziono dokumentu" }, { status: 404 });
  }

  await prisma.playbackState.upsert({
    where: { userId: session.sub },
    update: { documentId, chunkOrder, offsetMs, speed },
    create: { userId: session.sub, documentId, chunkOrder, offsetMs, speed }
  });

  return NextResponse.json({ success: true });
}
