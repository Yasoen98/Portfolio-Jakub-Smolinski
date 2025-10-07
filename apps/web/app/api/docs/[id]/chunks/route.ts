import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";

interface Params {
  params: { id: string };
}

export async function GET(request: Request, { params }: Params) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const document = await prisma.document.findFirst({
    where: { id: params.id, userId: session.sub }
  });

  if (!document) {
    return NextResponse.json({ error: "Nie znaleziono dokumentu" }, { status: 404 });
  }

  const { searchParams } = new URL(request.url);
  const from = Number(searchParams.get("from") ?? "0");
  const limit = Number(searchParams.get("limit") ?? "3");

  const chunks = await prisma.documentChunk.findMany({
    where: { documentId: params.id },
    orderBy: { order: "asc" },
    skip: from,
    take: Math.min(limit, 10)
  });

  return NextResponse.json({ chunks });
}
