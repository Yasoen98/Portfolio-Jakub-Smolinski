import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";

interface Params {
  params: { id: string };
}

export async function GET(_request: Request, { params }: Params) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const document = await prisma.document.findFirst({
    where: { id: params.id, userId: session.sub },
    include: { chunks: { take: 5, orderBy: { order: "asc" } } }
  });

  if (!document) {
    return NextResponse.json({ error: "Nie znaleziono dokumentu" }, { status: 404 });
  }

  return NextResponse.json({ document });
}
