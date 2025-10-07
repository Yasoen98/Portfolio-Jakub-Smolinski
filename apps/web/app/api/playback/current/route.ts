import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";

export async function GET(request: Request) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const documentId = searchParams.get("documentId");

  const state = await prisma.playbackState.findUnique({ where: { userId: session.sub } });
  if (!state || (documentId && state.documentId !== documentId)) {
    return NextResponse.json({ state: null });
  }

  return NextResponse.json({ state });
}
