import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";

export async function GET() {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const documents = await prisma.document.findMany({
    where: { userId: session.sub },
    orderBy: { createdAt: "desc" },
    include: { chunks: { take: 1 } }
  });

  return NextResponse.json({ documents });
}
