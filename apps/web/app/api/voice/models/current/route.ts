import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";

export async function GET() {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const voiceModel = await prisma.voiceModel.findFirst({
    where: { userId: session.sub, status: "succeeded" },
    orderBy: { updatedAt: "desc" }
  });

  return NextResponse.json({ model: voiceModel });
}
