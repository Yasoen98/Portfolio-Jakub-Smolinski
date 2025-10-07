import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const modelId = searchParams.get("modelId");

  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const voiceModel = await prisma.voiceModel.findFirst({
    where: modelId
      ? { id: modelId, userId: session.sub }
      : { userId: session.sub },
    include: { samples: true },
    orderBy: { updatedAt: "desc" }
  });

  if (!voiceModel) {
    return NextResponse.json({ error: "Nie znaleziono modelu" }, { status: 404 });
  }

  const job = await prisma.trainingJob.findFirst({
    where: { modelId: voiceModel.id },
    orderBy: { createdAt: "desc" }
  });

  return NextResponse.json({
    model: voiceModel,
    job
  });
}
