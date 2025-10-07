import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { trainingQueue, trainingQueueName } from "@queue";

export async function POST() {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const user = await prisma.user.findUnique({ where: { id: session.sub } });

  if (!user?.consentVoice) {
    return NextResponse.json({ error: "Wymagana zgoda na przetwarzanie głosu" }, { status: 403 });
  }

  const voiceModel = await prisma.voiceModel.findFirst({
    where: { userId: session.sub },
    include: { samples: true }
  });

  if (!voiceModel || voiceModel.samples.length < 3) {
    return NextResponse.json({ error: "Wgraj minimum 3 próbki" }, { status: 400 });
  }

  const job = await trainingQueue.add("train-voice", {
    modelId: voiceModel.id,
    userId: session.sub
  });

  const jobId = String(job.id);

  await prisma.trainingJob.create({
    data: {
      id: jobId,
      modelId: voiceModel.id,
      status: "queued"
    }
  });

  await prisma.voiceModel.update({
    where: { id: voiceModel.id },
    data: { status: "queued" }
  });

  return NextResponse.json({ jobId, queue: trainingQueueName });
}
