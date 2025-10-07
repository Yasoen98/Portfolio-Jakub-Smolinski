import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { getStorageDriver } from "@/lib/storage";

const SUPPORTED_TYPES = ["audio/wav", "audio/x-wav", "audio/flac", "audio/mp3", "audio/mpeg"];

export async function POST(request: Request) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const user = await prisma.user.findUnique({
    where: { id: session.sub },
    include: { VoiceModel: { include: { samples: true }, orderBy: { createdAt: "desc" }, take: 1 } }
  });

  if (!user || !user.consentVoice) {
    return NextResponse.json({ error: "Wymagana zgoda na przetwarzanie głosu" }, { status: 403 });
  }

  const formData = await request.formData();
  const files = formData.getAll("samples").filter((value): value is File => value instanceof File);

  if (files.length < 1) {
    return NextResponse.json({ error: "Dołącz co najmniej jedną próbkę" }, { status: 400 });
  }

  if (files.length > 10) {
    return NextResponse.json({ error: "Maksymalnie 10 próbek" }, { status: 400 });
  }

  for (const file of files) {
    if (!SUPPORTED_TYPES.includes(file.type)) {
      return NextResponse.json({ error: `Nieobsługiwany format: ${file.type}` }, { status: 400 });
    }
    if (file.size < 64 * 1024) {
      return NextResponse.json({ error: "Próbka jest zbyt krótka – minimum 10 sekund" }, { status: 400 });
    }
    if (file.size > 10 * 1024 * 1024) {
      return NextResponse.json({ error: "Próbka jest zbyt długa – maksymalnie 60 sekund" }, { status: 400 });
    }
  }

  const driver = getStorageDriver();

  const existingModel = user.VoiceModel[0];
  const existingSamplesCount = existingModel?.samples.length ?? 0;
  const voiceModel =
    existingModel ??
    (await prisma.voiceModel.create({
      data: {
        userId: user.id,
        status: "ready",
        engine: process.env.FEATURE_EXTERNAL_TTS === "true" ? "external" : "mock"
      }
    }));

  if (existingSamplesCount + files.length > 10) {
    return NextResponse.json({ error: "Łącznie można dodać maksymalnie 10 próbek" }, { status: 400 });
  }

  for (const file of files) {
    const buffer = Buffer.from(await file.arrayBuffer());
    const stored = await driver.upload(buffer, {
      contentType: file.type,
      filename: file.name
    });

    await prisma.voiceSample.create({
      data: {
        voiceModelId: voiceModel.id,
        url: stored.url,
        durationSec: 30,
        sampleRate: 16000
      }
    });
  }

  await prisma.voiceModel.update({
    where: { id: voiceModel.id },
    data: { status: "ready" }
  });

  return NextResponse.json({ success: true, totalSamples: existingSamplesCount + files.length });
}
