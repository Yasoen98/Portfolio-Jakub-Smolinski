import { NextResponse } from "next/server";
import { prisma } from "@db";
import { hashPassword, createSessionToken, setSessionCookie } from "@/lib/auth";
import { z } from "zod";

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  consentVoice: z.boolean(),
  consentText: z.boolean()
});

export async function POST(request: Request) {
  const data = await request.json();
  const parseResult = registerSchema.safeParse(data);
  if (!parseResult.success) {
    return NextResponse.json({ error: "Nieprawidłowe dane" }, { status: 400 });
  }

  const { email, password, consentVoice, consentText } = parseResult.data;

  if (!consentVoice || !consentText) {
    return NextResponse.json({ error: "Wymagana zgoda" }, { status: 400 });
  }

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json({ error: "Użytkownik już istnieje" }, { status: 400 });
  }

  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      consentVoice,
      consentText
    }
  });

  await prisma.voiceModel.create({
    data: {
      userId: user.id,
      status: "ready",
      engine: process.env.FEATURE_EXTERNAL_TTS === "true" ? "external" : "mock"
    }
  });

  const token = await createSessionToken({ sub: user.id, email: user.email });
  await setSessionCookie(token);

  return NextResponse.json({ success: true });
}
