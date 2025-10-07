import { NextResponse } from "next/server";
import { prisma } from "@db";
import { createSessionToken, setSessionCookie, verifyPassword } from "@/lib/auth";
import { z } from "zod";

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

export async function POST(request: Request) {
  const data = await request.json();
  const parseResult = loginSchema.safeParse(data);
  if (!parseResult.success) {
    return NextResponse.json({ error: "Nieprawidłowe dane" }, { status: 400 });
  }

  const { email, password } = parseResult.data;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return NextResponse.json({ error: "Nie znaleziono użytkownika" }, { status: 401 });
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    return NextResponse.json({ error: "Błędne dane logowania" }, { status: 401 });
  }

  const token = await createSessionToken({ sub: user.id, email: user.email });
  await setSessionCookie(token);

  return NextResponse.json({ success: true });
}
