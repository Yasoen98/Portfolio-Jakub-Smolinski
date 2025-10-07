import { NextResponse } from "next/server";
import { prisma } from "@db";
import { getSessionFromRequest } from "@/lib/auth";
import { getStorageDriver } from "@/lib/storage";
import { extractPdf } from "@voxbook/core";
import { pdfQueue } from "@queue";

const MAX_SIZE = 200 * 1024 * 1024;

export async function POST(request: Request) {
  const session = await getSessionFromRequest();
  if (!session) {
    return NextResponse.json({ error: "Brak autoryzacji" }, { status: 401 });
  }

  const user = await prisma.user.findUnique({ where: { id: session.sub } });

  if (!user?.consentText) {
    return NextResponse.json({ error: "Wymagana zgoda na przetwarzanie tekstów" }, { status: 403 });
  }

  const formData = await request.formData();
  const file = formData.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json({ error: "Dołącz plik PDF" }, { status: 400 });
  }

  if (file.type !== "application/pdf") {
    return NextResponse.json({ error: "Wymagany format PDF" }, { status: 400 });
  }

  if (file.size > MAX_SIZE) {
    return NextResponse.json({ error: "Plik jest zbyt duży (max 200MB)" }, { status: 400 });
  }

  const buffer = Buffer.from(await file.arrayBuffer());
  const storage = getStorageDriver();
  const stored = await storage.upload(buffer, {
    filename: file.name,
    contentType: file.type
  });

  const extracted = await extractPdf(
    buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
  );

  const document = await prisma.document.create({
    data: {
      userId: session.sub,
      title: extracted.metadata.title,
      author: extracted.metadata.author ?? undefined,
      pages: extracted.metadata.pageCount,
      bytes: extracted.metadata.bytes,
      storageUrl: stored.url
    }
  });

  await prisma.documentChunk.createMany({
    data: extracted.chunks.map((chunk) => ({
      ...chunk,
      documentId: document.id
    }))
  });

  await pdfQueue.add("post-process", {
    documentId: document.id,
    userId: session.sub,
    chunkCount: extracted.chunks.length
  });

  return NextResponse.json({ documentId: document.id });
}
