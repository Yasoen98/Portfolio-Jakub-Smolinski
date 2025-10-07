import { prisma } from "../src";
import bcrypt from "bcryptjs";
import { chunkText } from "@voxbook/core";

async function main() {
  const email = "demo@voxbook.local";
  const password = await bcrypt.hash("password123", 10);

  const user = await prisma.user.upsert({
    where: { email },
    update: {},
    create: {
      email,
      passwordHash: password,
      consentVoice: true,
      consentText: true
    }
  });

  const document = await prisma.document.upsert({
    where: { id: "demo-doc" },
    update: {},
    create: {
      id: "demo-doc",
      userId: user.id,
      title: "VoxBook Demo Manual",
      author: "VoxBook",
      pages: 3,
      bytes: 1024,
      storageUrl: "s3://voxbook/demo.pdf"
    }
  });

  const sampleText = `Welcome to VoxBook! This demo document showcases how live audiobook generation works. Each paragraph is chunked and ready to be streamed. Enjoy testing the playback controls and training features.`;
  const chunks = chunkText(sampleText, 300);

  await prisma.documentChunk.deleteMany({ where: { documentId: document.id } });
  await prisma.documentChunk.createMany({
    data: chunks.map((chunk) => ({
      ...chunk,
      documentId: document.id
    }))
  });

  await prisma.voiceModel.upsert({
    where: { id: "demo-voice" },
    update: {},
    create: {
      id: "demo-voice",
      userId: user.id,
      status: "succeeded",
      engine: "mock",
      version: 1
    }
  });

  console.log("Seed completed");
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
