import "dotenv/config";
import { Worker } from "bullmq";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

const connection = {
  connection: {
    url: process.env.REDIS_URL ?? "redis://localhost:6379"
  }
};

const TRAINING_QUEUE = "voice-training";
const PDF_QUEUE = "pdf-processing";

const trainingWorker = new Worker(
  TRAINING_QUEUE,
  async (job) => {
    const { modelId } = job.data as { modelId: string };
    await prisma.voiceModel.update({ where: { id: modelId }, data: { status: "running" } });
    await prisma.trainingJob.update({ where: { id: job.id as string }, data: { status: "running" } });
    await new Promise((resolve) => setTimeout(resolve, 3000));
    await prisma.voiceModel.update({
      where: { id: modelId },
      data: {
        status: "succeeded",
        metricsJson: { mos: 4.2, similarity: 0.91 }
      }
    });
    await prisma.trainingJob.update({ where: { id: job.id as string }, data: { status: "succeeded" } });
  },
  connection
);

trainingWorker.on("failed", async (job, err) => {
  if (!job?.id) return;
  await prisma.trainingJob.update({ where: { id: job.id as string }, data: { status: "failed" } });
  await prisma.voiceModel.update({ where: { id: (job.data as { modelId: string }).modelId }, data: { status: "failed" } });
  console.error("Training job failed", err);
});

const pdfWorker = new Worker(
  PDF_QUEUE,
  async (job) => {
    console.log("Processing PDF job", job.id);
  },
  connection
);

pdfWorker.on("failed", (job, err) => {
  console.error("PDF job failed", job?.id, err);
});

process.on("SIGINT", async () => {
  await trainingWorker.close();
  await pdfWorker.close();
  await prisma.$disconnect();
  process.exit(0);
});
