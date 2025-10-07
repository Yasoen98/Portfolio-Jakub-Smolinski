import { Queue } from "bullmq";

const connection = () => ({
  connection: {
    url: process.env.REDIS_URL ?? "redis://localhost:6379"
  }
});

export const trainingQueueName = "voice-training";
export const pdfQueueName = "pdf-processing";

export const trainingQueue = new Queue(trainingQueueName, connection());
export const pdfQueue = new Queue(pdfQueueName, connection());
