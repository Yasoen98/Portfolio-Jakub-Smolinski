"use client";

import { useCallback, useEffect, useRef } from "react";
import { usePlayerStore } from "@/lib/player-store";

interface PlaybackInitializerProps {
  documentId: string;
  modelId: string;
  initialOrder: number;
  initialSpeed: number;
}

async function readAudioStream(response: Response): Promise<{ url: string; transcript: any[] }> {
  if (!response.body) {
    throw new Error("Brak strumienia audio");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) chunks.push(value);
  }
  const blob = new Blob(chunks, { type: "audio/wav" });
  const url = URL.createObjectURL(blob);
  const transcriptHeader = response.headers.get("x-transcript-timestamps") ?? "[]";
  const transcript = JSON.parse(transcriptHeader) as any[];
  return { url, transcript };
}

export const PlaybackInitializer = ({ documentId, modelId, initialOrder, initialSpeed }: PlaybackInitializerProps) => {
  const {
    setDocument,
    currentOrder,
    setOrder,
    setAudio,
    speed,
    setSpeed,
    liveMode,
    markBuffered
  } = usePlayerStore();
  const loadingRef = useRef(false);

  useEffect(() => {
    setDocument(documentId, modelId);
    setOrder(initialOrder);
    setSpeed(initialSpeed);
  }, [documentId, modelId, initialOrder, initialSpeed, setDocument, setOrder, setSpeed]);

  const loadChunk = useCallback(
    async (order: number) => {
      if (loadingRef.current) return;
      loadingRef.current = true;
      const response = await fetch("/api/tts/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ documentId, modelId, chunkOrder: order, speed })
      });
      if (!response.ok) {
        console.error("Nie udało się pobrać audio");
        loadingRef.current = false;
        return;
      }
      const { url, transcript } = await readAudioStream(response);
      setAudio(url, transcript);
      markBuffered(order);
      await fetch("/api/playback/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ documentId, chunkOrder: order, offsetMs: 0, speed })
      });
      loadingRef.current = false;
    },
    [documentId, modelId, setAudio, markBuffered, speed]
  );

  useEffect(() => {
    void loadChunk(currentOrder);
  }, [currentOrder, loadChunk]);

  useEffect(() => {
    if (!liveMode) return;
    const interval = setInterval(() => {
      fetch("/api/playback/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ documentId, chunkOrder: currentOrder, offsetMs: 0, speed })
      }).catch(() => undefined);
    }, 5000);
    return () => clearInterval(interval);
  }, [documentId, currentOrder, liveMode, speed]);

  return null;
};
