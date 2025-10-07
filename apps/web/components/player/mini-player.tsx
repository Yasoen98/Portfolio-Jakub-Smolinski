"use client";

import { useEffect, useMemo, useRef } from "react";
import { usePlayerStore } from "@/lib/player-store";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Pause, Play, SkipForward } from "lucide-react";

export const MiniPlayer = () => {
  const {
    audioUrl,
    isPlaying,
    speed,
    setSpeed,
    volume,
    setVolume,
    liveMode,
    setLiveMode,
    transcript,
    currentOrder,
    markBuffered,
    bufferedOrders,
    setPlaying,
    setOrder
  } = usePlayerStore();
  const audioRef = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;
    audio.playbackRate = speed;
  }, [speed]);

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;
    audio.volume = volume;
  }, [volume]);

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;
    if (audioUrl) {
      audio.src = audioUrl;
      audio.load();
      if (isPlaying) {
        void audio.play();
      }
    }
  }, [audioUrl, isPlaying]);

  useEffect(() => {
    const audio = audioRef.current;
    if (!audio) return;

    const handlePlay = () => setPlaying(true);
    const handlePause = () => setPlaying(false);
    const handleEnded = () => {
      if (liveMode) {
        setOrder(currentOrder + 1);
      }
    };

    audio.addEventListener("play", handlePlay);
    audio.addEventListener("pause", handlePause);
    audio.addEventListener("ended", handleEnded);

    return () => {
      audio.removeEventListener("play", handlePlay);
      audio.removeEventListener("pause", handlePause);
      audio.removeEventListener("ended", handleEnded);
    };
  }, [setPlaying, setOrder, currentOrder, liveMode]);

  const transcriptText = useMemo(
    () => transcript.map((entry) => entry.text).join(" "),
    [transcript]
  );

  useEffect(() => {
    if (audioUrl && !bufferedOrders.includes(currentOrder)) {
      markBuffered(currentOrder);
    }
  }, [audioUrl, currentOrder, bufferedOrders, markBuffered]);

  if (!audioUrl) {
    return (
      <div className="fixed inset-x-0 bottom-0 bg-slate-900 py-4 text-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4">
          <span className="text-sm">Mini-player gotowy. Wybierz dokument, aby rozpocząć.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-x-0 bottom-0 bg-slate-900 py-4 text-white">
      <div className="mx-auto flex max-w-5xl flex-col gap-3 px-4">
        <div className="flex items-center gap-3">
          <Button
            size="icon"
            variant="ghost"
            className="text-white hover:bg-slate-800"
            onClick={() => {
              const audio = audioRef.current;
              if (!audio) return;
              if (isPlaying) {
                audio.pause();
              } else {
                void audio.play();
              }
            }}
          >
            {isPlaying ? <Pause className="h-5 w-5" /> : <Play className="h-5 w-5" />}
          </Button>
          <Button
            size="icon"
            variant="ghost"
            className="text-white hover:bg-slate-800"
            onClick={() => setOrder(currentOrder + 1)}
          >
            <SkipForward className="h-5 w-5" />
          </Button>
          <div className="grow">
            <Slider
              min={0.75}
              max={1.5}
              step={0.05}
              value={[speed]}
              onValueChange={(value) => setSpeed(value[0] ?? 1)}
            />
            <p className="mt-2 text-xs text-slate-300">Tempo: {speed.toFixed(2)}x</p>
          </div>
          <div className="w-32">
            <Slider
              min={0}
              max={1}
              step={0.01}
              value={[volume]}
              onValueChange={(value) => setVolume(value[0] ?? 1)}
            />
            <p className="mt-2 text-xs text-slate-300">Głośność: {(volume * 100).toFixed(0)}%</p>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={liveMode} onCheckedChange={setLiveMode} id="live" />
            <label htmlFor="live" className="text-xs text-slate-300">
              Live
            </label>
          </div>
          <div className="text-xs text-slate-400">
            Bufor: {bufferedOrders.length} chunków
          </div>
        </div>
        <div className="rounded-md bg-slate-800 p-3 text-sm text-slate-200">
          {transcriptText || "Trwa ładowanie napisów..."}
        </div>
        <audio ref={audioRef} className="hidden" controls={false} />
      </div>
    </div>
  );
};
