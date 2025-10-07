"use client";

import { useState } from "react";
import type { VoiceModel, VoiceSample, User } from "@prisma/client";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";

export interface VoiceModelPanelProps {
  user: User & { VoiceModel: (VoiceModel & { samples: VoiceSample[] })[] };
}

export const VoiceModelPanel = ({ user }: VoiceModelPanelProps) => {
  const [uploading, setUploading] = useState(false);
  const [training, setTraining] = useState(false);
  const currentModel = user.VoiceModel[0];
  const sampleCount = currentModel?.samples.length ?? 0;
  const hasEnoughSamples = sampleCount >= 3;

  const handleSampleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;
    setUploading(true);
    const formData = new FormData();
    Array.from(files).forEach((file) => formData.append("samples", file));
    const response = await fetch("/api/voice/samples", { method: "POST", body: formData });
    setUploading(false);
    if (response.ok) {
      window.location.reload();
    }
  };

  const handleTraining = async () => {
    setTraining(true);
    const response = await fetch("/api/voice/train", { method: "POST" });
    setTraining(false);
    if (response.ok) {
      window.location.reload();
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Twój model głosu</CardTitle>
        <CardDescription>
          Wgraj 3-10 próbek (10-60s) i uruchom trening, aby stworzyć spersonalizowany głos.
        </CardDescription>
      </CardHeader>
      <div className="space-y-4">
        <div>
          <Label className="mb-2 block text-sm font-semibold">Status</Label>
          <p className="text-sm text-slate-600">
            {currentModel ? `Model ${currentModel.status}` : "Brak modelu - wgraj próbki, aby rozpocząć."}
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="samples">Próbki głosu (WAV/FLAC/MP3)</Label>
          <input
            id="samples"
            type="file"
            accept="audio/wav,audio/flac,audio/mp3,audio/mpeg"
            multiple
            onChange={handleSampleUpload}
            className="block w-full text-sm"
          />
          <p className="text-xs text-slate-500">
            Minimum 3 próbki, każda 10-60s. Zadbaj o ciche otoczenie i jeden głos.
          </p>
          <Button disabled={uploading} className="w-full" type="button" onClick={() => document.getElementById("samples")?.click()}>
            {uploading ? "Przesyłanie..." : "Wybierz pliki"}
          </Button>
        </div>
        <Button type="button" className="w-full" onClick={handleTraining} disabled={training || !hasEnoughSamples}>
          {training ? "Trwa trenowanie..." : hasEnoughSamples ? "Trenuj model" : "Wgraj min. 3 próbki"}
        </Button>
        {currentModel ? (
          <div className="rounded-md border border-slate-200 p-3 text-sm text-slate-600">
            <p>Silnik: {currentModel.engine}</p>
            <p>Wersja: {currentModel.version}</p>
            <p>Próbek: {sampleCount}</p>
            <p className="text-xs text-slate-400">
              Po zakończeniu treningu metryki jakości pojawią się w panelu.
            </p>
          </div>
        ) : null}
      </div>
    </Card>
  );
};
