"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";

export const PdfUploadForm = () => {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!file) {
      setError("Wybierz plik PDF");
      return;
    }
    if (file.size > 200 * 1024 * 1024) {
      setError("Maksymalny rozmiar to 200 MB");
      return;
    }
    setUploading(true);
    setError(null);
    const formData = new FormData();
    formData.append("file", file);
    const response = await fetch("/api/docs/upload", { method: "POST", body: formData });
    setUploading(false);
    if (!response.ok) {
      const message = (await response.json()).error ?? "Nie udało się wgrać pliku";
      setError(message);
      return;
    }
    router.push("/library");
    router.refresh();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6 rounded-lg border border-dashed border-slate-300 p-6">
      <div className="flex flex-col items-center justify-center gap-3 text-center">
        <input
          type="file"
          accept="application/pdf"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <p className="text-sm text-slate-500">Przeciągnij i upuść plik lub wybierz go ręcznie.</p>
        {file ? (
          <p className="text-xs text-slate-500">
            Wybrano: {file.name} ({(file.size / (1024 * 1024)).toFixed(2)} MB)
          </p>
        ) : null}
      </div>
      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      <Button type="submit" className="w-full" disabled={uploading}>
        {uploading ? "Wgrywanie..." : "Wyślij PDF"}
      </Button>
    </form>
  );
};
