"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const RegisterForm = () => {
  const router = useRouter();
  const [form, setForm] = useState({ email: "", password: "", confirm: "" });
  const [consentVoice, setConsentVoice] = useState(false);
  const [consentText, setConsentText] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (form.password !== form.confirm) {
      setError("Hasła nie są zgodne");
      return;
    }
    if (!consentVoice || !consentText) {
      setError("Musisz zaakceptować zgody");
      return;
    }
    setLoading(true);
    setError(null);
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: form.email,
        password: form.password,
        consentVoice,
        consentText
      })
    });
    setLoading(false);
    if (!response.ok) {
      const message = (await response.json()).error ?? "Nie udało się utworzyć konta";
      setError(message);
      return;
    }
    router.push("/dashboard");
    router.refresh();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          value={form.email}
          onChange={(event) => setForm((prev) => ({ ...prev, email: event.target.value }))}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Hasło</Label>
        <Input
          id="password"
          type="password"
          value={form.password}
          onChange={(event) => setForm((prev) => ({ ...prev, password: event.target.value }))}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="confirm">Powtórz hasło</Label>
        <Input
          id="confirm"
          type="password"
          value={form.confirm}
          onChange={(event) => setForm((prev) => ({ ...prev, confirm: event.target.value }))}
          required
        />
      </div>
      <fieldset className="space-y-2 rounded-md border border-slate-200 p-4">
        <legend className="px-1 text-sm font-semibold">Zgody</legend>
        <label className="flex items-start gap-3 text-sm text-slate-600">
          <input
            type="checkbox"
            checked={consentVoice}
            onChange={(event) => setConsentVoice(event.target.checked)}
            className="mt-1"
          />
          Wyrażam zgodę na wykorzystanie moich próbek głosu do trenowania spersonalizowanego modelu TTS.
        </label>
        <label className="flex items-start gap-3 text-sm text-slate-600">
          <input
            type="checkbox"
            checked={consentText}
            onChange={(event) => setConsentText(event.target.checked)}
            className="mt-1"
          />
          Potwierdzam, że mam prawo do wykorzystania przesyłanych treści tekstowych.
        </label>
      </fieldset>
      {error ? <p className="text-sm text-red-600">{error}</p> : null}
      <Button type="submit" className="w-full" disabled={loading}>
        {loading ? "Rejestrowanie..." : "Utwórz konto"}
      </Button>
    </form>
  );
};
