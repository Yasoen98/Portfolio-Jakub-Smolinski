import { getSessionFromRequest } from "@/lib/auth";
import { PdfUploadForm } from "@/components/forms/pdf-upload-form";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export default async function UploadPage() {
  const session = await getSessionFromRequest();
  if (!session) {
    return null;
  }

  return (
    <main className="mx-auto flex max-w-3xl flex-col gap-6 px-4 py-12">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-semibold text-slate-900">Wgraj dokument PDF</h1>
          <p className="text-slate-500">Limit rozmiaru: 200 MB. Obsługujemy tekst i OCR (wkrótce).</p>
        </div>
        <Link href="/library">
          <Button variant="outline">Powrót</Button>
        </Link>
      </div>
      <PdfUploadForm />
    </main>
  );
}
