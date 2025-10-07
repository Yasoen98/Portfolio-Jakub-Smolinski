export interface PdfMetadata {
  title: string;
  author?: string | null;
  pageCount: number;
  bytes: number;
}

export interface DocumentChunkInput {
  text: string;
  page: number;
  order: number;
  charStart: number;
  charEnd: number;
}

export interface ExtractedDocument {
  metadata: PdfMetadata;
  chunks: DocumentChunkInput[];
}

const DEFAULT_CHUNK_SIZE = 1400;

export async function extractPdf(buffer: ArrayBuffer): Promise<ExtractedDocument> {
  const pdfModule = await import("pdf-parse");
  const pdf = pdfModule.default ?? pdfModule;
  const result = await pdf(Buffer.from(buffer));
  const info = result.info ?? {};
  const text = result.text ?? "";

  const metadata: PdfMetadata = {
    title: (info.Title as string) || "Nieznany dokument",
    author: (info.Author as string) || null,
    pageCount: result.numpages ?? 1,
    bytes: buffer.byteLength
  };

  const lines = text.split(/\n+/g);
  const chunks: DocumentChunkInput[] = [];
  let chunkText: string[] = [];
  let chunkStart = 0;
  let order = 0;
  let currentPage = 1;

  for (const line of lines) {
    if (line.trim().length === 0) {
      chunkText.push("\n");
      continue;
    }

    chunkText.push(line);

    if (chunkText.join(" ").length >= DEFAULT_CHUNK_SIZE) {
      const textContent = chunkText.join(" ").trim();
      chunks.push({
        text: textContent,
        page: currentPage,
        order,
        charStart: chunkStart,
        charEnd: chunkStart + textContent.length
      });
      order += 1;
      chunkStart = chunkStart + textContent.length;
      chunkText = [];
    }

    if (line.includes("\f")) {
      currentPage += 1;
    }
  }

  if (chunkText.length) {
    const textContent = chunkText.join(" ").trim();
    chunks.push({
      text: textContent,
      page: currentPage,
      order,
      charStart: chunkStart,
      charEnd: chunkStart + textContent.length
    });
  }

  if (!chunks.length) {
    chunks.push({
      text: "Brak rozpoznanego tekstu w PDF – dodaj treść ręcznie lub uruchom OCR.",
      page: 1,
      order: 0,
      charStart: 0,
      charEnd: 0
    });
  }

  return {
    metadata,
    chunks
  };
}

export function chunkText(text: string, chunkSize = DEFAULT_CHUNK_SIZE): DocumentChunkInput[] {
  const sentences = text.split(/(?<=[.!?])\s+/);
  const chunks: DocumentChunkInput[] = [];
  let buffer = "";
  let order = 0;
  let start = 0;

  for (const sentence of sentences) {
    if ((buffer + sentence).length > chunkSize && buffer.length > 0) {
      chunks.push({
        text: buffer.trim(),
        page: 1,
        order,
        charStart: start,
        charEnd: start + buffer.trim().length
      });
      start += buffer.trim().length;
      buffer = sentence;
      order += 1;
    } else {
      buffer += (buffer ? " " : "") + sentence;
    }
  }

  if (buffer.trim().length > 0) {
    chunks.push({
      text: buffer.trim(),
      page: 1,
      order,
      charStart: start,
      charEnd: start + buffer.trim().length
    });
  }

  return chunks;
}
