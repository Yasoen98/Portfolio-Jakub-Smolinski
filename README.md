# VoxBook

VoxBook to monorepo (pnpm workspaces) zbudowany wokół personalizowanego lektora głosowego. Aplikacja umożliwia trenowanie modelu klonowania głosu na podstawie próbek użytkownika, import plików PDF, a następnie strumieniowe odczytywanie treści dokumentów w mini-odtwarzaczu z zachowaniem stanu.

## Zawartość repozytorium

```
.
├── apps
│   ├── web      # Next.js (App Router) – frontend + API routes
│   └── worker   # Worker BullMQ przetwarzający długotrwałe zadania
├── packages
│   ├── core     # Logika współdzielona: TTS, parsowanie PDF, kolejka odtwarzania
│   └── db       # Konfiguracja Prisma + seed danych
├── docker-compose.yml
└── README.md
```

## Wymagania

- Node.js 18+
- pnpm 8+
- Docker + Docker Compose (PostgreSQL, Redis, MinIO)

## Szybki start

1. **Zainstaluj zależności**

   ```bash
   pnpm install
   ```

2. **Uruchom infrastrukturę**

   ```bash
   docker compose up -d
   ```

3. **Skonfiguruj bazę i dane demo**

   ```bash
   cd apps/web
   cp .env.example .env
   cd ../..
   pnpm db:push
   pnpm db:seed
   ```

4. **Uruchom środowisko developerskie**

   ```bash
   pnpm dev          # aplikacja web (http://localhost:3000)
   pnpm worker       # w drugim terminalu – obsługa kolejki treningu
   ```

## Instrukcja krok po kroku dla początkujących

Jeżeli dopiero zaczynasz pracę z projektami JavaScript i Dockerem, wykonaj poniższe kroki dokładnie w tej kolejności:

1. **Przygotuj narzędzia**
   - Zainstaluj [Node.js 18 LTS](https://nodejs.org/) i podczas instalacji zaznacz opcję dodania go do zmiennej `PATH`.
   - Zainstaluj [pnpm](https://pnpm.io/installation) (np. poleceniem `npm install -g pnpm`).
   - Zainstaluj [Docker Desktop](https://www.docker.com/products/docker-desktop/) i upewnij się, że po uruchomieniu ikonka wieloryba w pasku zadań jest aktywna.

2. **Pobierz projekt**
   - Otwórz terminal (PowerShell, Terminal macOS lub terminal w VS Code).
   - Przejdź do folderu, w którym chcesz pracować (np. `cd C:\Users\TwojeImie\Projekty`).
   - Sklonuj repozytorium (`git clone ...`) albo skopiuj katalog projektu w inne miejsce.

3. **Zainstaluj biblioteki projektu**
   - W terminalu wejdź do folderu repozytorium (`cd Portfolio-Jakub-Smolinski`).
   - Wpisz `pnpm install` i poczekaj, aż pobieranie paczek się zakończy (może to potrwać kilka minut przy pierwszym uruchomieniu).

4. **Uruchom usługi pomocnicze**
   - Nadal w tym samym terminalu wpisz `docker compose up -d`.
   - Po chwili polecenie zwróci prompt – oznacza to, że Postgres, Redis i MinIO działają w tle.

5. **Skonfiguruj zmienne środowiskowe i bazę**
   - Wpisz po kolei:

     ```bash
     cd apps/web
     cp .env.example .env
     cd ../..
     pnpm db:push
     pnpm db:seed
     ```

   - Komendy `db:push` i `db:seed` tworzą strukturę bazy danych oraz dodają konto testowe. Poczekaj, aż każda zakończy się komunikatem „Done”.

6. **Uruchom aplikację**
   - Otwórz **nowe** okno terminala lub kartę w VS Code (pierwsze okno zostaw w spokoju).
   - W pierwszym terminalu uruchom serwer: `pnpm dev`.
   - W drugim terminalu uruchom worker kolejkowy: `pnpm worker`.
   - Oba procesy powinny działać równolegle; nie zamykaj okien.

7. **Wejdź do aplikacji**
   - W przeglądarce przejdź na `http://localhost:3000`.
   - Zaloguj się przy użyciu danych: `demo@voxbook.local` / `password123`.
   - Po zalogowaniu zobaczysz przykładowy model głosu i dokument – możesz od razu przejść do panelu i mini-odtwarzacza.

8. **Zatrzymanie pracy (opcjonalnie)**
   - Aby przerwać aplikację, użyj skrótu `Ctrl+C` w obu terminalach.
   - Aby zatrzymać usługi Docker, wpisz `docker compose down` w terminalu z katalogu projektu.

## Konta testowe

Po wykonaniu seedów dostępny jest użytkownik:

- Email: `demo@voxbook.local`
- Hasło: `password123`

Konto posiada przykładowy model głosu (MockTtsEngine) oraz dokument „VoxBook Demo Manual”.

## Najważniejsze funkcje

- **Rejestracja i logowanie** z tokenami JWT przechowywanymi w ciasteczkach httpOnly.
- **Panel głosu**:
  - upload 3–10 próbek audio (walidacja formatu i długości),
  - kolejka BullMQ z podglądem statusu treningu (queued/running/succeeded/failed),
  - MockTtsEngine działa natychmiast, ExternalTtsEngine można podpiąć przez zmienne środowiskowe.
- **Biblioteka PDF**:
  - upload do 200 MB, ekstrakcja tekstu przy użyciu `pdf-parse`, chunkowanie treści i zapis do bazy,
  - szybki podgląd, wyszukiwalność, rozdziały na podstawie chunków.
- **Audiobook Live**:
  - mini-odtwarzacz dokowany (play/pause, seek do kolejnego chunku, tempo, głośność, tryb live),
  - streaming audio przez HTTP chunked, lazy prefetch kolejnych fragmentów,
  - napisy z przybliżonymi timestampami,
  - zapamiętywanie postępu w `PlaybackState` i wznowienie po odświeżeniu.
- **Zgody i prywatność**: przed treningiem wymagane potwierdzenie prawa do próbek i tekstów.

## Zmienne środowiskowe

`apps/web/.env.example` zawiera kompletny zestaw zmiennych:

- `DATABASE_URL` – połączenie z PostgreSQL,
- `REDIS_URL` – adres brokera BullMQ,
- `S3_*` – konfiguracja kompatybilna z MinIO,
- `JWT_SECRET` – klucz do podpisywania sesji,
- `FEATURE_EXTERNAL_TTS`, `EXTERNAL_TTS_API_*` – integracja z zewnętrznym silnikiem TTS,
- `FEATURE_OCR` – flaga pod przyszły fallback OCR.

## Testy i jakość

```bash
pnpm lint     # linting Next.js
pnpm test     # testy jednostkowe (Vitest: chunkowanie PDF, kolejka odtwarzania)
```

## Dalszy rozwój

- Implementacja OCR (np. Tesseract) jako fallback przy braku tekstu w PDF.
- Rozszerzenie mini-playera o wizualizację bufora (IndexedDB) i cross-fade między chunkami.
- Podłączenie realnego silnika klonowania głosu poprzez `ExternalTtsEngine`.
- Automatyczne skalowanie workerów BullMQ.

Miłej pracy z VoxBook! Jeśli masz pytania – śmiało rozwijaj projekt dalej. 💬
