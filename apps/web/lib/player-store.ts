import { create } from "zustand";

export interface TranscriptEntry {
  startMs: number;
  endMs: number;
  text: string;
}

export interface PlayerState {
  documentId?: string;
  modelId?: string;
  currentOrder: number;
  isPlaying: boolean;
  liveMode: boolean;
  speed: number;
  volume: number;
  audioUrl?: string;
  transcript: TranscriptEntry[];
  bufferedOrders: number[];
  setDocument(documentId: string, modelId: string): void;
  setOrder(order: number): void;
  setAudio(url: string, transcript: TranscriptEntry[]): void;
  togglePlay(): void;
  setPlaying(isPlaying: boolean): void;
  setSpeed(speed: number): void;
  setVolume(volume: number): void;
  setLiveMode(live: boolean): void;
  markBuffered(order: number): void;
}

export const usePlayerStore = create<PlayerState>((set) => ({
  currentOrder: 0,
  isPlaying: false,
  liveMode: true,
  speed: 1,
  volume: 0.8,
  transcript: [],
  bufferedOrders: [],
  setDocument: (documentId, modelId) =>
    set(() => ({ documentId, modelId, currentOrder: 0, bufferedOrders: [] })),
  setOrder: (order) => set(() => ({ currentOrder: order })),
  setAudio: (audioUrl, transcript) => set(() => ({ audioUrl, transcript })),
  togglePlay: () => set((state) => ({ isPlaying: !state.isPlaying })),
  setPlaying: (isPlaying) => set(() => ({ isPlaying })),
  setSpeed: (speed) => set(() => ({ speed })),
  setVolume: (volume) => set(() => ({ volume })),
  setLiveMode: (liveMode) => set(() => ({ liveMode })),
  markBuffered: (order) =>
    set((state) => ({
      bufferedOrders: state.bufferedOrders.includes(order)
        ? state.bufferedOrders
        : [...state.bufferedOrders, order]
    }))
}));
