import "./globals.css";
import type { ReactNode } from "react";
import { Inter } from "next/font/google";
import { MiniPlayer } from "@/components/player/mini-player";

const inter = Inter({ subsets: ["latin"] });

export const metadata = {
  title: "VoxBook",
  description: "Personalised AI voice reader"
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="pl" className="h-full">
      <body className={`${inter.className} min-h-screen bg-slate-50`}> 
        <div className="min-h-screen pb-32">
          {children}
        </div>
        <MiniPlayer />
      </body>
    </html>
  );
}
