"use client";

import { Bell, Search, Menu } from "lucide-react";

export function TopBar() {
  return (
    <header className="h-16 border-b border-white/5 bg-dark-900/30 backdrop-blur-md flex items-center justify-between px-8 z-10 sticky top-0">
      <div className="flex items-center flex-1">
        <button className="md:hidden mr-4 text-zinc-400 hover:text-white">
          <Menu className="w-5 h-5" />
        </button>
        <div className="relative w-96 hidden md:block">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input 
            type="text" 
            placeholder="Search scans, vulnerabilities, or endpoints..." 
            className="w-full bg-dark-800/50 border border-white/10 rounded-lg pl-10 pr-4 py-2 text-sm text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-brand-500/50 focus:ring-1 focus:ring-brand-500/50 transition-all"
          />
        </div>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          Engine Online
        </div>
        <button className="relative p-2 text-zinc-400 hover:text-white transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-accent-rose shadow-[0_0_8px_rgba(244,63,94,0.8)] border border-dark-900" />
        </button>
      </div>
    </header>
  );
}
