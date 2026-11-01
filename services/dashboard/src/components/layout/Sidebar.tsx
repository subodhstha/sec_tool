"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ShieldAlert, LayoutDashboard, Settings, Code, FileKey } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Active Scans", href: "/scans", icon: Activity },
  { name: "Vulnerabilities", href: "/vulnerabilities", icon: ShieldAlert },
  { name: "API Keys", href: "/keys", icon: FileKey },
  { name: "Integrations", href: "/integrations", icon: Code },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 h-screen border-r border-white/5 bg-dark-900/50 backdrop-blur-2xl flex flex-col">
      <div className="h-16 flex items-center px-6 border-b border-white/5">
        <ShieldAlert className="w-6 h-6 text-brand-500 mr-3" />
        <span className="font-bold text-xl tracking-tight text-white">Vyomite<span className="text-brand-500">DAST</span></span>
      </div>
      
      <div className="flex-1 py-6 px-4 space-y-1 overflow-y-auto">
        <div className="text-xs font-semibold text-dark-500 uppercase tracking-wider mb-4 px-2">Navigation</div>
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group",
                isActive 
                  ? "bg-brand-500/10 text-brand-400" 
                  : "text-zinc-400 hover:bg-white/5 hover:text-zinc-200"
              )}
            >
              <item.icon className={cn(
                "w-5 h-5 mr-3 transition-colors", 
                isActive ? "text-brand-400" : "text-zinc-500 group-hover:text-zinc-300"
              )} />
              {item.name}
              {isActive && (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-brand-500 shadow-[0_0_8px_rgba(99,102,241,0.8)]" />
              )}
            </Link>
          );
        })}
      </div>

      <div className="p-4 mt-auto border-t border-white/5">
        <div className="flex items-center p-3 rounded-xl bg-dark-800/50 border border-white/5 cursor-pointer hover:bg-dark-800 transition-colors">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-brand-500 to-accent-teal flex items-center justify-center text-white font-bold text-sm shadow-lg">
            JD
          </div>
          <div className="ml-3 overflow-hidden">
            <p className="text-sm font-medium text-zinc-200 truncate">John Doe</p>
            <p className="text-xs text-zinc-500 truncate">Admin / Architect</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
