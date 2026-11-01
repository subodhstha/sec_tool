"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, Search, ShieldCheck } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

export default function ScansPage() {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const fetchScans = async () => {
      try {
        const res = await fetch('/api/v1/scans');
        if (res.ok) {
          const data = await res.json();
          setScans(data.scans || []);
        }
      } catch (err) {
        console.error("Failed to load scans:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchScans();
  }, []);

  const filteredScans = scans.filter(s => s.target_url.toLowerCase().includes(search.toLowerCase()) || s.id.includes(search));

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in duration-500 pb-12">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Active Scans</h1>
          <p className="text-zinc-400 mt-2">Manage and monitor all your DAST assessments in one place.</p>
        </div>
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="p-6 border-b border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="relative max-w-md w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input 
              type="text" 
              placeholder="Search by URL or ID..." 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-dark-800 border border-white/10 rounded-lg pl-10 pr-4 py-2.5 text-sm text-zinc-200 focus:outline-none focus:border-brand-500/50 transition-colors"
            />
          </div>
        </div>

        {loading ? (
          <div className="p-12 text-center text-zinc-500 flex flex-col items-center">
            <div className="w-8 h-8 border-2 border-brand-500/20 border-t-brand-500 rounded-full animate-spin mb-4" />
            Loading assessments...
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="p-16 text-center text-zinc-500">
            No scans found matching your criteria.
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {filteredScans.map(scan => (
              <Link key={scan.id} href={`/scans/${scan.id}`} className="block p-6 hover:bg-white/[0.02] transition-colors cursor-pointer group">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-xl border flex items-center justify-center transition-transform group-hover:scale-105 ${
                      scan.status === 'RUNNING' ? 'bg-brand-500/10 border-brand-500/20 text-brand-400' :
                      scan.status === 'COMPLETED' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                      scan.status === 'FAILED' ? 'bg-accent-rose/10 border-accent-rose/20 text-accent-rose' :
                      'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                    }`}>
                      {scan.status === 'RUNNING' ? <Activity className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                    </div>
                    <div>
                      <h3 className="text-zinc-100 font-semibold group-hover:text-brand-300 transition-colors">{scan.target_url}</h3>
                      <p className="text-xs text-zinc-500 font-mono mt-1">{scan.id} &bull; {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <p className="text-xs text-zinc-500 mb-1">Vulnerabilities</p>
                      <p className="text-lg font-bold text-accent-rose">{scan.stats?.vulnerabilities_found || 0}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-zinc-500 mb-1">Endpoints</p>
                      <p className="text-lg font-bold text-zinc-300">{scan.stats?.endpoints_discovered || 0}</p>
                    </div>
                    <span className={`px-3 py-1 text-xs font-bold rounded-full uppercase tracking-wider ${
                      scan.status === 'RUNNING' ? 'bg-brand-500/10 text-brand-400' :
                      scan.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400' :
                      scan.status === 'FAILED' ? 'bg-accent-rose/10 text-accent-rose' :
                      'bg-zinc-500/10 text-zinc-400'
                    }`}>
                      {scan.status}
                    </span>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
