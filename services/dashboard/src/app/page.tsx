"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Play, ShieldCheck, AlertTriangle, Bug, Server, Clock, Activity, StopCircle } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { ScanModal } from "@/components/ScanModal";
import { Button } from "@/components/ui/button";

export default function Dashboard() {
  const [scans, setScans] = useState<any[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchScans = async () => {
    try {
      const res = await fetch("/api/v1/scans");
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
      }
    } catch (err) {
      console.error("Failed to poll scans:", err);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, []);

  // Calculate metrics
  const activeScans = scans.filter(s => s.status === "PENDING" || s.status === "RUNNING").length;
  const totalFindings = scans.reduce((acc, scan) => acc + (scan.stats?.vulnerabilities_found || 0), 0);
  const totalRequests = scans.reduce((acc, scan) => acc + (scan.stats?.total_requests_sent || 0), 0);

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in duration-500">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Security Overview</h1>
          <p className="text-zinc-400 mt-1">Real-time dynamic analysis metrics and active assessments.</p>
        </div>
        <Button onClick={() => setIsModalOpen(true)} className="gap-2">
          <Play className="w-4 h-4 fill-current" />
          New Assessment
        </Button>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        <MetricCard 
          title="Active Scans" 
          value={activeScans.toString()} 
          icon={<Activity className="text-brand-400 w-5 h-5" />}
          trend="Currently running"
          color="brand"
        />
        <MetricCard 
          title="Vulnerabilities Found" 
          value={totalFindings.toString()} 
          icon={<Bug className="text-accent-rose w-5 h-5" />}
          trend="Across all targets"
          color="rose"
        />
        <MetricCard 
          title="Total Requests Sent" 
          value={totalRequests.toLocaleString()} 
          icon={<Server className="text-accent-teal w-5 h-5" />}
          trend="Payloads delivered"
          color="teal"
        />
        <MetricCard 
          title="Engine Status" 
          value="Healthy" 
          icon={<ShieldCheck className="text-emerald-400 w-5 h-5" />}
          trend="All workers online"
          color="emerald"
        />
      </div>

      {/* Recent Scans */}
      <div className="glass-panel overflow-hidden">
        <div className="p-6 border-b border-white/5 flex justify-between items-center">
          <h3 className="text-lg font-semibold text-white">Recent Assessments</h3>
          <button className="text-sm text-brand-400 hover:text-brand-300 font-medium">View All</button>
        </div>
        
        {scans.length === 0 ? (
          <div className="p-12 text-center flex flex-col items-center justify-center">
            <div className="w-16 h-16 rounded-full bg-dark-800 border border-white/5 flex items-center justify-center mb-4">
              <ShieldCheck className="w-8 h-8 text-zinc-600" />
            </div>
            <h4 className="text-zinc-200 font-medium mb-1">No assessments yet</h4>
            <p className="text-zinc-500 text-sm max-w-md">Launch your first DAST assessment to start discovering vulnerabilities in your web applications.</p>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {scans.slice(0, 5).map((scan) => (
              <Link key={scan.id} href={`/scans/${scan.id}`} className="block p-4 sm:p-6 hover:bg-white/[0.04] transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4 cursor-pointer group">
                <div className="flex items-start gap-4">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border transition-colors ${
                    scan.status === 'RUNNING' ? 'bg-brand-500/10 border-brand-500/30 group-hover:bg-brand-500/20' : 
                    scan.status === 'COMPLETED' ? 'bg-emerald-500/10 border-emerald-500/30 group-hover:bg-emerald-500/20' : 
                    scan.status === 'FAILED' ? 'bg-accent-rose/10 border-accent-rose/30 group-hover:bg-accent-rose/20' : 
                    'bg-zinc-500/10 border-zinc-500/30 group-hover:bg-zinc-500/20'
                  }`}>
                    {scan.status === 'RUNNING' ? <Activity className="w-5 h-5 text-brand-400 animate-pulse" /> :
                     scan.status === 'COMPLETED' ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> :
                     scan.status === 'FAILED' ? <AlertTriangle className="w-5 h-5 text-accent-rose" /> :
                     <Clock className="w-5 h-5 text-zinc-400" />}
                  </div>
                  <div>
                    <h4 className="text-zinc-100 font-medium group-hover:text-brand-300 transition-colors">{scan.target_url}</h4>
                    <div className="flex items-center gap-3 mt-1 text-xs text-zinc-500">
                      <span className="group-hover:text-zinc-400 transition-colors">{scan.id.split('-')[0]}</span>
                      <span className="w-1 h-1 rounded-full bg-zinc-700" />
                      <span>{formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}</span>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center gap-6 sm:ml-auto">
                  <div className="text-right">
                    <p className="text-xs text-zinc-500 mb-1">Vulnerabilities</p>
                    <p className={`font-semibold ${scan.stats?.vulnerabilities_found > 0 ? 'text-accent-rose' : 'text-emerald-400'}`}>
                      {scan.stats?.vulnerabilities_found || 0}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-zinc-500 mb-1">Endpoints</p>
                    <p className="font-semibold text-zinc-200">{scan.stats?.endpoints_discovered || 0}</p>
                  </div>
                  <div className="w-24 text-right flex items-center justify-end gap-2">
                    <span className={`inline-flex px-2.5 py-1 rounded-full text-xs font-medium border ${
                      scan.status === 'RUNNING' ? 'bg-brand-500/10 text-brand-400 border-brand-500/20' : 
                      scan.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 
                      scan.status === 'FAILED' ? 'bg-accent-rose/10 text-accent-rose border-accent-rose/20' : 
                      'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
                    }`}>
                      {scan.status}
                    </span>
                    {(scan.status === 'RUNNING' || scan.status === 'PENDING') && (
                      <button 
                        onClick={async (e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          try {
                            await fetch(`/api/v1/scans/${scan.id}/abort`, { method: 'POST' });
                            fetchScans();
                          } catch (err) {
                            console.error(err);
                          }
                        }}
                        className="px-3 py-1 rounded bg-accent-rose/10 text-accent-rose hover:bg-accent-rose/20 text-xs font-medium transition-colors"
                        title="Abort Scan"
                      >
                        Stop
                      </button>
                    )}
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>

      <ScanModal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        onSuccess={fetchScans}
      />
    </div>
  );
}

import { Card, CardContent } from "@/components/ui/card";

function MetricCard({ title, value, icon, trend, color }: { title: string, value: string, icon: React.ReactNode, trend: string, color: 'brand' | 'emerald' | 'rose' | 'teal' }) {
  const bgColors = {
    brand: "bg-brand-500/10",
    emerald: "bg-emerald-500/10",
    rose: "bg-accent-rose/10",
    teal: "bg-accent-teal/10",
  };

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex justify-between items-start mb-4">
          <div className={`p-3 rounded-xl ${bgColors[color]}`}>
            {icon}
          </div>
        </div>
        <div>
          <h4 className="text-zinc-400 text-sm font-medium mb-1">{title}</h4>
          <h2 className="text-3xl font-bold text-white tracking-tight mb-2">{value}</h2>
          <p className="text-xs text-zinc-500">{trend}</p>
        </div>
      </CardContent>
    </Card>
  );
}
