"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Bug, Search, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";

type Finding = {
  id: string;
  scan_id: string;
  title: string;
  category: string;
  severity?: string;
  cvss_score?: number;
  target_url: string;
  affected_parameter?: string;
  description?: string;
};

const severityStyles: Record<string, string> = {
  CRITICAL: "bg-red-500/10 text-red-300 border-red-500/20",
  HIGH: "bg-accent-rose/10 text-accent-rose border-accent-rose/20",
  MEDIUM: "bg-accent-amber/10 text-accent-amber border-accent-amber/20",
  LOW: "bg-blue-500/10 text-blue-300 border-blue-500/20",
  INFO: "bg-zinc-500/10 text-zinc-300 border-zinc-500/20",
};

export default function VulnerabilitiesPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadFindings = async () => {
      try {
        const scansResponse = await fetch("/api/v1/scans");
        if (!scansResponse.ok) return;
        const { scans = [] } = await scansResponse.json();
        const resultSets = await Promise.all(
          scans.map(async (scan: { id: string }) => {
            const response = await fetch(`/api/v1/scans/${scan.id}/results`);
            if (!response.ok) return [];
            const data = await response.json();
            return (data.findings || []).map((finding: Finding) => ({ ...finding, scan_id: scan.id }));
          }),
        );
        const unique = new Map<string, Finding>();
        resultSets.flat().forEach((finding) => {
          unique.set(finding.id || `${finding.scan_id}-${finding.title}-${finding.target_url}`, finding);
        });
        setFindings(Array.from(unique.values()));
      } catch (error) {
        console.error("Failed to load vulnerabilities:", error);
      } finally {
        setLoading(false);
      }
    };

    loadFindings();
  }, []);

  const filteredFindings = useMemo(() => {
    const query = search.toLowerCase();
    return findings.filter((finding) => {
      const matchesSeverity = severity === "ALL" || finding.severity === severity;
      const haystack = `${finding.title} ${finding.category} ${finding.target_url} ${finding.affected_parameter || ""}`.toLowerCase();
      return matchesSeverity && haystack.includes(query);
    });
  }, [findings, search, severity]);

  const criticalCount = findings.filter((finding) => finding.severity === "CRITICAL").length;
  const highCount = findings.filter((finding) => finding.severity === "HIGH").length;

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in duration-500 pb-12">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Vulnerabilities</h1>
          <p className="text-zinc-400 mt-2">Review findings across every assessment and jump to the evidence.</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <span className="text-red-300">{criticalCount} critical</span>
          <span>·</span>
          <span className="text-accent-rose">{highCount} high</span>
        </div>
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="p-5 border-b border-white/5 flex flex-col lg:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search title, category, target, or parameter..."
              className="w-full bg-dark-800 border border-white/10 rounded-lg pl-10 pr-4 py-2.5 text-sm text-zinc-200 focus:outline-none focus:border-brand-500/50"
            />
          </div>
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            className="bg-dark-800 border border-white/10 rounded-lg px-3 py-2.5 text-sm text-zinc-200 focus:outline-none focus:border-brand-500/50"
          >
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {loading ? (
          <div className="p-16 text-center text-zinc-500">Loading findings...</div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-16 text-center flex flex-col items-center">
            {findings.length === 0 ? <ShieldCheck className="w-10 h-10 text-emerald-400 mb-4" /> : <AlertTriangle className="w-10 h-10 text-zinc-600 mb-4" />}
            <p className="text-zinc-300 font-medium">{findings.length === 0 ? "No vulnerabilities detected" : "No findings match this filter"}</p>
          </div>
        ) : (
          <div className="divide-y divide-white/5">
            {filteredFindings.map((finding) => {
              const level = finding.severity || "INFO";
              return (
                <div key={finding.id || `${finding.scan_id}-${finding.title}`} className="p-5 hover:bg-white/[0.02] transition-colors">
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <Bug className="w-4 h-4 text-accent-rose" />
                        <h2 className="text-zinc-100 font-semibold">{finding.title || finding.category}</h2>
                        <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${severityStyles[level] || severityStyles.INFO}`}>{level}</span>
                      </div>
                      <p className="text-sm text-zinc-400 line-clamp-2">{finding.description || finding.category}</p>
                      <div className="flex flex-wrap gap-2 mt-3 text-xs text-zinc-500">
                        <span className="font-mono">{finding.category}</span>
                        <span>·</span>
                        <span className="truncate max-w-xl">{finding.target_url}</span>
                        {finding.affected_parameter && <><span>·</span><span>Param: {finding.affected_parameter}</span></>}
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {finding.cvss_score ? <span className="text-xs text-zinc-400">CVSS {finding.cvss_score}</span> : null}
                      <Link href={`/scans/${finding.scan_id}`}>
                        <Button variant="outline" size="sm">View scan</Button>
                      </Link>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
