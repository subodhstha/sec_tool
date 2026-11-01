"use client";

import { useState } from "react";
import { Shield, X, Rocket, ShieldAlert, SlidersHorizontal, Activity, Info, Network, Gauge } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

function InfoTooltip({ text }: { text: string }) {
  return (
    <div className="group relative ml-auto flex items-center">
      <Info className="w-4 h-4 text-zinc-500 cursor-help hover:text-zinc-300 transition-colors" />
      <div className="pointer-events-none absolute bottom-full right-0 sm:-translate-x-1/2 sm:right-auto sm:left-1/2 mb-2 w-56 opacity-0 translate-y-1 group-hover:opacity-100 group-hover:translate-y-0 transition-all duration-200 z-[100] bg-zinc-800 border border-white/10 rounded-lg p-3 text-xs text-zinc-200 shadow-xl leading-relaxed text-center font-normal tracking-wide">
        {text}
        <div className="absolute top-full right-2 sm:right-auto sm:left-1/2 sm:-translate-x-1/2 -mt-[1px] border-[6px] border-transparent border-t-white/10">
          <div className="absolute -top-[7px] -left-[5px] border-[5px] border-transparent border-t-zinc-800" />
        </div>
      </div>
    </div>
  );
}

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function ScanModal({ isOpen, onClose, onSuccess }: ScanModalProps) {
  const [targetUrl, setTargetUrl] = useState("");
  const [safeMode, setSafeMode] = useState(true);
  const [maxRps, setMaxRps] = useState(20);
  const [consecutive5xxCap, setConsecutive5xxCap] = useState(5);
  const [maxDepth, setMaxDepth] = useState(3);
  const [baselineLatency, setBaselineLatency] = useState(250);
  const [verificationToken, setVerificationToken] = useState("vyomite-dev-token");
  const [targetCategories, setTargetCategories] = useState<string[]>([]);
  const [payloadProfile, setPayloadProfile] = useState("STANDARD");
  const [activeFuzzing, setActiveFuzzing] = useState(false);
  const [maxConcurrency, setMaxConcurrency] = useState(10);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/v1/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: targetUrl,
          scan_name: `Assessment-${new Date().toLocaleTimeString()}`,
          config: {
            safe_mode: safeMode,
            max_rps: Number(maxRps),
            max_concurrency: Number(maxConcurrency),
            max_depth: Number(maxDepth),
            verification_token: verificationToken,
            baseline_latency_ms: Number(baselineLatency),
            consecutive_5xx_cap: Number(consecutive5xxCap),
            active_fuzzing: activeFuzzing,
            payload_profile: payloadProfile,
            target_categories: targetCategories.length > 0 ? targetCategories : undefined,
          },
        }),
      });

      if (!res.ok) {
        const contentType = res.headers.get("content-type");
        let errorMessage = "Failed to dispatch scan";
        if (contentType && contentType.includes("application/json")) {
          const errData = await res.json();
          errorMessage = errData.details || errData.error || errorMessage;
        } else {
          errorMessage = await res.text();
        }
        throw new Error(errorMessage);
      }

      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="w-full max-w-2xl bg-dark-900 border border-white/10 rounded-2xl shadow-2xl overflow-hidden flex flex-col animate-in zoom-in-95 duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-center px-6 py-5 border-b border-white/5 bg-dark-800/50">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-500/20 border border-brand-500/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-brand-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-white">Configure New DAST Assessment</h2>
              <p className="text-sm text-zinc-400">Launch a dynamic scan against your target application</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-zinc-400 hover:text-white hover:bg-white/5 rounded-lg transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto max-h-[70vh]">
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-accent-rose/10 border border-accent-rose/20 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-accent-rose shrink-0 mt-0.5" />
              <div className="text-sm text-accent-rose/90 font-medium whitespace-pre-wrap">{error}</div>
            </div>
          )}

          <div className="space-y-6">
            {/* Target URL */}
            <div>
              <label className="block text-sm font-medium text-zinc-300 mb-2">Target Web URL</label>
              <input
                type="url"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://staging.internal.vyomite.com"
                className="w-full bg-dark-800 border border-white/10 rounded-xl px-4 py-3 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-all"
              />
            </div>

            {/* Verification Token */}
            <div>
              <label className="block text-sm font-medium text-zinc-300 mb-2">Domain Verification Token (FR-4.1)</label>
              <input
                type="text"
                required
                value={verificationToken}
                onChange={(e) => setVerificationToken(e.target.value)}
                className="w-full bg-dark-800 border border-white/10 rounded-xl px-4 py-3 text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-all font-mono text-sm"
              />
              <p className="mt-2 text-xs text-zinc-500">Must match DNS TXT or <code className="text-brand-400">/.well-known/vyomite-verification.txt</code></p>
            </div>

            {/* Advanced Metrics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-5 p-5 rounded-xl border border-white/5 bg-dark-800/30">
              <div>
                <label className="flex items-center text-sm font-medium text-zinc-300 mb-2">
                  <Activity className="w-4 h-4 text-zinc-400 mr-2" /> Max Requests / Sec
                  <InfoTooltip text="Limits the maximum injection rate to prevent overwhelming the target." />
                </label>
                <input
                  type="number"
                  min="1" max="200"
                  value={maxRps}
                  onChange={(e) => setMaxRps(Number(e.target.value))}
                  className="w-full bg-dark-900 border border-white/10 rounded-lg px-3 py-2.5 text-zinc-200 focus:outline-none focus:border-brand-500 transition-all"
                />
              </div>
              <div>
                <label className="flex items-center text-sm font-medium text-zinc-300 mb-2">
                  <SlidersHorizontal className="w-4 h-4 text-zinc-400 mr-2" /> 5xx Circuit Breaker Cap
                  <InfoTooltip text="Automatically pauses the scan if this many consecutive 5xx server errors occur, protecting target stability." />
                </label>
                <input
                  type="number"
                  min="1" max="20"
                  value={consecutive5xxCap}
                  onChange={(e) => setConsecutive5xxCap(Number(e.target.value))}
                  className="w-full bg-dark-900 border border-white/10 rounded-lg px-3 py-2.5 text-zinc-200 focus:outline-none focus:border-brand-500 transition-all"
                />
              </div>
              <div>
                <label className="flex items-center text-sm font-medium text-zinc-300 mb-2">
                  <Network className="w-4 h-4 text-zinc-400 mr-2" /> Crawl Depth Limit
                  <InfoTooltip text="Maximum depth the crawler will traverse from the base URL." />
                </label>
                <input
                  type="number"
                  min="1" max="10"
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(Number(e.target.value))}
                  className="w-full bg-dark-900 border border-white/10 rounded-lg px-3 py-2.5 text-zinc-200 focus:outline-none focus:border-brand-500 transition-all"
                />
              </div>
              <div>
                <label className="flex items-center text-sm font-medium text-zinc-300 mb-2">
                  <Gauge className="w-4 h-4 text-zinc-400 mr-2" /> Baseline Latency (ms)
                  <InfoTooltip text="Normal expected response time of the target. Used to accurately detect time-based blind vulnerabilities (e.g. Blind SQLi)." />
                </label>
                <input
                  type="number"
                  min="50" max="5000"
                  value={baselineLatency}
                  onChange={(e) => setBaselineLatency(Number(e.target.value))}
                  className="w-full bg-dark-900 border border-white/10 rounded-lg px-3 py-2.5 text-zinc-200 focus:outline-none focus:border-brand-500 transition-all"
                />
              </div>
              <div>
                <label className="flex items-center text-sm font-medium text-zinc-300 mb-2">
                  <Activity className="w-4 h-4 text-zinc-400 mr-2" /> Request Concurrency
                  <InfoTooltip text="Maximum number of payload requests the engine may execute in parallel for an endpoint." />
                </label>
                <input
                  type="number"
                  min="1" max="50"
                  value={maxConcurrency}
                  onChange={(e) => setMaxConcurrency(Number(e.target.value))}
                  className="w-full bg-dark-900 border border-white/10 rounded-lg px-3 py-2.5 text-zinc-200 focus:outline-none focus:border-brand-500 transition-all"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
              <div className="p-5 rounded-xl border border-white/5 bg-dark-800/30">
                <label className="block text-sm font-medium text-zinc-300 mb-2">Payload Safety Profile</label>
                <select
                  value={payloadProfile}
                  onChange={(e) => setPayloadProfile(e.target.value)}
                  className="w-full bg-dark-900 border border-white/10 rounded-lg px-3 py-2.5 text-zinc-200 focus:outline-none focus:border-brand-500 transition-all"
                >
                  <option value="PASSIVE">Passive</option>
                  <option value="LIGHT">Light</option>
                  <option value="STANDARD">Standard</option>
                  <option value="AGGRESSIVE">Aggressive</option>
                  <option value="FULL">Full</option>
                </select>
                <p className="mt-2 text-xs text-zinc-500">Controls active, time-based, OOB, and high-risk payloads.</p>
              </div>
              <label className={cn(
                "p-5 rounded-xl border transition-all cursor-pointer flex items-start gap-3",
                activeFuzzing ? "bg-accent-rose/10 border-accent-rose/30" : "bg-dark-800/30 border-white/5"
              )}>
                <input
                  type="checkbox"
                  checked={activeFuzzing}
                  onChange={(e) => setActiveFuzzing(e.target.checked)}
                  className="mt-1 w-4 h-4 rounded border-zinc-600 text-accent-rose focus:ring-accent-rose focus:ring-offset-dark-900"
                />
                <span>
                  <span className={cn("block text-sm font-medium", activeFuzzing ? "text-accent-rose" : "text-zinc-300")}>Enable active fuzzing</span>
                  <span className="block mt-1 text-xs text-zinc-500">Allows non-safe time-based, OOB, and exploitation probes.</span>
                </span>
              </label>
            </div>

            {/* Target Attack Categories */}
            <div className="p-5 rounded-xl border border-white/5 bg-dark-800/30">
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-zinc-300">Target Attack Categories</label>
                <div className="text-xs font-medium text-zinc-500 flex items-center gap-1">
                  <Info className="w-3.5 h-3.5" /> Leave empty to run ALL payloads
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {["SQLI", "XSS", "CMDI", "SSRF", "XXE", "SSTI", "NOSQLI", "CORS", "CSRF", "JWT", "IDOR", "GRAPHQL", "FILE_INCLUSION", "FILE_UPLOAD", "OPEN_REDIRECT"].map(cat => (
                  <button
                    key={cat}
                    type="button"
                    onClick={(e) => {
                      e.preventDefault();
                      if (targetCategories.includes(cat)) {
                        setTargetCategories(targetCategories.filter(c => c !== cat));
                      } else {
                        setTargetCategories([...targetCategories, cat]);
                      }
                    }}
                    className={cn(
                      "px-3 py-1.5 rounded-lg text-xs font-bold border transition-all",
                      targetCategories.includes(cat)
                        ? "bg-brand-500/20 border-brand-500/40 text-brand-400 shadow-[0_0_10px_rgba(var(--brand-500),0.2)]"
                        : "bg-dark-900/50 border-white/10 text-zinc-400 hover:border-white/20 hover:text-zinc-200 hover:bg-dark-800"
                    )}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Safe Mode Toggle */}
            <div 
              className={cn(
                "p-4 rounded-xl border transition-all cursor-pointer flex items-start gap-4",
                safeMode ? "bg-brand-500/10 border-brand-500/30" : "bg-dark-800/50 border-white/5"
              )}
              onClick={() => setSafeMode(!safeMode)}
            >
              <div className="pt-1">
                <input 
                  type="checkbox" 
                  checked={safeMode} 
                  onChange={(e) => setSafeMode(e.target.checked)}
                  className="w-5 h-5 rounded border-zinc-600 text-brand-500 focus:ring-brand-500 focus:ring-offset-dark-900"
                  onClick={(e) => e.stopPropagation()}
                />
              </div>
              <div>
                <h4 className={cn("font-medium", safeMode ? "text-brand-300" : "text-zinc-300")}>
                  Safe Mode: Destructive HTTP Filter (FR-4.2)
                </h4>
                <p className="text-sm text-zinc-500 mt-1">
                  Unconditionally drops DELETE requests and regex-matches for /delete, /purge, /drop to prevent accidental data loss in production.
                </p>
              </div>
            </div>
          </div>
          
          <div className="mt-8 flex justify-end gap-3 pt-6 border-t border-white/5">
            <Button variant="ghost" type="button" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={loading || !targetUrl}
              className="gap-2"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <Rocket className="w-4 h-4" />
              )}
              {loading ? "Dispatching..." : "Launch Assessment"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
