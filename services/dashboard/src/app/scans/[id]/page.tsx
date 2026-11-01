"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, ShieldCheck, AlertTriangle, Bug, Server, Clock, Activity, ExternalLink, ShieldAlert, CheckCircle2, Code2, Database, Globe, Info } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function ScanDetail() {
  const params = useParams();
  const router = useRouter();
  const [scan, setScan] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchScanData = async () => {
      try {
        const id = params.id as string;
        
        // Fetch scan meta
        const metaRes = await fetch(`/api/v1/scans/${id}`);
        if (metaRes.ok) {
          const metaData = await metaRes.json();
          setScan(metaData);
        }

        // Fetch findings
        const findingsRes = await fetch(`/api/v1/scans/${id}/results`);
        if (findingsRes.ok) {
          const findingsData = await findingsRes.json();
          // Deduplicate based on dedup_hash or title+target_url
          const uniqueFindings = [];
          const seen = new Set();
          for (const f of (findingsData.findings || [])) {
            const hash = f.dedup_hash || `${f.title}-${f.target_url}-${f.category}`;
            if (!seen.has(hash)) {
              seen.add(hash);
              uniqueFindings.push(f);
            }
          }
          setFindings(uniqueFindings);
        }
      } catch (err) {
        console.error("Failed to load scan details:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchScanData();
  }, [params.id]);

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center h-full">
        <div className="flex flex-col items-center">
          <div className="w-10 h-10 border-4 border-brand-500/20 border-t-brand-500 rounded-full animate-spin mb-4" />
          <p className="text-zinc-400 font-medium">Loading Assessment Data...</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-center">
        <AlertTriangle className="w-12 h-12 text-zinc-500 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Assessment Not Found</h2>
        <p className="text-zinc-400 mb-6">The requested scan could not be located or has been deleted.</p>
        <Button onClick={() => router.push('/')} variant="outline">
          Return to Dashboard
        </Button>
      </div>
    );
  }

  const highSev = findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length;
  const medSev = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowSev = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFO' || f.severity === 'UNSURE' || !f.severity).length;

  const categoryMap: Record<string, string> = {
    "SQL_INJECTION": "SQLI",
    "TIME_BASED_BLIND_SQLI": "SQLI",
    "CROSS_SITE_SCRIPTING": "XSS",
    "SERVER_SIDE_REQUEST_FORGERY": "SSRF",
    "BLIND_SSRF_OOB": "SSRF",
    "COMMAND_INJECTION": "CMDI",
    "PATH_TRAVERSAL": "FILE_INCLUSION",
    "INFORMATION_DISCLOSURE": "INFO_DISCLOSURE",
    "XML_EXTERNAL_ENTITY": "XXE",
    "SERVER_SIDE_TEMPLATE_INJECTION": "SSTI",
    "OPEN_REDIRECT": "OPEN_REDIRECT",
    "HEADER_INJECTION": "HEADERS",
    "HOST_HEADER_INJECTION": "HEADERS",
    "NOSQL_INJECTION": "NOSQLI",
    "CORS_MISCONFIGURATION": "CORS",
    "CROSS_SITE_REQUEST_FORGERY": "CSRF",
    "INSECURE_DIRECT_OBJECT_REFERENCE": "IDOR",
    "JWT_VULNERABILITY": "JWT",
    "GRAPHQL_VULNERABILITY": "GRAPHQL",
    "FILE_UPLOAD_VULNERABILITY": "FILE_UPLOAD",
    "FILE_INCLUSION": "FILE_INCLUSION",
    "SECURITY_MISCONFIGURATION": "HEADERS",
    "SENSITIVE_DATA_EXPOSURE": "INFO_DISCLOSURE"
  };

  const ALL_CATEGORIES = ["SQLI", "XSS", "CMDI", "SSRF", "XXE", "SSTI", "NOSQLI", "CORS", "JWT", "CSRF", "IDOR", "GRAPHQL", "FILE_INCLUSION", "FILE_UPLOAD", "OPEN_REDIRECT", "HEADERS", "INFO_DISCLOSURE"];
  const runCategories = scan.config?.target_categories?.length > 0 ? scan.config.target_categories : ALL_CATEGORIES;
  const foundCategories = new Set(findings.flatMap((f: any) => {
    const cats = [categoryMap[f.category] || f.category];
    if (f.title && (f.title.includes('Header') || f.title.includes('CSP') || f.title.includes('Cache-Control') || f.title.includes('Cross-Origin') || f.title.includes('Cookie'))) {
      cats.push("HEADERS");
    }
    return cats;
  }));
  const passedCategories = runCategories.filter((cat: string) => !foundCategories.has(cat));

  const inferredFrameworks = new Set<string>(scan.fingerprint?.frameworks || []);
  const inferredLanguages = new Set<string>(scan.fingerprint?.languages || []);
  const inferredDatabases = new Set<string>(scan.fingerprint?.databases || []);

  findings.forEach((f: any) => {
    const text = ((f.title || '') + ' ' + (f.description || '') + ' ' + (f.category || '')).toLowerCase();
    if (text.includes('wordpress') || text.includes('wp-login') || text.includes('wp-admin')) inferredFrameworks.add('WordPress');
    if (text.includes('php') || f.occurrences?.some((o: any) => (o.target_url || o.proof?.request_url || '').includes('.php'))) inferredLanguages.add('PHP');
    if (text.includes('mysql') || text.includes('sql syntax')) inferredDatabases.add('MySQL');
    if (text.includes('postgresql')) inferredDatabases.add('PostgreSQL');
    if (text.includes('express')) inferredFrameworks.add('Express.js');
    if (text.includes('react')) inferredFrameworks.add('React');
    if (text.includes('mongodb') || text.includes('nosql')) inferredDatabases.add('MongoDB');
  });

  const finalFrameworks = Array.from(inferredFrameworks);
  const finalLanguages = Array.from(inferredLanguages);
  const finalDatabases = Array.from(inferredDatabases);
  const hasFingerprint = scan.fingerprint?.server_header || finalLanguages.length > 0 || finalFrameworks.length > 0 || finalDatabases.length > 0;

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-in fade-in duration-500 pb-12">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => router.push('/')}
            className="w-10 h-10 rounded-xl bg-dark-800 border border-white/5 flex items-center justify-center text-zinc-400 hover:text-white hover:bg-white/10 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-white tracking-tight">{scan.target_url}</h1>
              <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${
                scan.status === 'RUNNING' ? 'bg-brand-500/10 text-brand-400 border-brand-500/20' : 
                scan.status === 'COMPLETED' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 
                scan.status === 'FAILED' ? 'bg-accent-rose/10 text-accent-rose border-accent-rose/20' : 
                'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
              }`}>
                {scan.status}
              </span>
            </div>
            <p className="text-zinc-400 mt-1 flex items-center gap-2 text-sm">
              <span>ID: {scan.id}</span>
              <span className="w-1 h-1 rounded-full bg-zinc-700" />
              <span>Started {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}</span>
            </p>
          </div>
        </div>
        <div className="flex gap-3">
           <Button variant="outline" className="gap-2" onClick={() => window.open(`/api/v1/scans/${scan.id}/results?format=sarif`, '_blank')}>
             <ExternalLink className="w-4 h-4" /> Export SARIF
           </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Column: Stats & Tech Stack */}
        <div className="lg:col-span-1 space-y-6">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-400 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-accent-rose" /> Critical / High
              </CardTitle>
            </CardHeader>
            <CardContent>
              <h2 className="text-4xl font-bold text-white">{highSev}</h2>
            </CardContent>
          </Card>
          
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-accent-amber" /> Medium Risk
              </CardTitle>
            </CardHeader>
            <CardContent>
              <h2 className="text-4xl font-bold text-white">{medSev}</h2>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-400 flex items-center gap-2">
                <Info className="w-4 h-4 text-blue-400" /> Low / Info (Unsure)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <h2 className="text-4xl font-bold text-white">{lowSev}</h2>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-400 flex items-center gap-2">
                <Server className="w-4 h-4 text-brand-400" /> Endpoints Tested
              </CardTitle>
            </CardHeader>
            <CardContent>
              <h2 className="text-4xl font-bold text-white">{scan.stats?.endpoints_discovered || 0}</h2>
              <p className="text-xs text-zinc-500 mt-1">Average latency: {scan.stats?.average_latency_ms || 0}ms</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="border-b border-white/5 pb-4">
              <CardTitle className="text-sm text-zinc-300 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-brand-400" /> Scan Policy
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4 space-y-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-500">Payload profile</span>
                <span className="text-brand-300 font-semibold">{scan.config?.payload_profile || "Legacy"}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-500">Safe mode</span>
                <span className={scan.config?.safe_mode ? "text-emerald-400" : "text-accent-rose"}>{scan.config?.safe_mode ? "On" : "Off"}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-500">Active fuzzing</span>
                <span className={scan.config?.active_fuzzing ? "text-accent-amber" : "text-zinc-300"}>{scan.config?.active_fuzzing ? "On" : "Off"}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-500">Concurrency</span>
                <span className="text-zinc-200">{scan.config?.max_concurrency || 0}</span>
              </div>
              <div className="pt-2 border-t border-white/5">
                <span className="text-zinc-500 block mb-2">Categories</span>
                <div className="flex flex-wrap gap-1.5">
                  {scan.config?.target_categories?.length ? scan.config.target_categories.map((category: string) => (
                    <span key={category} className="px-2 py-0.5 bg-white/5 text-zinc-300 rounded text-xs border border-white/10">{category}</span>
                  )) : <span className="text-xs text-zinc-400">All registered payload families</span>}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Security Posture Check */}
          <Card className={findings.length > 0 ? "border-accent-rose/30 bg-accent-rose/5" : ""}>
            <CardHeader className="border-b border-white/5 pb-4">
              <CardTitle className={`text-sm flex items-center gap-2 ${findings.length > 0 ? 'text-accent-rose' : 'text-emerald-400'}`}>
                {findings.length > 0 ? <ShieldAlert className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />}
                {findings.length > 0 ? "Application Vulnerable" : "Secure Patterns Verified"}
              </CardTitle>
            </CardHeader>
            <CardContent className="pt-4">
              {findings.length > 0 && foundCategories.size > 0 && (
                <div className="mb-5">
                  <p className="text-xs text-accent-rose font-semibold mb-2">Vulnerabilities Detected In:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {Array.from(foundCategories).map((cat: string) => (
                      <span key={cat} className="px-2 py-0.5 rounded text-xs border bg-accent-rose/20 text-accent-rose border-accent-rose/50 shadow-[0_0_10px_rgba(244,63,94,0.3)] font-bold flex items-center gap-1.5">
                        <Bug className="w-3 h-3" /> {cat}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              <div>
                {findings.length > 0 && <p className="text-xs text-zinc-500 mb-2">Patterns Verified (Secure):</p>}
                <div className="flex flex-wrap gap-1.5">
                  {passedCategories.length > 0 ? (
                    passedCategories.map((cat: string) => (
                      <span key={cat} className={`px-2 py-0.5 rounded text-xs border ${
                        findings.length > 0 
                        ? "bg-emerald-500/5 text-emerald-500/50 border-emerald-500/10" 
                        : "bg-emerald-500/10 text-emerald-300 border-emerald-500/20 shadow-[0_0_10px_rgba(16,185,129,0.1)]"
                      }`}>
                        {cat}
                      </span>
                    ))
                  ) : (
                    <p className="text-xs text-zinc-500">No categories completely passed.</p>
                  )}
                </div>
              </div>

              <p className={`text-[10px] mt-4 leading-relaxed ${findings.length > 0 ? 'text-accent-rose/70' : 'text-zinc-500'}`}>
                {findings.length === 0 
                  ? "These vulnerability categories were actively tested and no weaknesses were detected. Good job!"
                  : "The verified categories passed, but the application is NOT secure. Please review the findings panel for detected vulnerabilities."}
              </p>
            </CardContent>
          </Card>

          {/* Tech Stack Fingerprint */}
          {hasFingerprint && (
            <Card>
              <CardHeader className="border-b border-white/5 pb-4">
                <CardTitle className="text-sm text-white flex items-center gap-2">
                  <Globe className="w-4 h-4" /> Detected Tech Stack
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4 space-y-4">
                {scan.fingerprint?.server_header && (
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Server</p>
                    <p className="text-sm text-zinc-200 font-medium">{scan.fingerprint.server_header}</p>
                  </div>
                )}
                {finalLanguages.length > 0 && (
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Languages</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finalLanguages.map((l: string) => (
                        <span key={l} className="px-2 py-0.5 bg-brand-500/10 text-brand-300 rounded text-xs border border-brand-500/20">{l}</span>
                      ))}
                    </div>
                  </div>
                )}
                {finalFrameworks.length > 0 && (
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Frameworks</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finalFrameworks.map((f: string) => (
                        <span key={f} className="px-2 py-0.5 bg-emerald-500/10 text-emerald-300 rounded text-xs border border-emerald-500/20">{f}</span>
                      ))}
                    </div>
                  </div>
                )}
                {finalDatabases.length > 0 && (
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Databases</p>
                    <div className="flex flex-wrap gap-1.5">
                      {finalDatabases.map((db: string) => (
                        <span key={db} className="px-2 py-0.5 bg-blue-500/10 text-blue-300 rounded text-xs border border-blue-500/20">{db}</span>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Right Column: Findings List */}
        <div className="lg:col-span-3">
          <div className="glass-panel overflow-hidden">
            <div className="p-6 border-b border-white/5 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Bug className="w-5 h-5 text-brand-400" /> 
                Security Findings ({findings.length})
              </h3>
            </div>
            
            {findings.length === 0 ? (
              <div className="p-16 text-center flex flex-col items-center justify-center">
                <div className="w-20 h-20 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mb-6">
                  <CheckCircle2 className="w-10 h-10 text-emerald-400" />
                </div>
                <h4 className="text-xl text-zinc-200 font-bold mb-2">No vulnerabilities detected</h4>
                <p className="text-zinc-500 max-w-md">The assessment did not identify any security issues matching the current configurations.</p>
              </div>
            ) : (
              <div className="divide-y divide-white/5">
                {(() => {
                  // Group all findings by title first
                  const groupedFindings = Object.values(findings.reduce((acc: any, finding: any) => {
                    const key = finding.title || finding.category;
                    if (!acc[key]) acc[key] = { ...finding, occurrences: [] };
                    acc[key].occurrences.push(finding);
                    return acc;
                  }, {}));

                  // Bucket the grouped findings
                  const exploits: any[] = [];
                  const headers: any[] = [];
                  const info: any[] = [];

                  groupedFindings.forEach((group: any) => {
                    const title = (group.title || group.category).toLowerCase();
                    if (title.includes('header') || title.includes('policy') || title.includes('cors') || title.includes('hsts') || title.includes('cache-control')) {
                      headers.push(group);
                    } else if (group.severity === 'HIGH' || group.severity === 'CRITICAL' || ['SQLI', 'XSS', 'CMDI', 'SSRF', 'XXE', 'SSTI', 'NOSQLI'].includes(group.category)) {
                      exploits.push(group);
                    } else {
                      info.push(group);
                    }
                  });

                  const renderBucket = (title: string, items: any[], emptyMsg: string) => (
                    <div className="border-b border-white/5 last:border-0 pb-4">
                      <div className="px-6 py-4 bg-white/[0.02]">
                        <h4 className="text-sm font-bold text-zinc-400 uppercase tracking-wider">{title} ({items.length})</h4>
                      </div>
                      {items.length === 0 ? (
                        <div className="px-6 py-8 text-center text-zinc-600 text-sm italic">{emptyMsg}</div>
                      ) : (
                        items.map((group: any, idx: number) => (
                          <div key={idx} className="p-6 hover:bg-white/[0.02] transition-colors border-t border-white/5 first:border-0">
                            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-4">
                              <div>
                                <div className="flex items-center gap-3 mb-2">
                                  <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${
                                    group.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                                    group.severity === 'HIGH' ? 'bg-accent-rose/10 text-accent-rose border-accent-rose/20' :
                                    group.severity === 'MEDIUM' ? 'bg-accent-amber/10 text-accent-amber border-accent-amber/20' :
                                    group.severity === 'LOW' || group.severity === 'INFO' || group.severity === 'UNSURE' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                                    'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
                                  }`}>
                                    {group.severity || 'UNSURE'}
                                  </span>
                                  <h4 className="text-zinc-100 font-bold text-lg">{group.title || group.category} <span className="text-zinc-500 text-sm font-normal ml-2">({group.occurrences.length} affected endpoints)</span></h4>
                                </div>
                                <div className="flex flex-wrap gap-2 text-xs">
                                  {group.cwe && (
                                    <span className="px-2 py-1 bg-white/5 text-zinc-300 rounded border border-white/10 flex items-center gap-1">
                                      <Code2 className="w-3 h-3" /> {group.cwe}
                                    </span>
                                  )}
                                  {group.owasp_category && (
                                    <span className="px-2 py-1 bg-white/5 text-zinc-300 rounded border border-white/10">
                                      {group.owasp_category}
                                    </span>
                                  )}
                                  {group.cvss_score > 0 && (
                                    <span className="px-2 py-1 bg-white/5 text-zinc-300 rounded border border-white/10">
                                      CVSS: {group.cvss_score}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                            
                            <p className="text-zinc-300 text-sm leading-relaxed mb-6">{group.description}</p>
                            
                            <div className="space-y-4">
                              {group.occurrences.map((occ: any, oIdx: number) => (
                                <div key={oIdx} className="bg-dark-900 border border-white/10 rounded-xl overflow-hidden">
                                  <div className="bg-white/5 px-4 py-2 border-b border-white/10 flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs font-bold text-brand-400">{occ.proof?.request_method || 'GET'}</span>
                                      <span className="text-xs text-zinc-300 font-mono truncate max-w-md">{occ.target_url || occ.proof?.request_url}</span>
                                    </div>
                                    {occ.affected_parameter && (
                                      <span className="text-xs px-2 py-0.5 bg-brand-500/20 text-brand-300 rounded border border-brand-500/20">Param: {occ.affected_parameter}</span>
                                    )}
                                  </div>
                                  
                                  {occ.proof?.request_body && (
                                    <div className="p-4 border-b border-white/5 font-mono text-xs text-zinc-400 overflow-x-auto whitespace-pre-wrap">
                                      <span className="text-accent-rose font-bold block mb-1">Payload / Request Body:</span>
                                      {occ.proof.request_body}
                                    </div>
                                  )}
                                  
                                  {occ.proof?.response_body && (
                                    <div className="p-4 border-b border-white/5 font-mono text-xs text-zinc-400 overflow-x-auto whitespace-pre-wrap max-h-40 overflow-y-auto">
                                      <span className="text-brand-300 font-bold block mb-1">Response Evidence (Status {occ.proof.status_code}):</span>
                                      {occ.proof.response_body}
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                            
                            {group.remediation && (
                              <div className="mt-6 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/10">
                                <h5 className="text-emerald-400 text-xs font-bold uppercase tracking-wider mb-1">Remediation Guidance</h5>
                                <p className="text-zinc-300 text-sm">{group.remediation}</p>
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  );

                  return (
                    <div className="flex flex-col">
                      {renderBucket("Attack Success / Exploits", exploits, "No active vulnerabilities or exploits were successfully triggered.")}
                      {renderBucket("Missing Security Headers & Misconfigurations", headers, "No missing security headers or misconfigurations detected.")}
                      {renderBucket("Information Disclosure & Notes", info, "No general information disclosures found.")}
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
