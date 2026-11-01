export type ScanStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'PAUSED_CIRCUIT_BREAKER'
  | 'THROTTLED'
  | 'ABORTED'
  | 'COMPLETED'
  | 'FAILED';

export interface ScanStats {
  total_requests_sent: number;
  current_rps: number;
  average_latency_ms: number;
  consecutive_5xx_count: number;
  circuit_breaker_trips: number;
  endpoints_discovered: number;
  endpoints_scanned: number;
  vulnerabilities_found: number;
}

export interface TargetFingerprint {
  server_header?: string;
  frameworks?: string[];
  languages?: string[];
  databases?: string[];
  cloud_provider?: string;
  fingerprinted_at?: string;
}

export interface ScanConfig {
  safe_mode: boolean;
  max_rps: number;
  max_concurrency: number;
  max_depth: number;
  verification_token: string;
  baseline_latency_ms: number;
  consecutive_5xx_cap: number;
  latency_backoff_cap_ms?: number;
  active_fuzzing: boolean;
  exclude_patterns?: string[];
}

export interface ScanJob {
  id: string;
  target_url: string;
  status: ScanStatus;
  created_at: string;
  updated_at: string;
  config: ScanConfig;
  fingerprint: TargetFingerprint;
  stats: ScanStats;
}

export interface HTTPProof {
  request_url: string;
  request_method: string;
  request_headers: Record<string, string[]>;
  request_body?: string;
  status_code: number;
  response_headers: Record<string, string[]>;
  response_body?: string;
  duration_ms: number;
}

export interface VulnerabilityFinding {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  remediation: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvss_score: number;
  cwe: string;
  owasp_category: string;
  iso27001_control?: string;
  nist_control?: string;
  nsa_cisa_guidance?: string;
  target_url: string;
  affected_parameter?: string;
  injection_context?: string;
  dedup_hash: string;
  proof?: HTTPProof;
  discovered_at: string;
  occurrences_count: number;
  related_urls?: string[];
}
