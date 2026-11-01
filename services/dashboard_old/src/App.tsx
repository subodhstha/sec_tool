import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Plus, 
  Terminal, 
  AlertTriangle, 
  RotateCw, 
  Layers, 
  Compass, 
  FileCode, 
  XOctagon, 
  CheckCircle2, 
  Server
} from 'lucide-react';
import { ScanJob, VulnerabilityFinding, ScanConfig } from './types';
import { CircuitBreakerCard } from './components/CircuitBreakerCard';
import { VulnerabilityFeed } from './components/VulnerabilityFeed';
import { ScanModal } from './components/ScanModal';
import { SarifViewerModal } from './components/SarifViewerModal';

export const App: React.FC = () => {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [sarifModalScanId, setSarifModalScanId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Poll scan list
  const fetchScans = async () => {
    try {
      const res = await fetch('/api/v1/scans');
      if (res.ok) {
        const data = await res.json();
        setScans(data.scans || []);
        if (!selectedScanId && data.scans && data.scans.length > 0) {
          setSelectedScanId(data.scans[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to poll scans:', err);
    }
  };

  // Poll findings for selected scan
  const fetchFindings = async (scanId: string) => {
    try {
      const res = await fetch(`/api/v1/scans/${scanId}/results`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data.findings || []);
      }
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedScanId) {
      fetchFindings(selectedScanId);
      const interval = setInterval(() => fetchFindings(selectedScanId), 3000);
      return () => clearInterval(interval);
    }
  }, [selectedScanId]);

  const handleCreateScan = async (targetUrl: string, config: ScanConfig) => {
    const res = await fetch('/api/v1/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_url: targetUrl,
        scan_name: `Assessment-${new Date().toLocaleTimeString()}`,
        config,
      }),
    });

    if (!res.ok) {
      const contentType = res.headers.get('content-type');
      let errorMessage = 'Failed to dispatch scan';
      if (contentType && contentType.includes('application/json')) {
        const err = await res.json();
        errorMessage = err.details || err.error || errorMessage;
      } else {
        errorMessage = await res.text();
      }
      throw new Error(errorMessage);
    }

    const data = await res.json();
    setSelectedScanId(data.scan_id);
    fetchScans();
  };

  const handleAbortScan = async (scanId: string) => {
    try {
      await fetch(`/api/v1/scans/${scanId}/abort`, { method: 'POST' });
      fetchScans();
    } catch (err) {
      console.error('Failed to abort scan:', err);
    }
  };

  const selectedScan = scans.find((s) => s.id === selectedScanId);

  // Compute aggregate metrics
  const totalFindings = scans.reduce((acc, s) => acc + (s.stats?.vulnerabilities_found || 0), 0);
  const totalRequests = scans.reduce((acc, s) => acc + (s.stats?.total_requests_sent || 0), 0);
  const activeScansCount = scans.filter((s) => s.status === 'RUNNING' || s.status === 'PAUSED_CIRCUIT_BREAKER').length;

  return (
    <div className="app-container">
      {/* Top Navbar */}
      <header className="navbar">
        <div className="brand-section">
          <div className="brand-logo-icon">
            <Shield size={22} color="white" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span className="brand-title">VYOMITE DAST</span>
              <span className="brand-badge">Dogfooding v1.0</span>
            </div>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Zero-Disruption Continuous Security Assessment Platform
            </p>
          </div>
        </div>

        <div className="nav-actions">
          <button onClick={() => setIsModalOpen(true)} className="btn-primary">
            <Plus size={16} />
            Launch Assessment
          </button>
        </div>
      </header>

      {/* Main Workspace */}
      <main className="main-content">
        {/* Global Telemetry KPI Row */}
        <div className="grid-cols-4" style={{ marginBottom: '1.75rem' }}>
          <div className="glass-panel" style={{ padding: '1.15rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>
              <span>Active Assessments</span>
              <Terminal size={16} color="var(--accent-cyan)" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
              {activeScansCount}
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              {scans.length} total assessments queued
            </span>
          </div>

          <div className="glass-panel" style={{ padding: '1.15rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>
              <span>Requests Dispatched</span>
              <RotateCw size={16} color="var(--accent-primary)" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700 }}>
              {totalRequests.toLocaleString()}
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Dynamic latency throttling active
            </span>
          </div>

          <div className="glass-panel" style={{ padding: '1.15rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>
              <span>Vulnerabilities Discovered</span>
              <AlertTriangle size={16} color="var(--accent-rose)" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: totalFindings > 0 ? 'var(--accent-rose)' : 'var(--text-main)' }}>
              {totalFindings}
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Deduplicated via FR-5.1 hashing
            </span>
          </div>

          <div className="glass-panel" style={{ padding: '1.15rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '0.4rem' }}>
              <span>Safety Circuit Breakers</span>
              <Shield size={16} color="var(--accent-emerald)" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent-emerald)' }}>
              PROTECTED
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              5xx trip & safe verbs active
            </span>
          </div>
        </div>

        {/* Workspace Layout */}
        <div style={{ display: 'grid', gridTemplateColumns: scans.length > 0 ? '320px 1fr' : '1fr', gap: '1.5rem', alignItems: 'start' }}>
          {/* Left Column: Scans List */}
          {scans.length > 0 && (
            <div className="glass-panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '0.9rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Assessments ({scans.length})
                </h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                {scans.map((s) => {
                  const isSelected = s.id === selectedScanId;
                  return (
                    <div
                      key={s.id}
                      onClick={() => setSelectedScanId(s.id)}
                      style={{
                        padding: '0.85rem',
                        borderRadius: 'var(--radius-md)',
                        background: isSelected ? 'rgba(99, 102, 241, 0.15)' : 'rgba(0, 0, 0, 0.25)',
                        border: isSelected ? '1px solid var(--accent-primary)' : '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                        <span className={`status-pill status-${s.status.toLowerCase().replace('_', '-')}`} style={{ fontSize: '0.65rem', padding: '0.15rem 0.5rem' }}>
                          {s.status}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                          {new Date(s.created_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <div className="font-mono" style={{ fontSize: '0.8rem', color: '#f1f5f9', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {s.target_url}
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        <span>Scanned: {s.stats?.endpoints_scanned || 0}/{s.stats?.endpoints_discovered || 0}</span>
                        <span style={{ color: (s.stats?.vulnerabilities_found || 0) > 0 ? 'var(--accent-rose)' : 'var(--text-dim)', fontWeight: 600 }}>
                          {s.stats?.vulnerabilities_found || 0} flaws
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Right Column: Active Scan Details & Findings */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {selectedScan ? (
              <>
                {/* Header Card */}
                <div className="glass-panel">
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                        <h2 style={{ fontSize: '1.35rem', fontWeight: 700 }}>{selectedScan.target_url}</h2>
                        <span className={`status-pill status-${selectedScan.status.toLowerCase().replace('_', '-')}`}>
                          {selectedScan.status}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: '1.25rem' }}>
                        <span>ID: <code className="font-mono" style={{ color: '#cbd5e1' }}>{selectedScan.id}</code></span>
                        <span>Mode: <strong style={{ color: selectedScan.config.safe_mode ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>{selectedScan.config.safe_mode ? 'Safe Mode' : 'Standard'}</strong></span>
                        <span>Fuzzing: <strong style={{ color: selectedScan.config.active_fuzzing ? 'var(--accent-cyan)' : 'var(--text-dim)' }}>{selectedScan.config.active_fuzzing ? 'Active' : 'Passive Only'}</strong></span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '0.75rem' }}>
                      <button
                        onClick={() => setSarifModalScanId(selectedScan.id)}
                        className="btn-secondary"
                        style={{ padding: '0.5rem 0.9rem', fontSize: '0.8rem' }}
                      >
                        <FileCode size={15} />
                        View SARIF (FR-5.2)
                      </button>

                      {(selectedScan.status === 'RUNNING' || selectedScan.status === 'PAUSED_CIRCUIT_BREAKER') && (
                        <button
                          onClick={() => handleAbortScan(selectedScan.id)}
                          className="btn-danger"
                          style={{ padding: '0.5rem 0.9rem', fontSize: '0.8rem' }}
                        >
                          <XOctagon size={15} />
                          Abort Scan (Scenario A)
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Passive Stack Fingerprint Info (FR-3.1) */}
                  {selectedScan.fingerprint && (
                    <div style={{ background: 'rgba(0,0,0,0.25)', padding: '0.75rem 1rem', borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', gap: '1.5rem', fontSize: '0.75rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--accent-cyan)' }}>
                        <Server size={14} />
                        <span style={{ fontWeight: 600 }}>Detected Stack (FR-3.1):</span>
                      </div>
                      <div>Server: <strong style={{ color: '#f1f5f9' }}>{selectedScan.fingerprint.server_header || 'Unknown'}</strong></div>
                      {selectedScan.fingerprint.frameworks && selectedScan.fingerprint.frameworks.length > 0 && (
                        <div>Frameworks: <strong style={{ color: '#f1f5f9' }}>{selectedScan.fingerprint.frameworks.join(', ')}</strong></div>
                      )}
                      {selectedScan.fingerprint.languages && selectedScan.fingerprint.languages.length > 0 && (
                        <div>Languages: <strong style={{ color: '#f1f5f9' }}>{selectedScan.fingerprint.languages.join(', ')}</strong></div>
                      )}
                    </div>
                  )}
                </div>

                {/* Circuit Breaker & Safeguard Telemetry (FR-4.3 & FR-4.4) */}
                <CircuitBreakerCard scan={selectedScan} />

                {/* Vulnerability Findings Feed (FR-5.1) */}
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Shield size={18} color="var(--accent-primary)" />
                      Vulnerability Findings ({findings.length})
                    </h3>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Deduplicated by Parameter + Context + Category
                    </span>
                  </div>

                  <VulnerabilityFeed findings={findings} />
                </div>
              </>
            ) : (
              <div className="glass-panel" style={{ textAlign: 'center', padding: '4rem 2rem' }}>
                <Compass size={48} color="var(--accent-primary)" style={{ marginBottom: '1rem', opacity: 0.8 }} />
                <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>No Active Assessment Selected</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', maxWidth: 450, margin: '0 auto 1.5rem' }}>
                  Launch a new continuous security assessment against internal QA, Staging, or UAT environments with zero-disruption guardrails.
                </p>
                <button onClick={() => setIsModalOpen(true)} className="btn-primary">
                  <Plus size={16} />
                  Launch First Assessment
                </button>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* New Scan Configuration Modal */}
      <ScanModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSubmit={handleCreateScan}
      />

      {/* SARIF 2.1.0 Inspector Modal (FR-5.2) */}
      <SarifViewerModal
        scanId={sarifModalScanId}
        onClose={() => setSarifModalScanId(null)}
      />
    </div>
  );
};
