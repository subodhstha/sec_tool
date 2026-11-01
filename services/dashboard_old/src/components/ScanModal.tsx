import React, { useState } from 'react';
import { X, Shield, Play } from 'lucide-react';
import { ScanConfig } from '../types';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (targetUrl: string, config: ScanConfig) => Promise<void>;
}

export const ScanModal: React.FC<Props> = ({ isOpen, onClose, onSubmit }) => {
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080');
  const [verificationToken, setVerificationToken] = useState('vyomite-dev-token');
  const [safeMode, setSafeMode] = useState(true);
  const [activeFuzzing, setActiveFuzzing] = useState(true);
  const [maxRps, setMaxRps] = useState(20);
  const [consecutive5xxCap, setConsecutive5xxCap] = useState(5);
  const [maxDepth, setMaxDepth] = useState(3);
  const [baselineLatency, setBaselineLatency] = useState(250);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await onSubmit(targetUrl, {
        safe_mode: safeMode,
        max_rps: Number(maxRps),
        max_concurrency: 10,
        max_depth: Number(maxDepth),
        verification_token: verificationToken,
        baseline_latency_ms: Number(baselineLatency),
        consecutive_5xx_cap: Number(consecutive5xxCap),
        active_fuzzing: activeFuzzing,
      });
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Shield size={20} color="var(--accent-primary)" />
            <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>Configure New DAST Assessment</h3>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: '1.5rem' }}>
          {error && (
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: 'var(--radius-md)', padding: '0.75rem 1rem', marginBottom: '1.25rem', color: '#fca5a5', fontSize: '0.85rem' }}>
              {error}
            </div>
          )}

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
              Target Web URL
            </label>
            <input
              type="url"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://staging.internal.vyomite.com"
              style={{
                width: '100%',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-card)',
                borderRadius: 'var(--radius-md)',
                padding: '0.65rem 0.85rem',
                color: 'var(--text-main)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.875rem',
              }}
            />
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
              Domain Verification Token (FR-4.1)
            </label>
            <input
              type="text"
              required
              value={verificationToken}
              onChange={(e) => setVerificationToken(e.target.value)}
              placeholder="e.g. vyomite-token-xyz or vyomite-dev-token"
              style={{
                width: '100%',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-card)',
                borderRadius: 'var(--radius-md)',
                padding: '0.65rem 0.85rem',
                color: 'var(--text-main)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.875rem',
              }}
            />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', display: 'block', marginTop: '0.3rem' }}>
              Must match DNS TXT or <code>/.well-known/vyomite-verification.txt</code>
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Max Requests / Sec (FR-4.4)
              </label>
              <input
                type="number"
                min="1"
                max="200"
                value={maxRps}
                onChange={(e) => setMaxRps(Number(e.target.value))}
                style={{
                  width: '100%',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-card)',
                  borderRadius: 'var(--radius-md)',
                  padding: '0.65rem 0.85rem',
                  color: 'var(--text-main)',
                  fontSize: '0.875rem',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                5xx Circuit Breaker Cap (FR-4.3)
              </label>
              <input
                type="number"
                min="1"
                max="20"
                value={consecutive5xxCap}
                onChange={(e) => setConsecutive5xxCap(Number(e.target.value))}
                style={{
                  width: '100%',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-card)',
                  borderRadius: 'var(--radius-md)',
                  padding: '0.65rem 0.85rem',
                  color: 'var(--text-main)',
                  fontSize: '0.875rem',
                }}
              />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Crawl Depth Limit (FR-1.3)
              </label>
              <input
                type="number"
                min="1"
                max="10"
                value={maxDepth}
                onChange={(e) => setMaxDepth(Number(e.target.value))}
                style={{
                  width: '100%',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-card)',
                  borderRadius: 'var(--radius-md)',
                  padding: '0.65rem 0.85rem',
                  color: 'var(--text-main)',
                  fontSize: '0.875rem',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                Baseline Latency (ms)
              </label>
              <input
                type="number"
                min="50"
                max="2000"
                value={baselineLatency}
                onChange={(e) => setBaselineLatency(Number(e.target.value))}
                style={{
                  width: '100%',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-card)',
                  borderRadius: 'var(--radius-md)',
                  padding: '0.65rem 0.85rem',
                  color: 'var(--text-main)',
                  fontSize: '0.875rem',
                }}
              />
            </div>
          </div>

          {/* Safeguard Toggles */}
          <div style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: 'var(--radius-md)', marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={safeMode}
                onChange={(e) => setSafeMode(e.target.checked)}
                style={{ accentColor: 'var(--accent-primary)', width: 16, height: 16 }}
              />
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)' }}>Safe Mode: Destructive HTTP Filter (FR-4.2)</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Unconditionally drops DELETE and regex-matches /delete, /purge, /drop</div>
              </div>
            </label>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={activeFuzzing}
                onChange={(e) => setActiveFuzzing(e.target.checked)}
                style={{ accentColor: 'var(--accent-primary)', width: 16, height: 16 }}
              />
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)' }}>Active Attack Fuzzing (Phase 2)</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Simulate SQLi & Blind SSRF payloads. Disable for Phase 1 passive-only mapping.</div>
              </div>
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button type="button" onClick={onClose} className="btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn-primary">
              <Play size={16} />
              {loading ? 'Submitting...' : 'Queue Assessment (202 Accepted)'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
