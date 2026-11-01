import React from 'react';
import { ShieldCheck, ShieldAlert, Zap, Activity } from 'lucide-react';
import { ScanJob } from '../types';

interface Props {
  scan: ScanJob;
}

export const CircuitBreakerCard: React.FC<Props> = ({ scan }) => {
  const { stats, config, status } = scan;
  const isTripped = status === 'PAUSED_CIRCUIT_BREAKER';
  const isThrottled = status === 'THROTTLED';

  return (
    <div className="glass-panel" style={{ borderLeft: isTripped ? '4px solid var(--accent-critical)' : '4px solid var(--accent-emerald)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            width: 34,
            height: 34,
            borderRadius: 'var(--radius-md)',
            background: isTripped ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: isTripped ? 'var(--accent-critical)' : 'var(--accent-emerald)'
          }}>
            {isTripped ? <ShieldAlert size={20} /> : <ShieldCheck size={20} />}
          </div>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Safety Guardrails & Circuit Breaker</h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>FR-4.3 5xx Detection & FR-4.4 Latency Back-off</span>
          </div>
        </div>

        <span className={`status-pill ${isTripped ? 'status-paused' : isThrottled ? 'status-paused' : 'status-completed'}`}>
          {isTripped ? 'CIRCUIT OPEN (TRIPPED)' : isThrottled ? 'THROTTLED BACK-OFF' : 'CIRCUIT CLOSED (HEALTHY)'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        {/* Consecutive 5xx Metric */}
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Consecutive 5xx Errors</span>
            <Activity size={14} color="var(--text-dim)" />
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700, color: stats.consecutive_5xx_count > 0 ? 'var(--accent-amber)' : 'var(--text-main)' }}>
            {stats.consecutive_5xx_count} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-dim)' }}>/ {config.consecutive_5xx_cap} Cap</span>
          </div>
          <div style={{ width: '100%', height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 2, marginTop: '0.5rem', overflow: 'hidden' }}>
            <div style={{
              width: `${Math.min(100, (stats.consecutive_5xx_count / (config.consecutive_5xx_cap || 5)) * 100)}%`,
              height: '100%',
              background: stats.consecutive_5xx_count >= (config.consecutive_5xx_cap || 5) ? 'var(--accent-critical)' : 'var(--accent-amber)',
              transition: 'width 0.3s ease'
            }} />
          </div>
        </div>

        {/* Dynamic RPS Metric */}
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Throughput / Pacing</span>
            <Zap size={14} color="var(--text-dim)" />
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700 }}>
            {stats.current_rps ? stats.current_rps.toFixed(1) : config.max_rps} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-dim)' }}>req/sec (Max: {config.max_rps})</span>
          </div>
          <span style={{ fontSize: '0.7rem', color: config.safe_mode ? 'var(--accent-emerald)' : 'var(--accent-amber)', display: 'block', marginTop: '0.35rem' }}>
            {config.safe_mode ? '✓ Safe Verbs Filter Active (No DELETEs)' : '⚠ Safe Mode Disabled'}
          </span>
        </div>

        {/* Latency Metric */}
        <div style={{ background: 'rgba(0,0,0,0.2)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Average Server Latency</span>
            <Activity size={14} color="var(--text-dim)" />
          </div>
          <div style={{ fontSize: '1.25rem', fontWeight: 700 }}>
            {stats.average_latency_ms || config.baseline_latency_ms} <span style={{ fontSize: '0.8rem', fontWeight: 400, color: 'var(--text-dim)' }}>ms</span>
          </div>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.35rem' }}>
            Baseline: {config.baseline_latency_ms} ms (diff evaluated)
          </span>
        </div>
      </div>
    </div>
  );
};
