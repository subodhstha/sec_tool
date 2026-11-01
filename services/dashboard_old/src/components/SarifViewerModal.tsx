import React, { useEffect, useState } from 'react';
import { X, Copy, Download, Check, FileCode } from 'lucide-react';

interface Props {
  scanId: string | null;
  onClose: () => void;
}

export const SarifViewerModal: React.FC<Props> = ({ scanId, onClose }) => {
  const [sarifData, setSarifData] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    if (!scanId) return;

    setLoading(true);
    fetch(`/api/v1/scans/${scanId}/results?format=sarif`)
      .then((res) => res.json())
      .then((data) => {
        setSarifData(JSON.stringify(data, null, 2));
      })
      .catch((err) => {
        setSarifData(JSON.stringify({ error: 'Failed to fetch SARIF', details: err.message }, null, 2));
      })
      .finally(() => setLoading(false));
  }, [scanId]);

  if (!scanId) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(sarifData);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([sarifData], { type: 'application/sarif+json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vyomite-dast-${scanId}.sarif`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '800px' }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1.25rem 1.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FileCode size={20} color="var(--accent-cyan)" />
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>SARIF v2.1.0 Pipeline Export</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>FR-5.2 Developer-Native CI/CD Defect Interchange</span>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginBottom: '1rem' }}>
            <button onClick={handleCopy} className="btn-secondary" style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem' }}>
              {copied ? <Check size={14} color="var(--accent-emerald)" /> : <Copy size={14} />}
              {copied ? 'Copied to Clipboard' : 'Copy JSON'}
            </button>
            <button onClick={handleDownload} className="btn-primary" style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem' }}>
              <Download size={14} />
              Download .sarif
            </button>
          </div>

          <div style={{ position: 'relative' }}>
            {loading ? (
              <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>Generating SARIF document...</div>
            ) : (
              <pre
                className="font-mono"
                style={{
                  background: '#070a11',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '1rem',
                  fontSize: '0.75rem',
                  maxHeight: '450px',
                  overflow: 'auto',
                  color: '#93c5fd',
                  lineHeight: 1.5,
                }}
              >
                {sarifData}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
