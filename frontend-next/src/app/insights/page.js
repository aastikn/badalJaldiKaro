'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';

export default function InsightsPage() {
  const router = useRouter();
  const { authToken, analysisData } = useAuth();

  useEffect(() => {
    if (!authToken || !analysisData) {
      router.replace('/dashboard');
    }
  }, [authToken, analysisData, router]);

  if (!analysisData) return null;

  const vulns = analysisData.vulnerabilities || [];
  const critCount = vulns.filter((v) => (v.priority || '').toLowerCase() === 'critical').length;
  const nonCritCount = vulns.length - critCount;

  const summaryText = analysisData.summary
    ? typeof analysisData.summary === 'string'
      ? analysisData.summary
      : JSON.stringify(analysisData.summary)
    : vulns.length
      ? `Found ${vulns.length} issue(s) — ${critCount} critical, ${nonCritCount} non-critical.`
      : 'No vulnerabilities were identified in your infrastructure. Looking good!';

  return (
    <div className="insights-screen page-fade">
      {/* Top Bar */}
      <div className="insights-topbar">
        <div className="topbar-left">
          <button className="btn-back" onClick={() => router.push('/dashboard')}>
            ← Back to Dashboard
          </button>
        </div>
        <div className="topbar-left">
          <div className="topbar-logo">⛈️</div>
          <span className="topbar-title gradient-text">Badal</span>
          <span className="insights-subtitle">AI Insights</span>
        </div>
      </div>

      <div className="insights-content">
        {/* Hero */}
        <div className="insights-hero">
          <div className="insights-hero-icon">🤖</div>
          <h2 className="gradient-text">AI Vulnerability Analysis</h2>
          <p className="insights-summary-text">{summaryText}</p>
        </div>

        {/* Stats */}
        <div className="insights-stats">
          <div className="glass-card insights-stat critical-stat">
            <div className="stat-number">{critCount}</div>
            <div className="stat-label">Critical</div>
          </div>
          <div className="glass-card insights-stat noncritical-stat">
            <div className="stat-number">{nonCritCount}</div>
            <div className="stat-label">Non-Critical</div>
          </div>
          <div className="glass-card insights-stat total-stat">
            <div className="stat-number">{vulns.length}</div>
            <div className="stat-label">Total Issues</div>
          </div>
        </div>

        {/* Vulnerability Cards */}
        <div className="insights-vuln-list">
          {vulns.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">✅</div>
              <p>No vulnerabilities identified by AI analysis. Your infrastructure looks clean!</p>
            </div>
          ) : (
            vulns.map((v, i) => (
              <div
                key={i}
                className={`glass-card insights-vuln-card ${
                  (v.priority || '').toLowerCase() === 'critical' ? 'vuln-critical' : 'vuln-noncritical'
                }`}
              >
                <div className="insights-vuln-header">
                  <span
                    className={`badge ${
                      (v.priority || '').toLowerCase() === 'critical' ? 'badge-critical' : 'badge-low'
                    }`}
                  >
                    {v.priority || 'non critical'}
                  </span>
                  <span className="insights-vuln-number">#{i + 1}</span>
                </div>
                <h4 className="insights-vuln-problem">{v.problem || 'Unknown issue'}</h4>
                <p className="insights-vuln-solution">
                  <strong>Fix:</strong> {v.solution || 'N/A'}
                </p>
                {v.cli_command && (
                  <div className="insights-cli-wrap">
                    <div className="insights-cli-label">CLI Command</div>
                    <div className="cli-command">{v.cli_command}</div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Full Table */}
        <div className="glass-card insights-table-section">
          <h3 style={{ marginBottom: 16 }}>📋 Full Breakdown</h3>
          <div className="ai-vuln-table-wrap">
            <table className="ai-vuln-table">
              <thead>
                <tr>
                  <th>Priority</th>
                  <th>Problem</th>
                  <th>Solution</th>
                  <th>CLI Command</th>
                </tr>
              </thead>
              <tbody>
                {vulns.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
                      No vulnerabilities identified by AI analysis.
                    </td>
                  </tr>
                ) : (
                  vulns.map((v, i) => (
                    <tr key={i}>
                      <td>
                        <span
                          className={`badge ${
                            (v.priority || '').toLowerCase() === 'critical' ? 'badge-critical' : 'badge-low'
                          }`}
                        >
                          {v.priority || 'non critical'}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-primary)' }}>{v.problem || ''}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>{v.solution || ''}</td>
                      <td>
                        {v.cli_command ? (
                          <div className="cli-command">{v.cli_command}</div>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
