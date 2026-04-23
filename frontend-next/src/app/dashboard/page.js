'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { apiPost } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import {
  getRiskColor,
  getTypeBadgeClass,
  getSeverityBadgeClass,
  getDepTypeDotColor,
} from '@/lib/helpers';

const TABS = [
  { id: 'resources', label: 'Resources' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'graph', label: 'Dependency Graph' },
  { id: 'bottlenecks', label: 'Bottlenecks' },
  { id: 'depmap', label: 'Dependency Map' },
  { id: 'recommendations', label: 'Recommendations' },
  { id: 'ai', label: 'AI Analysis ✨' },
];

export default function DashboardPage() {
  const router = useRouter();
  const { authToken, accountInfo, scanReport, setAnalysisData, logout } = useAuth();
  const [activeTab, setActiveTab] = useState('resources');
  const [aiLoading, setAiLoading] = useState(false);

  useEffect(() => {
    if (!authToken || !scanReport) {
      router.replace('/');
    }
  }, [authToken, scanReport, router]);

  if (!scanReport) return null;

  const resources = scanReport.aws_resources || [];
  const bottlenecks = scanReport.bottlenecks || [];
  const totalVulns = resources.reduce((sum, r) => sum + (r.vulnerabilities?.length || 0), 0);
  const avgRisk =
    resources.length > 0
      ? resources.reduce((sum, r) => sum + (r.risk_score || 0), 0) / resources.length
      : 0;

  function handleLogout() {
    logout();
    router.push('/');
  }

  async function handleAiAnalyze() {
    setAiLoading(true);
    try {
      const analysis = await apiPost('/analyze', { report: scanReport }, authToken);
      setAnalysisData(analysis);
      router.push('/insights');
    } catch (err) {
      alert('AI Analysis failed: ' + err.message);
    } finally {
      setAiLoading(false);
    }
  }

  return (
    <div className="dashboard-screen page-fade">
      {/* Top Bar */}
      <div className="topbar">
        <div className="topbar-left">
          <div className="topbar-logo">⛈️</div>
          <span className="topbar-title gradient-text">Badal</span>
        </div>
        <div className="topbar-right">
          <div className="topbar-info">
            <div>
              Account: <span className="account-id">{accountInfo.account || '—'}</span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
              {accountInfo.region || '—'}
            </div>
          </div>
          <button className="btn-logout" onClick={handleLogout}>
            Sign Out
          </button>
        </div>
      </div>

      <div className="dashboard-content">
        {/* Overview Cards */}
        <div className="overview-grid">
          <div className="glass-card overview-card resources">
            <div className="card-icon">🖥️</div>
            <div className="card-value">{resources.length}</div>
            <div className="card-label">Resources Scanned</div>
          </div>
          <div className="glass-card overview-card vulns">
            <div className="card-icon">🛡️</div>
            <div className="card-value">{totalVulns}</div>
            <div className="card-label">Vulnerabilities Found</div>
          </div>
          <div className="glass-card overview-card risk">
            <div className="card-icon">⚠️</div>
            <div className="card-value">{avgRisk.toFixed(2)}</div>
            <div className="card-label">Avg Risk Score</div>
          </div>
          <div className="glass-card overview-card bottlenecks">
            <div className="card-icon">🔗</div>
            <div className="card-value">{bottlenecks.length}</div>
            <div className="card-label">Bottlenecks Detected</div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="tab-nav">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'resources' && <ResourcesTab resources={resources} />}
        {activeTab === 'vulnerabilities' && <VulnerabilitiesTab resources={resources} />}
        {activeTab === 'graph' && <GraphTab graphBase64={scanReport.graph_base64} />}
        {activeTab === 'bottlenecks' && <BottlenecksTab bottlenecks={bottlenecks} />}
        {activeTab === 'depmap' && <DepMapTab depMap={scanReport.dependency_map || []} />}
        {activeTab === 'recommendations' && (
          <RecommendationsTab recs={scanReport.actionable_recommendations || []} />
        )}
        {activeTab === 'ai' && <AiTab onAnalyze={handleAiAnalyze} loading={aiLoading} />}
      </div>
    </div>
  );
}

/* ---- Sub-components ---- */

function EmptyState({ icon, text }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <p>{text}</p>
    </div>
  );
}

function ResourcesTab({ resources }) {
  if (!resources.length)
    return <EmptyState icon="📭" text="No resources found in this account/region." />;

  return (
    <div className="resources-table-wrap glass-card" style={{ padding: 0, border: 'none' }}>
      <table className="resources-table">
        <thead>
          <tr>
            <th>Resource</th>
            <th>Type</th>
            <th>Region</th>
            <th>Risk Score</th>
            <th>Vulnerabilities</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((r, i) => (
            <tr key={i}>
              <td>
                <div className="resource-name">{r.name}</div>
                <div className="resource-id">{r.id}</div>
              </td>
              <td>
                <span className={`badge ${getTypeBadgeClass(r.type)}`}>{r.type}</span>
              </td>
              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                {r.region}
              </td>
              <td>
                <div className="risk-meter">
                  <div className="risk-bar">
                    <div
                      className="risk-bar-fill"
                      style={{
                        width: `${(r.risk_score || 0) * 100}%`,
                        background: getRiskColor(r.risk_score),
                      }}
                    />
                  </div>
                  <span className="risk-score" style={{ color: getRiskColor(r.risk_score) }}>
                    {(r.risk_score || 0).toFixed(2)}
                  </span>
                </div>
              </td>
              <td>
                {r.vulnerabilities?.length > 0 ? (
                  r.vulnerabilities.map((v, vi) => (
                    <span key={vi} className={`badge ${getSeverityBadgeClass(v.severity)}`} style={{ margin: 2 }}>
                      {v.id}
                    </span>
                  ))
                ) : (
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>None</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VulnerabilitiesTab({ resources }) {
  const vulnResources = resources.filter((r) => r.vulnerabilities?.length > 0);
  if (!vulnResources.length)
    return <EmptyState icon="✅" text="No known vulnerabilities detected. Your resources look clean!" />;

  return (
    <div className="vuln-list">
      {vulnResources.map((r, ri) => (
        <div key={ri} className="glass-card vuln-card">
          <div className="vuln-card-header">
            <h4>
              <span className={`badge ${getTypeBadgeClass(r.type)}`}>{r.type}</span>
              {r.name}
            </h4>
            <span className="risk-score" style={{ color: getRiskColor(r.risk_score) }}>
              Risk: {(r.risk_score || 0).toFixed(2)}
            </span>
          </div>
          {r.vulnerabilities.map((v, vi) => (
            <VulnItem key={vi} v={v} ri={ri} vi={vi} />
          ))}
        </div>
      ))}
    </div>
  );
}

function VulnItem({ v, ri, vi }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ padding: '12px 0', borderTop: vi > 0 ? '1px solid var(--border-subtle)' : 'none' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className={`badge ${getSeverityBadgeClass(v.severity)}`}>{v.severity}</span>
          <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem' }}>{v.id}</strong>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: getRiskColor(v.cvss_score / 10) }}>
            CVSS {v.cvss_score}
          </span>
        </div>
        <button className="vuln-toggle" onClick={() => setOpen(!open)}>
          {open ? 'Details ▾' : 'Details ▸'}
        </button>
      </div>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{v.description}</p>
      {open && (
        <div className="vuln-details open">
          <div className="vuln-detail-row"><span className="label">CVE ID</span><span className="value">{v.id}</span></div>
          <div className="vuln-detail-row"><span className="label">CVSS Score</span><span className="value">{v.cvss_score}</span></div>
          <div className="vuln-detail-row"><span className="label">Severity</span><span className="value">{v.severity}</span></div>
          <div className="vuln-detail-row"><span className="label">Vector</span><span className="value">{v.vector}</span></div>
          <div className="vuln-detail-row"><span className="label">Published</span><span className="value">{v.published}</span></div>
        </div>
      )}
    </div>
  );
}

function GraphTab({ graphBase64 }) {
  const [zoomed, setZoomed] = useState(false);
  if (!graphBase64)
    return <EmptyState icon="🕸️" text="No dependency graph could be generated." />;

  return (
    <div className="glass-card graph-container">
      <h3 style={{ marginBottom: 16, textAlign: 'left' }}>Resource Dependency Graph</h3>
      <img
        src={`data:image/png;base64,${graphBase64}`}
        alt="Dependency Graph"
        className={zoomed ? 'zoomed' : ''}
        onClick={() => setZoomed(!zoomed)}
      />
    </div>
  );
}

function BottlenecksTab({ bottlenecks }) {
  if (!bottlenecks.length)
    return <EmptyState icon="🎯" text="No bottlenecks or single points of failure detected." />;

  return (
    <div className="bottleneck-grid">
      {bottlenecks.map((bn, i) => {
        const icon = bn.type === 'Circular Dependency' ? '🔄' : bn.type === 'AWS Service Role' ? '🔐' : '⚡';
        return (
          <div key={i} className="glass-card bottleneck-card">
            <div className="bn-type">
              <span className="icon">{icon}</span>
              <div>
                <h4>{bn.type}</h4>
                <span className={`badge ${getSeverityBadgeClass(bn.severity)}`}>{bn.severity}</span>
              </div>
            </div>
            {bn.resource && <div className="bn-resource">{bn.resource}</div>}
            {bn.dependents && (
              <div className="bn-dependents">
                {bn.dependents.length} dependent resource(s): {bn.dependents.join(', ')}
              </div>
            )}
            {bn.chain && (
              <div className="bn-chain">
                {bn.chain.map((node, ci) => (
                  <span key={ci}>
                    <span className="chain-node">{node}</span>
                    {ci < bn.chain.length - 1 && <span className="chain-arrow">→</span>}
                  </span>
                ))}
                <span className="chain-arrow">→</span>
                <span className="chain-node">{bn.chain[0]}</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function DepMapTab({ depMap }) {
  if (!depMap.length)
    return <EmptyState icon="🗺️" text="No dependency map data available." />;

  return (
    <div className="dep-map-list">
      {depMap.map((item, i) => (
        <div key={i} className="glass-card dep-map-item">
          <div className="dep-resource-name">{item.resource_name}</div>
          <div className="dep-provider">{item.provider}</div>
          {item.dependencies?.length ? (
            <div className="dep-list">
              {item.dependencies.map((dep, di) => (
                <div key={di} className="dep-chip">
                  <span className="dep-type-dot" style={{ background: getDepTypeDotColor(dep.dependency_type) }} />
                  {dep.dependency_name}
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                    {typeof dep.dependency_type === 'string' ? dep.dependency_type : ''}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No dependencies</span>
          )}
        </div>
      ))}
    </div>
  );
}

function RecommendationsTab({ recs }) {
  const filtered = recs.filter((r) => r.recommendations?.length);
  if (!filtered.length)
    return <EmptyState icon="📋" text="No actionable recommendations at this time." />;

  return (
    <div className="recommendation-list">
      {filtered.map((rec, i) => (
        <div key={i} className="glass-card recommendation-item">
          <span className="rec-icon">💡</span>
          <div className="rec-content">
            <h4>{rec.bottleneck_type}</h4>
            {rec.recommendations.map((text, ti) => (
              <p key={ti}>{text}</p>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function AiTab({ onAnalyze, loading }) {
  return (
    <div className="glass-card ai-section">
      <div className="ai-trigger">
        <button className="btn-ai" onClick={onAnalyze} disabled={loading}>
          {loading ? '⏳ Analysing with Mistral AI…' : '✨ Run AI Vulnerability Analysis'}
        </button>
        <p>Uses Mistral AI to generate prioritized vulnerability breakdown with CLI fix commands.</p>
      </div>
    </div>
  );
}
