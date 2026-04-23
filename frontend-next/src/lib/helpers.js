export function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function getRiskColor(score) {
  if (score >= 0.7) return 'var(--accent-red)';
  if (score >= 0.4) return 'var(--accent-orange)';
  return 'var(--accent-green)';
}

export function getTypeBadgeClass(type) {
  const map = {
    compute: 'badge-compute',
    serverless: 'badge-serverless',
    database: 'badge-database',
    storage: 'badge-storage',
    queue: 'badge-queue',
    identity: 'badge-identity',
    network: 'badge-network',
  };
  return map[type] || 'badge-compute';
}

export function getSeverityBadgeClass(severity) {
  const s = (severity || '').toLowerCase();
  if (s === 'critical') return 'badge-critical';
  if (s === 'high') return 'badge-high';
  if (s === 'medium') return 'badge-medium';
  return 'badge-low';
}

export function getDepTypeDotColor(type) {
  const t = typeof type === 'string' ? type.toLowerCase() : '';
  const map = {
    compute: 'var(--accent-cyan)',
    serverless: 'var(--accent-green)',
    database: 'var(--accent-purple)',
    storage: 'var(--accent-orange)',
    queue: 'var(--accent-pink)',
    identity: 'var(--accent-red)',
    network: 'var(--accent-blue)',
  };
  return map[t] || 'var(--text-muted)';
}
