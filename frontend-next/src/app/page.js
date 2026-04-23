'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiPost } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';

const REGIONS = [
  { value: 'us-east-1', label: 'US East (N. Virginia)' },
  { value: 'us-east-2', label: 'US East (Ohio)' },
  { value: 'us-west-1', label: 'US West (N. California)' },
  { value: 'us-west-2', label: 'US West (Oregon)' },
  { value: 'ap-south-1', label: 'Asia Pacific (Mumbai)' },
  { value: 'ap-southeast-1', label: 'Asia Pacific (Singapore)' },
  { value: 'ap-southeast-2', label: 'Asia Pacific (Sydney)' },
  { value: 'ap-northeast-1', label: 'Asia Pacific (Tokyo)' },
  { value: 'eu-west-1', label: 'Europe (Ireland)' },
  { value: 'eu-central-1', label: 'Europe (Frankfurt)' },
  { value: 'sa-east-1', label: 'South America (São Paulo)' },
];

export default function LoginPage() {
  const router = useRouter();
  const { setAuthToken, setAccountInfo } = useAuth();
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await apiPost('/login', {
        access_key: accessKey.trim(),
        secret_key: secretKey.trim(),
        region,
      });

      setAuthToken(data.token);
      setAccountInfo({
        account: data.account,
        userId: data.user_id,
        arn: data.arn,
        region,
      });

      router.push('/scanning');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-screen page-fade">
      <div className="login-container">
        <div className="login-logo">
          <div className="logo-icon">⛈️</div>
          <h1>
            <span className="gradient-text">Badal</span>
          </h1>
          <p>Cloud Vulnerability Analyser</p>
        </div>

        <div className="glass-card login-form-card">
          <form onSubmit={handleSubmit} autoComplete="off">
            <div className="form-group">
              <label htmlFor="access-key">AWS Access Key ID</label>
              <input
                type="text"
                id="access-key"
                placeholder="AKIA..."
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="secret-key">AWS Secret Access Key</label>
              <input
                type="password"
                id="secret-key"
                placeholder="Your secret key"
                autoComplete="current-password"
                value={secretKey}
                onChange={(e) => setSecretKey(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label htmlFor="region">Region</label>
              <select
                id="region"
                value={region}
                onChange={(e) => setRegion(e.target.value)}
              >
                {REGIONS.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </select>
            </div>

            <button type="submit" id="btn-login" className="btn-primary" disabled={loading}>
              {loading ? 'Connecting…' : 'Authenticate & Connect'}
            </button>

            {error && (
              <div className="login-error">{error}</div>
            )}
          </form>
        </div>

        <div className="login-footer">
          <span className="lock-icon">🔒</span> Credentials are encrypted in-transit and never
          stored on disk
        </div>
      </div>
    </div>
  );
}
