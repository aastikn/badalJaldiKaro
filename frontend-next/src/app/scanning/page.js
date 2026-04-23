'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { apiPost } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';

const SCAN_STEPS = [
  '⏳ Authenticating with AWS…',
  '⏳ Scanning EC2, Lambda, RDS, S3, SQS, IAM…',
  '⏳ Checking NVD for vulnerabilities…',
  '⏳ Analysing dependencies & risk…',
  '⏳ Generating report…',
];

export default function ScanningPage() {
  const router = useRouter();
  const { authToken, setScanReport } = useAuth();
  const [steps, setSteps] = useState(SCAN_STEPS.map((text) => ({ text, status: 'pending' })));
  const hasStarted = useRef(false);

  useEffect(() => {
    if (!authToken) {
      router.replace('/');
      return;
    }

    if (hasStarted.current) return;
    hasStarted.current = true;

    // Animate steps
    let current = 0;
    const interval = setInterval(() => {
      setSteps((prev) => {
        const next = [...prev];
        if (current > 0 && current - 1 < next.length) {
          next[current - 1] = { ...next[current - 1], status: 'done', text: next[current - 1].text.replace('⏳', '✅') };
        }
        if (current < next.length) {
          next[current] = { ...next[current], status: 'active' };
        } else {
          clearInterval(interval);
        }
        current++;
        return next;
      });
    }, 3000);

    // Start scan
    apiPost('/scan', {}, authToken)
      .then((report) => {
        setScanReport(report);
        router.push('/dashboard');
      })
      .catch((err) => {
        alert('Scan failed: ' + err.message);
        router.replace('/');
      });

    return () => clearInterval(interval);
  }, [authToken, router, setScanReport]);

  return (
    <div className="scanning-screen page-fade">
      <div className="scanner-visual">
        <div className="scanner-ring"></div>
        <div className="scanner-ring"></div>
        <div className="scanner-ring"></div>
        <div className="scanner-core">🔍</div>
      </div>

      <div className="scanning-status">
        <h2 className="gradient-text">Scanning Infrastructure</h2>
        <p>
          Analysing your AWS resources, checking for vulnerabilities against the NVD database, and
          mapping dependencies…
        </p>
      </div>

      <div className="scan-progress">
        <div className="progress-bar-track">
          <div className="progress-bar-fill"></div>
        </div>
        <div className="scan-steps">
          {steps.map((step, i) => (
            <div key={i} className={`step ${step.status}`}>
              {step.text}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
