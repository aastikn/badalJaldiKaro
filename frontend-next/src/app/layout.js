import './globals.css';
import { AuthProvider } from '@/context/AuthContext';

export const metadata = {
  title: 'Badal — Cloud Vulnerability Analyser',
  description:
    'Scan your AWS infrastructure for vulnerabilities, dependency risks, and misconfigurations.',
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>⛈️</text></svg>",
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        {/* Background Particles */}
        <div className="bg-particles">
          <div className="orb"></div>
          <div className="orb"></div>
          <div className="orb"></div>
        </div>

        <div className="app-container">
          <AuthProvider>{children}</AuthProvider>
        </div>
      </body>
    </html>
  );
}
