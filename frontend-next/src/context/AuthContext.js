'use client';

import { createContext, useContext, useState, useCallback } from 'react';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [authToken, setAuthToken] = useState(null);
  const [accountInfo, setAccountInfo] = useState({});
  const [scanReport, setScanReport] = useState(null);
  const [analysisData, setAnalysisData] = useState(null);

  const logout = useCallback(() => {
    setAuthToken(null);
    setAccountInfo({});
    setScanReport(null);
    setAnalysisData(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        authToken,
        setAuthToken,
        accountInfo,
        setAccountInfo,
        scanReport,
        setScanReport,
        analysisData,
        setAnalysisData,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
