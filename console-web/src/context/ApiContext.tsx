// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { createContext, useContext, useEffect, useState } from 'react';
import { apiClient } from '../api/client';

interface ApiContextType {
  isLiveApi: boolean;
  isChecking: boolean;
  lastChecked: Date | null;
  checkConnection: () => Promise<boolean>;
}

const ApiContext = createContext<ApiContextType | undefined>(undefined);

export const ApiProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isLiveApi, setIsLiveApi] = useState<boolean>(apiClient.isLiveMode());
  const [isChecking, setIsChecking] = useState<boolean>(false);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const checkConnection = async (): Promise<boolean> => {
    setIsChecking(true);
    try {
      const isOk = await apiClient.checkHealth();
      setIsLiveApi(isOk);
      setLastChecked(new Date());
      return isOk;
    } finally {
      setIsChecking(false);
    }
  };

  useEffect(() => {
    const unsubscribe = apiClient.subscribeConnectionChange((live) => {
      setIsLiveApi(live);
    });

    checkConnection();

    // Subtle background polling every 20 seconds
    const interval = setInterval(() => {
      checkConnection();
    }, 20000);

    return () => {
      unsubscribe();
      clearInterval(interval);
    };
  }, []);

  return (
    <ApiContext.Provider
      value={{
        isLiveApi,
        isChecking,
        lastChecked,
        checkConnection,
      }}
    >
      {children}
    </ApiContext.Provider>
  );
};

export const useApi = () => {
  const context = useContext(ApiContext);
  if (!context) {
    throw new Error('useApi must be used within an ApiProvider');
  }
  return context;
};
