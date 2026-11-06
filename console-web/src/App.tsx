// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useState, useEffect } from 'react';
import { useAuth } from './context/AuthContext';
import { Navbar } from './components/layout/Navbar';
import { TabBar } from './components/layout/TabBar';
import { LoginView } from './components/views/LoginView';
import { DashboardView } from './components/views/DashboardView';
import { DevicesView } from './components/views/DevicesView';
import { BuilderView } from './components/views/BuilderView';
import { SecurityView } from './components/views/SecurityView';
import { NetworkView } from './components/views/NetworkView';
import { ActiveTab } from './types';
import { apiClient } from './api/client';

export const App: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    return (
      localStorage.getItem('cercano_theme') === 'dark' ||
      (!('cercano_theme' in localStorage) &&
        window.matchMedia('(prefers-color-scheme: dark)').matches)
    );
  });
  const [isRotateModalOpen, setIsRotateModalOpen] = useState(false);
  const [onlineCount, setOnlineCount] = useState<number>(0);
  const [totalDevices, setTotalDevices] = useState<number>(0);

  // Sync dark class on document root
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('cercano_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('cercano_theme', 'light');
    }
  }, [darkMode]);

  // Fetch quick metrics for tab badge
  useEffect(() => {
    if (isAuthenticated) {
      apiClient.getDevices().then((devs) => {
        setTotalDevices(devs.length);
        setOnlineCount(devs.filter((d) => d.status === 'online').length);
      });
    }
  }, [isAuthenticated, activeTab]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-apple-canvas dark:bg-apple-canvas-dark">
        <div className="flex flex-col items-center gap-3 animate-fade-in">
          <div className="w-10 h-10 border-3 border-cercano-blue/20 border-t-cercano-blue rounded-full animate-spin" />
          <span className="text-xs font-semibold text-cercano-slate dark:text-gray-400">
            Iniciando Cercano...
          </span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginView />;
  }

  return (
    <div className="min-h-screen flex flex-col bg-apple-canvas dark:bg-apple-canvas-dark text-cercano-night dark:text-white transition-colors duration-200">
      {/* Top Floating Glass Header */}
      <Navbar darkMode={darkMode} setDarkMode={setDarkMode} />

      {/* Segmented Controller Tab Bar */}
      <TabBar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onlineCount={onlineCount}
        totalDevices={totalDevices}
      />

      {/* Main Content View with symmetric layout */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pb-16">
        {activeTab === 'dashboard' && (
          <DashboardView
            setActiveTab={setActiveTab}
            openRotateKeyModal={() => {
              setActiveTab('security');
              setIsRotateModalOpen(true);
            }}
          />
        )}

        {activeTab === 'devices' && <DevicesView />}

        {activeTab === 'builder' && <BuilderView />}

        {activeTab === 'security' && (
          <SecurityView
            isRotateModalOpen={isRotateModalOpen}
            setIsRotateModalOpen={setIsRotateModalOpen}
          />
        )}

        {activeTab === 'network' && <NetworkView setActiveTab={setActiveTab} />}
      </main>

      {/* Bottom Legal & Project Footer */}
      <footer className="w-full border-t border-black/5 dark:border-white/10 py-6 text-center text-xs text-cercano-slate dark:text-gray-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p>
            Cercano Â© 2026 Cercano Contributors. Distribuido bajo licencia{' '}
            <span className="font-semibold text-cercano-night dark:text-white">AGPL-3.0</span>.
          </p>
          <p className="text-[11px]">
            Â«Soporte remoto, como si estuvieras ahÃ­.Â»
          </p>
        </div>
      </footer>
    </div>
  );
};
