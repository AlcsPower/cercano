// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React from 'react';
import { LayoutDashboard, Monitor, Palette, KeyRound, Network } from 'lucide-react';
import { ActiveTab } from '../../types';

interface TabBarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  onlineCount?: number;
  totalDevices?: number;
}

export const TabBar: React.FC<TabBarProps> = ({
  activeTab,
  setActiveTab,
  onlineCount = 0,
}) => {
  const tabs: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: number }[] = [
    {
      id: 'dashboard',
      label: 'Panel General',
      icon: <LayoutDashboard size={18} />,
    },
    {
      id: 'devices',
      label: 'Dispositivos',
      icon: <Monitor size={18} />,
      badge: onlineCount,
    },
    {
      id: 'builder',
      label: 'Personalizador',
      icon: <Palette size={18} />,
    },
    {
      id: 'security',
      label: 'Claves y Seguridad',
      icon: <KeyRound size={18} />,
    },
    {
      id: 'network',
      label: 'Servidor y Red',
      icon: <Network size={18} />,
    },
  ];

  return (
    <div className="w-full flex justify-center py-4 px-4 sticky top-16 z-30 pointer-events-none">
      <nav
        aria-label="Navegación principal"
        className="pointer-events-auto inline-flex items-center p-1.5 rounded-2xl bg-white/70 dark:bg-zinc-800/70 backdrop-blur-xl border border-black/10 dark:border-white/10 shadow-apple-card max-w-full overflow-x-auto"
      >
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              aria-label={tab.label}
              aria-current={isActive ? 'page' : undefined}
              className={`btn-apple relative flex items-center gap-2 px-3 sm:px-4 py-2 rounded-xl text-xs sm:text-sm font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                isActive
                  ? 'bg-cercano-blue text-white shadow-sm shadow-cercano-blue/30'
                  : 'text-cercano-slate dark:text-gray-300 hover:text-cercano-night dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5'
              }`}
            >
              <span>{tab.icon}</span>
              <span className="hidden md:inline">{tab.label}</span>
              {typeof tab.badge === 'number' && tab.badge > 0 && (
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold leading-tight ${
                    isActive
                      ? 'bg-white/25 text-white'
                      : 'bg-cercano-green/20 text-cercano-green-dark dark:text-cercano-green'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </div>
  );
};
