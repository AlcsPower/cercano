// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useRef } from 'react';
import {
  LayoutDashboard,
  Monitor,
  MessageCircle,
  Palette,
  KeyRound,
  Network,
  Users,
  Shield,
  ScrollText,
  Sliders,
  ShieldCheck,
  BookOpen,
} from 'lucide-react';
import { ActiveTab, UserRole } from '../../types';

export interface TabBarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  userRole?: UserRole | string;
  onlineCount?: number;
  totalDevices?: number;
  chatBadge?: number;
}

export function isTabVisibleForRole(tabId: ActiveTab, role?: UserRole | string): boolean {
  const currentRole = role || 'user';
  switch (currentRole) {
    case 'admin':
      return true; // admin: all tabs
    case 'operator':
      // operator: dashboard, devices, builder, chat, settings, twofa, network, identity
      return ['dashboard', 'devices', 'builder', 'chat', 'settings', 'twofa', 'network', 'identity'].includes(tabId);
    case 'auditor':
      // auditor: dashboard, devices, audit, settings, chat, twofa, network, identity
      return ['dashboard', 'devices', 'audit', 'settings', 'chat', 'twofa', 'network', 'identity'].includes(tabId);
    case 'user':
    default:
      // user: read-only subset
      return ['dashboard', 'devices', 'chat', 'settings', 'twofa'].includes(tabId);
  }
}

export const TabBar: React.FC<TabBarProps> = ({
  activeTab,
  setActiveTab,
  userRole = 'user',
  onlineCount = 0,
  chatBadge = 0,
}) => {
  const navRef = useRef<HTMLElement>(null);

  const allTabs: { id: ActiveTab; label: string; icon: React.ReactNode; badge?: number }[] = [
    {
      id: 'dashboard',
      label: 'Panel General',
      icon: <LayoutDashboard size={17} />,
    },
    {
      id: 'devices',
      label: 'Dispositivos',
      icon: <Monitor size={17} />,
      badge: onlineCount,
    },
    {
      id: 'users',
      label: 'Usuarios',
      icon: <Users size={17} />,
    },
    {
      id: 'roles',
      label: 'Roles y RBAC',
      icon: <Shield size={17} />,
    },
    {
      id: 'identity',
      label: 'Estrategias e Identidad',
      icon: <BookOpen size={17} />,
    },
    {
      id: 'audit',
      label: 'Auditoría',
      icon: <ScrollText size={17} />,
    },
    {
      id: 'chat',
      label: 'Conversaciones',
      icon: <MessageCircle size={17} />,
      badge: chatBadge,
    },
    {
      id: 'builder',
      label: 'Personalizador',
      icon: <Palette size={17} />,
    },
    {
      id: 'twofa',
      label: '2FA TOTP',
      icon: <ShieldCheck size={17} />,
    },
    {
      id: 'security',
      label: 'Claves y Seguridad',
      icon: <KeyRound size={17} />,
    },
    {
      id: 'network',
      label: 'Servidor y Red',
      icon: <Network size={17} />,
    },
    {
      id: 'settings',
      label: 'Ajustes',
      icon: <Sliders size={17} />,
    },
  ];

  const visibleTabs = allTabs.filter((tab) => isTabVisibleForRole(tab.id, userRole));

  const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      const nextIdx = (index + 1) % visibleTabs.length;
      setActiveTab(visibleTabs[nextIdx].id);
      focusTab(nextIdx);
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prevIdx = (index - 1 + visibleTabs.length) % visibleTabs.length;
      setActiveTab(visibleTabs[prevIdx].id);
      focusTab(prevIdx);
    } else if (e.key === 'Home') {
      e.preventDefault();
      setActiveTab(visibleTabs[0].id);
      focusTab(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      const lastIdx = visibleTabs.length - 1;
      setActiveTab(visibleTabs[lastIdx].id);
      focusTab(lastIdx);
    }
  };

  const focusTab = (idx: number) => {
    const buttons = navRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    if (buttons && buttons[idx]) {
      buttons[idx].focus();
    }
  };

  return (
    <div className="w-full flex justify-center py-3 px-4 sticky top-16 z-30 pointer-events-none">
      <nav
        ref={navRef}
        role="tablist"
        aria-label="Navegación principal de la consola"
        className="pointer-events-auto inline-flex items-center p-1.5 rounded-2xl bg-white/70 dark:bg-zinc-800/70 backdrop-blur-xl border border-black/10 dark:border-white/[0.06] shadow-xl shadow-black/5 dark:shadow-black/50 max-w-full overflow-x-auto gap-1"
      >
        {visibleTabs.map((tab, idx) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              role="tab"
              tabIndex={isActive ? 0 : -1}
              onClick={() => setActiveTab(tab.id)}
              onKeyDown={(e) => handleKeyDown(e, idx)}
              aria-label={tab.label}
              aria-selected={isActive}
              aria-current={isActive ? 'page' : undefined}
              className={`btn-apple relative flex items-center gap-2 px-3 sm:px-3.5 py-1.5 rounded-xl text-xs sm:text-sm font-semibold transition-colors whitespace-nowrap cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue ${
                isActive
                  ? 'bg-cercano-blue text-white shadow-sm shadow-cercano-blue/30'
                  : 'text-cercano-slate dark:text-gray-300 hover:text-cercano-night dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5'
              }`}
            >
              <span>{tab.icon}</span>
              <span className="hidden md:inline text-xs">{tab.label}</span>
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
