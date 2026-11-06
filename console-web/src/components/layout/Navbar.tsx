// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useState } from 'react';
import { LogOut, RefreshCw, Moon, Sun, Shield, User } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useApi } from '../../context/ApiContext';
import { CercanoLogo } from '../common/CercanoLogo';

interface NavbarProps {
  darkMode: boolean;
  setDarkMode: (val: boolean | ((prev: boolean) => boolean)) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ darkMode, setDarkMode }) => {
  const { user, logout } = useAuth();
  const { isLiveApi, isChecking, checkConnection } = useApi();
  const [showUserMenu, setShowUserMenu] = useState(false);

  return (
    <header className="sticky top-0 z-40 w-full apple-glass transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        {/* Left: Brand Identity */}
        <div className="flex items-center gap-3">
          <CercanoLogo size={34} showWordmark={true} />
          <span className="hidden sm:inline-block text-[11px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-md bg-cercano-blue/10 text-cercano-blue dark:bg-cercano-blue/20 dark:text-blue-300">
            Consola Web
          </span>
        </div>

        {/* Right: API Mode Pill, Theme Switch, User Avatar */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Live API / Mock Status Pill */}
          <div
            onClick={() => checkConnection()}
            title={isLiveApi ? 'Conectado a cercano-api en puerto 21114' : 'Haga clic para intentar reconectar con cercano-api en puerto 21114'}
            className={`btn-apple flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium cursor-pointer border backdrop-blur-md transition-all ${
              isLiveApi
                ? 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-300 border-emerald-500/25'
                : 'bg-amber-500/10 text-amber-800 dark:text-amber-300 border-amber-500/25'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isLiveApi ? 'bg-cercano-green pulse-emerald' : 'bg-amber-400'
              }`}
            />
            <span className="hidden md:inline">
              {isLiveApi ? 'API Conectada (:21114)' : 'Modo Demo / Local'}
            </span>
            <RefreshCw
              size={12}
              className={`opacity-70 ${isChecking ? 'animate-spin' : ''}`}
            />
          </div>

          {/* Dark / Light Mode Toggle */}
          <button
            onClick={() => setDarkMode((prev) => !prev)}
            aria-label="Cambiar tema"
            className="btn-apple p-2 rounded-xl bg-black/5 hover:bg-black/10 dark:bg-white/10 dark:hover:bg-white/15 text-cercano-slate dark:text-gray-300 transition-colors"
          >
            {darkMode ? <Sun size={17} /> : <Moon size={17} />}
          </button>

          {/* User Account Avatar & Popover */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="btn-apple flex items-center gap-2 p-1.5 pr-3 rounded-full bg-black/5 hover:bg-black/10 dark:bg-white/10 dark:hover:bg-white/15 border border-black/5 dark:border-white/[0.04]"
            >
              <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cercano-blue to-cercano-green flex items-center justify-center text-white text-xs font-bold shadow-sm">
                {user?.username ? user.username.charAt(0).toUpperCase() : 'A'}
              </div>
              <span className="text-xs font-semibold text-cercano-night dark:text-white max-w-[90px] truncate">
                {user?.username || 'admin'}
              </span>
            </button>

            {/* Account Popover Menu */}
            {showUserMenu && (
              <>
                <div
                  className="fixed inset-0 z-40"
                  onClick={() => setShowUserMenu(false)}
                />
                <div className="absolute right-0 mt-2 w-56 origin-top-right bg-white/95 dark:bg-zinc-900/95 backdrop-blur-xl rounded-2xl shadow-xl border border-black/10 dark:border-white/[0.08] py-2 z-50 animate-scale-spring">
                  <div className="px-4 py-2 border-b border-black/5 dark:border-white/[0.04]">
                    <p className="text-xs text-cercano-slate dark:text-gray-400">
                      Sesión activa como
                    </p>
                    <p className="text-sm font-bold text-cercano-night dark:text-white flex items-center gap-1.5 mt-0.5">
                      <Shield size={14} className="text-cercano-blue" />
                      {user?.username} ({user?.role})
                    </p>
                  </div>

                  <div className="px-2 py-1">
                    <div className="px-3 py-1.5 text-xs text-cercano-slate dark:text-gray-400 flex items-center gap-2">
                      <User size={14} /> ID: <code className="text-[10px]">{user?.id}</code>
                    </div>

                    <button
                      onClick={() => {
                        setShowUserMenu(false);
                        logout();
                      }}
                      className="w-full text-left px-3 py-2 text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-500/10 rounded-xl flex items-center gap-2 transition-colors cursor-pointer mt-1"
                    >
                      <LogOut size={14} />
                      Cerrar sesión
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
