// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useState } from 'react';
import { Lock, ArrowRight, AlertCircle, Server } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useApi } from '../../context/ApiContext';
import { CercanoLogo } from '../common/CercanoLogo';
import { AppleButton } from '../common/AppleButton';

export const LoginView: React.FC = () => {
  const { login } = useAuth();
  const { isLiveApi } = useApi();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [hasShaked, setHasShaked] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Por favor complete todos los campos.');
      triggerShake();
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await login(username.trim(), password.trim());
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Error al iniciar sesión. Verifique sus credenciales.');
      }
      triggerShake();
    } finally {
      setIsSubmitting(false);
    }
  };

  const triggerShake = () => {
    setHasShaked(true);
    setTimeout(() => setHasShaked(false), 450);
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 relative overflow-hidden bg-gradient-to-br from-[#E2E8F6] via-[#F2F5FB] to-[#DDE5F5] dark:from-[#070D18] dark:via-[#0B1426] dark:to-[#040810]">
      {/* Decorative ambient Apple aura */}
      <div className="absolute w-[500px] h-[500px] rounded-full bg-cercano-blue/15 dark:bg-cercano-blue/10 blur-[120px] pointer-events-none -top-24 -left-24 opacity-80" />
      <div className="absolute w-[400px] h-[400px] rounded-full bg-cercano-green/15 dark:bg-cercano-green/10 blur-[100px] pointer-events-none -bottom-20 -right-20 opacity-80" />

      {/* Main Glass Lock Card */}
      <div
        className={`relative w-full max-w-md bg-white/75 dark:bg-zinc-900/75 backdrop-blur-3xl rounded-[32px] p-8 sm:p-10 shadow-apple-modal border border-black/5 dark:border-white/[0.04] animate-scale-spring ${
          hasShaked ? 'animate-shake' : ''
        }`}
      >
        {/* Top: Avatar & App Branding */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="relative mb-4">
            <div className="w-20 h-20 rounded-3xl bg-white/80 dark:bg-zinc-800/80 shadow-apple-card border border-black/5 dark:border-white/[0.04] flex items-center justify-center p-3">
              <CercanoLogo size={52} />
            </div>
            {/* Live indicator dot */}
            <span
              title={isLiveApi ? 'cercano-api disponible' : 'cercano-api no detectado'}
              className={`absolute -bottom-1 -right-1 w-5 h-5 rounded-full border-2 border-white dark:border-zinc-900 flex items-center justify-center ${
                isLiveApi ? 'bg-cercano-green pulse-emerald' : 'bg-amber-400'
              }`}
            >
              <Server size={10} className="text-white" />
            </span>
          </div>

          <h1 className="text-2xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Consola Cercano
          </h1>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
            Administración segura de infraestructura de soporte remoto
          </p>
        </div>

        {/* Error Callout */}
        {error && (
          <div className="mb-6 p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 text-xs flex items-center gap-2.5 animate-fade-in">
            <AlertCircle size={16} className="shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
              Usuario de Administrador
            </label>
            <div className="relative">
              <input
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                className="w-full px-4 py-3 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 text-sm transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
              Contraseña
            </label>
            <div className="relative">
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-4 py-3 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 text-sm transition-all pr-10"
              />
              <Lock
                size={16}
                className="absolute right-3.5 top-3.5 text-gray-400 dark:text-gray-500"
              />
            </div>
          </div>

          <div className="pt-2">
            <AppleButton
              type="submit"
              variant="primary"
              size="lg"
              isLoading={isSubmitting}
              className="w-full justify-center text-sm font-semibold shadow-md"
              icon={<ArrowRight size={16} />}
            >
              Iniciar Sesión
            </AppleButton>
          </div>
        </form>

        {/* Status footer */}
        <div className="mt-6 pt-5 border-t border-black/5 dark:border-white/[0.04] text-center">
          <p className="text-[11px] text-cercano-slate dark:text-gray-400">
            Conexión con <code className="font-mono text-gray-600 dark:text-gray-300">cercano-api</code> en puerto 21114
          </p>
        </div>
      </div>
    </div>
  );
};
