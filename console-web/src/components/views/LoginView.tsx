// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useState } from 'react';
import {
  Lock,
  ArrowRight,
  AlertCircle,
  Server,
  KeyRound,
  ShieldCheck,
  ArrowLeft,
  LifeBuoy,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { useApi } from '../../context/ApiContext';
import { CercanoLogo } from '../common/CercanoLogo';
import { AppleButton } from '../common/AppleButton';

type LoginStep = 'credentials' | 'mfa';
type MfaMode = 'totp' | 'recovery';

export const LoginView: React.FC = () => {
  const { isLiveApi } = useApi();
  const [step, setStep] = useState<LoginStep>('credentials');
  const [mfaMode, setMfaMode] = useState<MfaMode>('totp');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [hasShaked, setHasShaked] = useState(false);

  const triggerShake = () => {
    setHasShaked(true);
    setTimeout(() => setHasShaked(false), 450);
  };

  // Step 1: Submit Username & Password
  const handleCredentialsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError('Por favor complete todos los campos.');
      triggerShake();
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const result = await apiClient.login(username.trim(), password.trim());
      if (result.kind === 'mfa_required') {
        setMfaToken(result.challenge.mfa_token);
        setStep('mfa');
        setMfaMode('totp');
        setTotpCode('');
        setRecoveryCode('');
      } else {
        // Direct login success (no 2FA required)
        window.location.reload();
      }
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

  // Step 2: Submit 2FA Code (TOTP or Recovery)
  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (mfaMode === 'totp') {
      const cleanCode = totpCode.trim().replace(/\s+/g, '');
      if (cleanCode.length !== 6) {
        setError('Ingrese los 6 dígitos del código de autenticación.');
        triggerShake();
        return;
      }

      setIsSubmitting(true);
      try {
        await apiClient.verify2fa({
          mfa_token: mfaToken,
          totp_code: cleanCode,
        });
        window.location.reload();
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('Código de verificación inválido.');
        }
        triggerShake();
      } finally {
        setIsSubmitting(false);
      }
    } else {
      // Recovery mode
      const cleanRecovery = recoveryCode.trim().toUpperCase();
      if (!cleanRecovery || cleanRecovery.length < 10) {
        setError('Ingrese un código de recuperación válido (formato XXXX-XXXX-XXXX).');
        triggerShake();
        return;
      }

      setIsSubmitting(true);
      try {
        await apiClient.verify2fa({
          mfa_token: mfaToken,
          recovery_code: cleanRecovery,
        });
        window.location.reload();
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError('Código de recuperación inválido o ya utilizado.');
        }
        triggerShake();
      } finally {
        setIsSubmitting(false);
      }
    }
  };

  const handleBackToCredentials = () => {
    setStep('credentials');
    setMfaToken('');
    setTotpCode('');
    setRecoveryCode('');
    setError(null);
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
        <div className="flex flex-col items-center text-center mb-7">
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
          <div
            role="alert"
            aria-live="assertive"
            className="mb-5 p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 text-xs flex items-center gap-2.5 animate-fade-in"
          >
            <AlertCircle size={16} className="shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* STEP 1: CREDENTIALS FORM */}
        {step === 'credentials' && (
          <form onSubmit={handleCredentialsSubmit} className="space-y-4 animate-fade-in">
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
                Continuar
              </AppleButton>
            </div>
          </form>
        )}

        {/* STEP 2: 2FA MFA CHALLENGE FORM */}
        {step === 'mfa' && (
          <form onSubmit={handleMfaSubmit} className="space-y-4 animate-fade-in">
            <div className="p-3 rounded-2xl bg-cercano-blue/10 border border-cercano-blue/20 text-center space-y-1">
              <div className="inline-flex p-2 rounded-xl bg-cercano-blue/15 text-cercano-blue mb-1">
                <KeyRound size={20} />
              </div>
              <h2 className="text-xs font-bold text-cercano-night dark:text-white uppercase tracking-wider">
                Verificación de Segundo Factor
              </h2>
              <p className="text-[11px] text-cercano-slate dark:text-gray-400">
                {mfaMode === 'totp'
                  ? 'Ingrese el código de 6 dígitos generado por su app autenticadora'
                  : 'Ingrese un código de recuperación de 12 caracteres (XXXX-XXXX-XXXX)'}
              </p>
            </div>

            {mfaMode === 'totp' ? (
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1 text-center">
                  Código de Autenticación TOTP (RFC 6238)
                </label>
                <input
                  type="text"
                  maxLength={6}
                  pattern="[0-9]*"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  className="w-full text-center text-2xl font-mono tracking-widest px-4 py-3 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white placeholder:text-gray-300 focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-bold"
                />
              </div>
            ) : (
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1 text-center">
                  Código de Recuperación de Un Solo Uso
                </label>
                <input
                  type="text"
                  autoFocus
                  value={recoveryCode}
                  onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                  placeholder="CRCN-XXXX-XXXX"
                  className="w-full text-center text-sm font-mono tracking-wider px-4 py-3 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 uppercase font-semibold"
                />
              </div>
            )}

            <div className="pt-2 space-y-2">
              <AppleButton
                type="submit"
                variant="primary"
                size="lg"
                isLoading={isSubmitting}
                className="w-full justify-center text-sm font-semibold shadow-md"
                icon={<ShieldCheck size={16} />}
              >
                Verificar y Acceder
              </AppleButton>

              <div className="flex items-center justify-between pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setMfaMode(mfaMode === 'totp' ? 'recovery' : 'totp');
                    setError(null);
                  }}
                  className="inline-flex items-center gap-1.5 text-xs text-cercano-blue hover:underline cursor-pointer"
                >
                  <LifeBuoy size={12} />
                  {mfaMode === 'totp'
                    ? '¿No tienes acceso al autenticador? Usar código de recuperación'
                    : 'Regresar a código TOTP'}
                </button>

                <button
                  type="button"
                  onClick={handleBackToCredentials}
                  className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-cercano-night dark:hover:text-white cursor-pointer"
                >
                  <ArrowLeft size={12} /> Volver
                </button>
              </div>
            </div>
          </form>
        )}

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
