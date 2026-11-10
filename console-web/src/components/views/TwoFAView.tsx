// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  KeyRound,
  Copy,
  Check,
  Download,
  AlertTriangle,
  AlertCircle,
  ArrowRight,
  Trash2,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import { TwoFactorEnrollResponse } from '../../types';
import { AppleButton } from '../common/AppleButton';

export const TwoFAView: React.FC = () => {
  const { user } = useAuth();
  const [is2faActive, setIs2faActive] = useState<boolean>(false);
  const [isCheckingStatus, setIsCheckingStatus] = useState<boolean>(true);
  const [stage, setStage] = useState<'idle' | 'enrolling' | 'confirmed'>('idle');
  const [enrollData, setEnrollData] = useState<TwoFactorEnrollResponse | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);

  // Synchronize 2FA status on mount against backend
  useEffect(() => {
    let isMounted = true;
    const check2faStatus = async () => {
      setIsCheckingStatus(true);
      try {
        const users = await apiClient.getUsers();
        const currentUser =
          users.find(
            (u) =>
              (user?.id && u.id === user.id) ||
              (user?.username && u.username === user.username)
          ) || (users.length === 1 ? users[0] : undefined);

        if (currentUser && isMounted) {
          const active =
            currentUser.totp_enabled === true ||
            (currentUser.totp_enabled as unknown === 1) ||
            currentUser.is_2fa_required === true ||
            (currentUser.is_2fa_required as unknown === 1);
          setIs2faActive(Boolean(active));
        }
      } catch (err: unknown) {
        if (isMounted && err instanceof Error) {
          setError(err.message);
        }
      } finally {
        if (isMounted) {
          setIsCheckingStatus(false);
        }
      }
    };

    check2faStatus();

    return () => {
      isMounted = false;
    };
  }, [user?.id, user?.username]);

  const startEnrollment = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiClient.enroll2fa();
      setEnrollData(data);
      setStage('enrolling');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Error al iniciar el enrolamiento 2FA.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmTotp = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = totpCode.trim().replace(/\s+/g, '');
    if (cleanCode.length !== 6) {
      setError('El código TOTP debe tener exactamente 6 dígitos numéricos.');
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      const resp = await apiClient.confirm2fa(cleanCode);
      setRecoveryCodes(resp.recovery_codes || []);
      setIs2faActive(true);
      setStage('confirmed');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Código de verificación inválido. Intente nuevamente.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopySecret = async () => {
    if (!enrollData?.totp_secret_base32) return;
    try {
      await navigator.clipboard.writeText(enrollData.totp_secret_base32);
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleCopyRecoveryCodes = async () => {
    if (recoveryCodes.length === 0) return;
    try {
      const text = [
        '# Códigos de Recuperación Cercano (8 códigos de un solo uso)',
        '# Usuario: ' + (user?.username || 'admin'),
        '# Fecha: ' + new Date().toISOString(),
        '',
        ...recoveryCodes,
      ].join('\n');
      await navigator.clipboard.writeText(text);
      setCopiedCodes(true);
      setTimeout(() => setCopiedCodes(false), 2000);
    } catch {
      // Fallback
    }
  };

  const handleDownloadRecoveryCodes = () => {
    if (recoveryCodes.length === 0) return;
    const text = [
      '====================================================',
      ' CERCANO - CÓDIGOS DE RECUPERACIÓN DE UN SOLO USO',
      '====================================================',
      'Usuario: ' + (user?.username || 'admin'),
      'Fecha de emisión: ' + new Date().toISOString(),
      '',
      'IMPORTANTE: Cada código solo puede ser utilizado una única vez',
      'en caso de no tener acceso a su aplicación autenticadora.',
      'Guarde este archivo en un medio cifrado o imprímalo en papel.',
      '----------------------------------------------------',
      ...recoveryCodes.map((code, idx) => `[${idx + 1}] ${code}`),
      '====================================================',
    ].join('\n');

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cercano-recovery-codes-${user?.username || 'user'}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleRevoke2fa = async () => {
    setIsRevoking(true);
    setError(null);
    try {
      await apiClient.revoke2fa();
      setIs2faActive(false);
      setStage('idle');
      setEnrollData(null);
      setTotpCode('');
      setRecoveryCodes([]);
      setShowRevokeModal(false);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Error al revocar el segundo factor.');
      }
    } finally {
      setIsRevoking(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto px-4 sm:px-6 py-6 animate-fade-in">
      {/* View Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-cercano-night dark:text-white flex items-center gap-2.5">
          <KeyRound className="text-cercano-blue" size={26} />
          Autenticación de Dos Factores (2FA TOTP)
        </h2>
        <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
          Proteja su cuenta institucional con códigos temporales RFC 6238 y llaves de recuperación
        </p>
      </div>

      {error && (
        <div
          role="alert"
          aria-live="assertive"
          className="p-3.5 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 text-xs flex items-center justify-between animate-fade-in"
        >
          <div className="flex items-center gap-2">
            <AlertCircle size={16} aria-hidden="true" className="shrink-0" />
            <span>{error}</span>
          </div>
          <button
            type="button"
            onClick={() => setError(null)}
            aria-label="Cerrar notificación de error"
            className="font-bold ml-2 hover:opacity-75 focus:outline-none focus:ring-1 focus:ring-red-500/40 rounded"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Status Card */}
      <div className="p-6 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div
              className={`w-12 h-12 rounded-2xl flex items-center justify-center ${
                is2faActive
                  ? 'bg-emerald-500/10 text-emerald-500'
                  : 'bg-amber-500/10 text-amber-500'
              }`}
            >
              {is2faActive ? <ShieldCheck size={26} /> : <ShieldAlert size={26} />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-sm text-cercano-night dark:text-white">
                  Estado del Segundo Factor:
                </h3>
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                    isCheckingStatus
                      ? 'bg-black/5 dark:bg-white/5 text-gray-400'
                      : is2faActive
                      ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                      : 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                  }`}
                >
                  {isCheckingStatus ? 'Verificando...' : is2faActive ? 'Activo' : 'No configurado'}
                </span>
              </div>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mt-0.5">
                {is2faActive
                  ? 'Su cuenta requiere un código de 6 dígitos al iniciar sesión desde cualquier navegador.'
                  : 'Se recomienda activar 2FA para proteger accesos privilegiados y datos de auditoría.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {is2faActive ? (
              <AppleButton
                variant="danger"
                size="sm"
                onClick={() => setShowRevokeModal(true)}
                icon={<Trash2 size={14} />}
                disabled={isCheckingStatus}
              >
                Desvincular 2FA
              </AppleButton>
            ) : stage === 'idle' ? (
              <AppleButton
                variant="primary"
                size="sm"
                isLoading={isLoading}
                disabled={isCheckingStatus}
                onClick={startEnrollment}
                icon={<Shield size={14} />}
              >
                Configurar 2FA
              </AppleButton>
            ) : null}
          </div>
        </div>
      </div>

      {/* Stage: Enrolling (Step 1 & Step 2) */}
      {stage === 'enrolling' && enrollData && (
        <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] p-6 shadow-sm space-y-6 animate-scale-spring">
          <div className="flex items-center justify-between border-b border-black/5 dark:border-white/[0.04] pb-4">
            <div>
              <h3 className="text-base font-bold text-cercano-night dark:text-white">
                Asistente de Enrolamiento TOTP
              </h3>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Siga los dos pasos a continuación para activar el factor en su dispositivo
              </p>
            </div>
            <button
              onClick={() => {
                setStage('idle');
                setEnrollData(null);
                setTotpCode('');
              }}
              className="text-xs text-gray-500 hover:text-cercano-night dark:hover:text-white"
            >
              Cancelar
            </button>
          </div>

          {/* Step 1: Secret Base32 & URI */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-cercano-blue text-white text-[11px] font-bold flex items-center justify-center">
                1
              </span>
              <h4 className="text-xs font-bold uppercase tracking-wider text-cercano-night dark:text-white">
                Vincular aplicación autenticadora
              </h4>
            </div>
            <p className="text-xs text-cercano-slate dark:text-gray-400 pl-7">
              Abra su aplicación (Google Authenticator, Microsoft Authenticator, 1Password, etc.) y añada una
              cuenta manualmente usando la clave secreta o enlace:
            </p>

            <div className="pl-7 space-y-3 max-w-xl">
              <div>
                <label className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider block mb-1">
                  Clave Secreta Base32 (RFC 6238)
                </label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 px-3 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-xs text-cercano-blue dark:text-sky-400 select-all font-bold tracking-wider">
                    {enrollData.totp_secret_base32}
                  </code>
                  <AppleButton
                    variant="secondary"
                    size="sm"
                    onClick={handleCopySecret}
                    icon={copiedSecret ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  >
                    {copiedSecret ? 'Copiado' : 'Copiar'}
                  </AppleButton>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider block mb-1">
                  URI de Aprovisionamiento (otpauth://)
                </label>
                <code className="block px-3 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-[11px] text-gray-600 dark:text-gray-400 break-all select-all">
                  {enrollData.otpauth_uri}
                </code>
              </div>
            </div>
          </div>

          {/* Step 2: Verification Code Input */}
          <div className="space-y-3 border-t border-black/5 dark:border-white/[0.04] pt-5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-cercano-blue text-white text-[11px] font-bold flex items-center justify-center">
                2
              </span>
              <h4 className="text-xs font-bold uppercase tracking-wider text-cercano-night dark:text-white">
                Confirmar código de 6 dígitos
              </h4>
            </div>
            <p className="text-xs text-cercano-slate dark:text-gray-400 pl-7">
              Ingrese el código temporal generado por su aplicación para validar el secreto:
            </p>

            <form onSubmit={handleConfirmTotp} className="pl-7 space-y-4 max-w-sm">
              <div>
                <input
                  type="text"
                  maxLength={6}
                  pattern="[0-9]*"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="123456"
                  className="w-full text-center text-xl font-mono tracking-widest px-4 py-3 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-cercano-night dark:text-white focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-bold"
                />
              </div>

              <div className="flex gap-2">
                <AppleButton
                  variant="primary"
                  type="submit"
                  size="md"
                  isLoading={isLoading}
                  disabled={totpCode.trim().length !== 6}
                  className="w-full justify-center text-xs font-semibold"
                  icon={<ArrowRight size={14} />}
                >
                  Activar Segundo Factor
                </AppleButton>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Stage: Confirmed (Display 8 Recovery Codes) */}
      {stage === 'confirmed' && recoveryCodes.length > 0 && (
        <div
          role="status"
          aria-live="polite"
          className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-emerald-500/30 p-6 shadow-sm space-y-5 animate-fade-in"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center shrink-0">
              <ShieldCheck size={22} />
            </div>
            <div>
              <h3 className="text-base font-bold text-cercano-night dark:text-white">
                ¡2FA Activado Correctamente!
              </h3>
              <p className="text-xs text-cercano-slate dark:text-gray-400">
                Guarde sus 8 códigos de recuperación de un solo uso
              </p>
            </div>
          </div>

          {/* Warning Box */}
          <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-400 text-xs flex items-start gap-2.5">
            <AlertTriangle size={16} className="shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong>Atención crítica:</strong> Cada uno de estos códigos solo puede utilizarse una única vez.
              Si pierde el acceso a su aplicación autenticadora, estos códigos son su única forma de recuperar su
              cuenta sin intervención del administrador. No se mostrarán de nuevo.
            </p>
          </div>

          {/* Grid of Recovery Codes */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-4 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-center text-xs font-bold text-cercano-night dark:text-white">
            {recoveryCodes.map((code, idx) => (
              <div
                key={code}
                className="py-2.5 px-2 bg-white dark:bg-zinc-800 rounded-xl shadow-xs border border-black/5 dark:border-white/[0.04] select-all"
              >
                <span className="text-[10px] text-gray-400 mr-1.5">{idx + 1}.</span>
                {code}
              </div>
            ))}
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <div className="flex items-center gap-2">
              <AppleButton
                variant="secondary"
                size="sm"
                onClick={handleCopyRecoveryCodes}
                icon={copiedCodes ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
              >
                {copiedCodes ? 'Códigos Copiados' : 'Copiar Todos'}
              </AppleButton>
              <AppleButton
                variant="secondary"
                size="sm"
                onClick={handleDownloadRecoveryCodes}
                icon={<Download size={14} />}
              >
                Descargar (.txt)
              </AppleButton>
            </div>

            <AppleButton
              variant="primary"
              size="sm"
              onClick={() => {
                setStage('idle');
                setEnrollData(null);
                setTotpCode('');
                setRecoveryCodes([]);
              }}
              icon={<Check size={14} />}
            >
              He Guardado Mis Códigos
            </AppleButton>
          </div>
        </div>
      )}

      {/* Revocation Confirmation Modal */}
      {showRevokeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md bg-white dark:bg-zinc-900 rounded-3xl p-6 shadow-2xl border border-black/10 dark:border-white/[0.08] space-y-4">
            <div className="flex items-center gap-3 text-red-500">
              <AlertTriangle size={24} />
              <h3 className="text-base font-bold text-cercano-night dark:text-white">
                ¿Desvincular Autenticación 2FA?
              </h3>
            </div>
            <p className="text-xs text-cercano-slate dark:text-gray-400 leading-relaxed">
              Esta acción eliminará el factor TOTP configurado y revocará inmediatamente todos los códigos de
              recuperación existentes. Si la directiva de la institución exige 2FA obligatorio, no podrá acceder
              hasta volver a enrolarse.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <AppleButton
                variant="secondary"
                size="sm"
                onClick={() => setShowRevokeModal(false)}
                disabled={isRevoking}
              >
                Cancelar
              </AppleButton>
              <AppleButton
                variant="danger"
                size="sm"
                isLoading={isRevoking}
                onClick={handleRevoke2fa}
                icon={<Trash2 size={14} />}
              >
                Confirmar Desvinculación
              </AppleButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
