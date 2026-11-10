// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import { Sliders, Save, CheckCircle, AlertCircle, Building2 } from 'lucide-react';
import { apiClient } from '../../api/client';
import { GeneralSettings } from '../../types';
import { AppleButton } from '../common/AppleButton';

export const SettingsView: React.FC = () => {
  const [settings, setSettings] = useState<GeneralSettings>({
    organization_name: 'Cercano Soporte Remoto',
    support_email: 'soporte@institucion.gob.ni',
    session_timeout_minutes: 60,
    enforce_2fa_all: false,
    lan_discovery_enabled: true,
    allow_registration: false,
  });
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    apiClient.getSettings().then(setSettings).catch(() => {});
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await apiClient.updateSettings(settings);
      setSuccess('Ajustes institucionales guardados correctamente');
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('Error al guardar ajustes institucionales');
      }
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto px-4 sm:px-6 py-6 animate-fade-in">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-cercano-night dark:text-white flex items-center gap-2.5">
          <Sliders className="text-cercano-blue" size={26} />
          Ajustes Generales del Servidor
        </h2>
        <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
          Configuración global de directivas de seguridad, tiempos de expiración y red
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

      {success && (
        <div
          role="status"
          aria-live="polite"
          className="p-3.5 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 text-xs flex items-center justify-between animate-fade-in"
        >
          <div className="flex items-center gap-2">
            <CheckCircle size={16} aria-hidden="true" className="shrink-0" />
            <span>{success}</span>
          </div>
          <button
            type="button"
            onClick={() => setSuccess(null)}
            aria-label="Cerrar notificación de confirmación"
            className="font-bold ml-2 hover:opacity-75 focus:outline-none focus:ring-1 focus:ring-emerald-500/40 rounded"
          >
            ✕
          </button>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] p-6 shadow-sm space-y-5">
          <h3 className="text-sm font-bold text-cercano-night dark:text-white border-b border-black/5 dark:border-white/[0.04] pb-3 flex items-center gap-2">
            <Building2 size={16} className="text-cercano-blue" />
            Identidad Institucional y Soporte
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold block text-cercano-night dark:text-white mb-1">
                Nombre de la Organización
              </label>
              <input
                type="text"
                value={settings.organization_name || ''}
                onChange={(e) => setSettings({ ...settings, organization_name: e.target.value })}
                placeholder="ej. Institución de Ejemplo"
                className="w-full px-3.5 py-2 text-xs rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-cercano-night dark:text-white focus:outline-none focus:ring-2 focus:ring-cercano-blue/40"
              />
              <p className="text-[11px] text-gray-500 mt-1">
                Aparece en la cabecera y en los clientes generados
              </p>
            </div>

            <div>
              <label className="text-xs font-semibold block text-cercano-night dark:text-white mb-1">
                Correo Electrónico de Soporte
              </label>
              <input
                type="email"
                value={settings.support_email || ''}
                onChange={(e) => setSettings({ ...settings, support_email: e.target.value })}
                placeholder="soporte@institucion.gob.ni"
                className="w-full px-3.5 py-2 text-xs rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-cercano-night dark:text-white focus:outline-none focus:ring-2 focus:ring-cercano-blue/40"
              />
              <p className="text-[11px] text-gray-500 mt-1">
                Canal oficial de contacto para incidentes de acceso
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] p-6 shadow-sm space-y-5">
          <h3 className="text-sm font-bold text-cercano-night dark:text-white border-b border-black/5 dark:border-white/[0.04] pb-3">
            Directivas de Autenticación y Sesiones
          </h3>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-xs font-semibold block text-cercano-night dark:text-white">
                Tiempo de expiración de sesión (minutos)
              </label>
              <p className="text-[11px] text-gray-500">
                Inactividad máxima permitida antes de revocar el token en la consola web
              </p>
            </div>
            <input
              type="number"
              min="5"
              max="1440"
              value={settings.session_timeout_minutes || 60}
              onChange={(e) =>
                setSettings({ ...settings, session_timeout_minutes: parseInt(e.target.value, 10) })
              }
              className="w-24 px-3 py-1.5 text-xs rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-right font-mono"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-xs font-semibold block text-cercano-night dark:text-white">
                Exigir 2FA obligatorio para todos los roles
              </label>
              <p className="text-[11px] text-gray-500">
                Bloquea el acceso a operadores y técnicos si no tienen configurado un factor TOTP
              </p>
            </div>
            <input
              type="checkbox"
              checked={!!settings.enforce_2fa_all}
              onChange={(e) => setSettings({ ...settings, enforce_2fa_all: e.target.checked })}
              className="w-4 h-4 rounded text-cercano-blue focus:ring-cercano-blue cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-xs font-semibold block text-cercano-night dark:text-white">
                Permitir auto-registro de usuarios
              </label>
              <p className="text-[11px] text-gray-500">
                Desactivado por defecto. Solo los administradores pueden aprovisionar operadores
              </p>
            </div>
            <input
              type="checkbox"
              checked={!!settings.allow_registration}
              onChange={(e) => setSettings({ ...settings, allow_registration: e.target.checked })}
              className="w-4 h-4 rounded text-cercano-blue focus:ring-cercano-blue cursor-pointer"
            />
          </div>
        </div>

        <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] p-6 shadow-sm space-y-5">
          <h3 className="text-sm font-bold text-cercano-night dark:text-white border-b border-black/5 dark:border-white/[0.04] pb-3">
            Descubrimiento y Red LAN
          </h3>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-xs font-semibold block text-cercano-night dark:text-white">
                Difusión de descubrimiento LAN (Broadcast UDP)
              </label>
              <p className="text-[11px] text-gray-500">
                Permite a los clientes de soporte encontrar servidores de señalización en la subred local
              </p>
            </div>
            <input
              type="checkbox"
              checked={settings.lan_discovery_enabled !== false}
              onChange={(e) => setSettings({ ...settings, lan_discovery_enabled: e.target.checked })}
              className="w-4 h-4 rounded text-cercano-blue focus:ring-cercano-blue cursor-pointer"
            />
          </div>
        </div>

        <div className="flex justify-end">
          <AppleButton variant="primary" type="submit" isLoading={isSaving} icon={<Save size={16} />}>
            Guardar Ajustes
          </AppleButton>
        </div>
      </form>
    </div>
  );
};
