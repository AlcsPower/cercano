// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  Upload,
  Copy,
  Check,
  ShieldCheck,
  Server,
  Palette,
  FileCode,
  Laptop,
  CheckCircle2,
} from 'lucide-react';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { apiClient } from '../../api/client';
import { CustomClientProfile } from '../../types';

const COLOR_PRESETS = [
  { name: 'Azul Cercano', hex: '#007AFF' },
  { name: 'Verde Esmeralda', hex: '#10B981' },
  { name: 'Índigo Corporativo', hex: '#6366F1' },
  { name: 'Púrpura Dinámico', hex: '#8B5CF6' },
  { name: 'Grafito Neutro', hex: '#1F2937' },
  { name: 'Naranja Alerta', hex: '#F97316' },
];

export const BuilderView: React.FC = () => {
  const [profile, setProfile] = useState<CustomClientProfile>({
    name: 'Cercano Asistencia',
    company_name: 'Mi Organización TI',
    logo_data: '',
    accent_color: '#007AFF',
    support_info: 'Para soporte llame a la extensión 4000 o soporte@empresa.lan',
    rendezvous_server: '127.0.0.1:21116',
    relay_server: '127.0.0.1:21117',
    api_server: 'http://127.0.0.1:21114',
    public_key: '',
    lock_settings: true,
    portable_mode: false,
    unattended_access: true,
    lan_only: true,
    allow_file_transfer: true,
    allow_terminal: false,
  });

  const [copiedScript, setCopiedScript] = useState<boolean>(false);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [generationDone, setGenerationDone] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Auto-load server public key from control plane
  useEffect(() => {
    apiClient.getServerPublicKey().then((res) => {
      if (res && res.public_key) {
        setProfile((prev: CustomClientProfile) => ({
          ...prev,
          public_key: res.public_key,
        }));
      }
    });
  }, []);

  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setProfile((prev: CustomClientProfile) => ({
          ...prev,
          logo_data: reader.result as string,
        }));
      };
      reader.readAsDataURL(file);
    }
  };

  const removeLogo = () => {
    setProfile((prev: CustomClientProfile) => ({ ...prev, logo_data: '' }));
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleDownloadProfile = () => {
    const profileJson = JSON.stringify(
      {
        version: '1.0.0',
        metadata: {
          client_name: profile.name,
          organization: profile.company_name,
          generated_at: new Date().toISOString(),
          format: 'cercano-profile-v1',
        },
        branding: {
          display_name: profile.name,
          company: profile.company_name,
          accent_color: profile.accent_color,
          support_note: profile.support_info,
          has_custom_logo: !!profile.logo_data,
        },
        connection: {
          rendezvous_server: profile.rendezvous_server,
          relay_server: profile.relay_server,
          api_server: profile.api_server,
          server_public_key: profile.public_key,
        },
        policy: {
          lock_network_settings: profile.lock_settings,
          portable_quick_support: profile.portable_mode,
          unattended_access: profile.unattended_access,
          lan_only_restriction: profile.lan_only,
          file_transfer_enabled: profile.allow_file_transfer,
          remote_terminal_enabled: profile.allow_terminal,
        },
      },
      null,
      2
    );

    const blob = new Blob([profileJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cercano-${profile.company_name.toLowerCase().replace(/[^a-z0-9]/g, '-')}-profile.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleGenerateScript = () => {
    const script = `@echo off
:: Script de despliegue silencioso para ${profile.name} (${profile.company_name})
:: Generado por Consola Cercano Web
echo Desplegando ${profile.name}...
mkdir "%ProgramFiles%\\Cercano" 2>nul

:: Generar perfil preconfigurado embebido
(
echo {
echo   "rendezvous_server": "${profile.rendezvous_server}",
echo   "relay_server": "${profile.relay_server}",
echo   "api_server": "${profile.api_server}",
echo   "key": "${profile.public_key}",
echo   "app_name": "${profile.name}",
echo   "lock_settings": ${profile.lock_settings}
echo }
) > "%ProgramFiles%\\Cercano\\cercano.json"

echo Perfil corporativo configurado exitosamente.
`;

    navigator.clipboard.writeText(script);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2500);
  };

  const triggerBuildSimulation = () => {
    setIsGenerating(true);
    setGenerationDone(false);
    setTimeout(() => {
      setIsGenerating(false);
      setGenerationDone(true);
      handleDownloadProfile();
      setTimeout(() => setGenerationDone(false), 4000);
    }, 1500);
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header View */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-cercano-blue/15 text-cercano-blue dark:bg-cercano-blue/25 dark:text-blue-400">
              Generador de Clientes
            </span>
            <span className="text-xs text-cercano-slate dark:text-gray-400">
              Paridad con Server Pro
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Personalización de Instalador
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1 max-w-2xl">
            Crea instaladores personalizados (.exe / .msi) con la marca de tu institución, servidores embebidos y políticas de seguridad bloqueadas.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <AppleButton
            variant="secondary"
            onClick={handleDownloadProfile}
            icon={<FileCode size={16} />}
          >
            Descargar Perfil JSON
          </AppleButton>
          <AppleButton
            variant="primary"
            onClick={triggerBuildSimulation}
            isLoading={isGenerating}
            icon={generationDone ? <CheckCircle2 size={16} /> : <Sparkles size={16} />}
          >
            {generationDone ? '¡Instalador Generado!' : 'Generar Instalador (.exe)'}
          </AppleButton>
        </div>
      </div>

      {/* Main Grid: Settings & Live Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column: Form Settings (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* Section 1: Identidad Corporativa */}
          <AppleCard>
            <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/10">
              <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                <Palette size={18} />
              </div>
              <div>
                <h3 className="text-sm font-bold text-cercano-night dark:text-white">
                  Identidad Corporativa y Marca
                </h3>
                <p className="text-xs text-cercano-slate dark:text-gray-400">
                  Configura el nombre visible, logotipo institucional y colores de acento
                </p>
              </div>
            </div>

            <div className="space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                    Nombre de la Aplicación / Cliente
                  </label>
                  <input
                    type="text"
                    value={profile.name}
                    onChange={(e) => setProfile({ ...profile, name: e.target.value })}
                    placeholder="Ej. Cercano Asistencia"
                    className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-medium"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                    Nombre de la Organización
                  </label>
                  <input
                    type="text"
                    value={profile.company_name}
                    onChange={(e) => setProfile({ ...profile, company_name: e.target.value })}
                    placeholder="Ej. Mi Organización TI"
                    className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-medium"
                  />
                </div>
              </div>

              {/* Logo Upload Box */}
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                  Logo / Isotipo Corporativo (PNG, SVG, JPG)
                </label>
                <div className="flex items-center gap-4">
                  <div
                    onClick={() => fileInputRef.current?.click()}
                    className="w-20 h-20 rounded-2xl border-2 border-dashed border-black/15 dark:border-white/15 hover:border-cercano-blue flex flex-col items-center justify-center p-2 cursor-pointer transition-all bg-black/2 dark:bg-white/2 overflow-hidden shrink-0"
                  >
                    {profile.logo_data ? (
                      <img
                        src={profile.logo_data}
                        alt="Logo Preview"
                        className="w-full h-full object-contain"
                      />
                    ) : (
                      <div className="text-center">
                        <Upload size={18} className="mx-auto text-gray-400 mb-1" />
                        <span className="text-[10px] text-gray-400 font-medium">Subir</span>
                      </div>
                    )}
                  </div>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleLogoUpload}
                    accept="image/png, image/jpeg, image/svg+xml"
                    className="hidden"
                  />
                  <div className="flex-1 space-y-1.5">
                    <p className="text-xs text-cercano-slate dark:text-gray-400">
                      Recomendado: imagen transparente de al menos 256×256 px.
                    </p>
                    {profile.logo_data && (
                      <button
                        type="button"
                        onClick={removeLogo}
                        className="text-xs text-red-500 hover:underline font-semibold cursor-pointer"
                      >
                        Eliminar logo personalizado
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Color Presets */}
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-2 ml-1">
                  Color Primario de la Marca
                </label>
                <div className="flex flex-wrap items-center gap-2.5">
                  {COLOR_PRESETS.map((preset) => (
                    <button
                      key={preset.hex}
                      type="button"
                      onClick={() => setProfile({ ...profile, accent_color: preset.hex })}
                      className={`btn-apple flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-semibold transition-all cursor-pointer ${
                        profile.accent_color === preset.hex
                          ? 'border-black/30 dark:border-white/40 shadow-sm ring-2 ring-cercano-blue/20'
                          : 'border-black/10 dark:border-white/10 opacity-75 hover:opacity-100'
                      }`}
                    >
                      <span
                        className="w-3.5 h-3.5 rounded-full shadow-inner"
                        style={{ backgroundColor: preset.hex }}
                      />
                      <span>{preset.name}</span>
                    </button>
                  ))}
                  <div className="flex items-center gap-2 ml-1">
                    <input
                      type="color"
                      value={profile.accent_color}
                      onChange={(e) => setProfile({ ...profile, accent_color: e.target.value })}
                      className="w-7 h-7 rounded-lg border-0 cursor-pointer p-0 bg-transparent"
                      title="Elegir color personalizado"
                    />
                    <span className="font-mono text-xs text-gray-400">{profile.accent_color}</span>
                  </div>
                </div>
              </div>

              {/* Support Info Note */}
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                  Mensaje de Ayuda / Pie de Interfaz
                </label>
                <input
                  type="text"
                  value={profile.support_info}
                  onChange={(e) => setProfile({ ...profile, support_info: e.target.value })}
                  placeholder="Ej. Contactar al Helpdesk extensión 4000"
                  className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-medium"
                />
              </div>
            </div>
          </AppleCard>

          {/* Section 2: Servidores y Red Embebida */}
          <AppleCard>
            <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/10">
              <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                <Server size={18} />
              </div>
              <div>
                <h3 className="text-sm font-bold text-cercano-night dark:text-white">
                  Conexión Embebida y Seguridad
                </h3>
                <p className="text-xs text-cercano-slate dark:text-gray-400">
                  Direcciones fijas del servidor y clave pública Ed25519
                </p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">
                    Servidor Rendezvous (ID Server)
                  </label>
                  <input
                    type="text"
                    value={profile.rendezvous_server}
                    onChange={(e) => setProfile({ ...profile, rendezvous_server: e.target.value })}
                    className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">
                    Servidor Relay
                  </label>
                  <input
                    type="text"
                    value={profile.relay_server}
                    onChange={(e) => setProfile({ ...profile, relay_server: e.target.value })}
                    className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-xs"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">
                  Clave Pública Ed25519 del Servidor (Embebida)
                </label>
                <input
                  type="text"
                  value={profile.public_key}
                  onChange={(e) => setProfile({ ...profile, public_key: e.target.value })}
                  placeholder="Clave pública del servidor (Base64)"
                  className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-xs"
                />
              </div>
            </div>
          </AppleCard>

          {/* Section 3: Políticas de Control */}
          <AppleCard>
            <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/10">
              <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                <ShieldCheck size={18} />
              </div>
              <div>
                <h3 className="text-sm font-bold text-cercano-night dark:text-white">
                  Políticas del Instalador
                </h3>
                <p className="text-xs text-cercano-slate dark:text-gray-400">
                  Reglas operativas y restricciones para el usuario final
                </p>
              </div>
            </div>

            <div className="space-y-3.5">
              <label className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/3 hover:bg-black/5 dark:hover:bg-white/5 cursor-pointer transition-all">
                <div className="pr-4">
                  <span className="text-sm font-semibold block text-cercano-night dark:text-white">
                    Bloquear ajustes de red en el cliente
                  </span>
                  <span className="text-xs text-cercano-slate dark:text-gray-400">
                    Impide que el usuario modifique la IP del servidor o la clave pública.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={profile.lock_settings}
                  onChange={(e) => setProfile({ ...profile, lock_settings: e.target.checked })}
                  className="w-5 h-5 rounded-md accent-cercano-blue cursor-pointer"
                />
              </label>

              <label className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/3 hover:bg-black/5 dark:hover:bg-white/5 cursor-pointer transition-all">
                <div className="pr-4">
                  <span className="text-sm font-semibold block text-cercano-night dark:text-white">
                    Modo Portable / Asistencia Rápida (SOS)
                  </span>
                  <span className="text-xs text-cercano-slate dark:text-gray-400">
                    Se ejecuta directamente sin solicitar permisos de administrador ni instalar servicios de sistema.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={profile.portable_mode}
                  onChange={(e) => setProfile({ ...profile, portable_mode: e.target.checked })}
                  className="w-5 h-5 rounded-md accent-cercano-blue cursor-pointer"
                />
              </label>

              <label className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/3 hover:bg-black/5 dark:hover:bg-white/5 cursor-pointer transition-all">
                <div className="pr-4">
                  <span className="text-sm font-semibold block text-cercano-night dark:text-white">
                    Acceso Desatendido Permitido
                  </span>
                  <span className="text-xs text-cercano-slate dark:text-gray-400">
                    Permite acceso con contraseña configurada sin requerir aceptación manual frente a la pantalla.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={profile.unattended_access}
                  onChange={(e) => setProfile({ ...profile, unattended_access: e.target.checked })}
                  className="w-5 h-5 rounded-md accent-cercano-blue cursor-pointer"
                />
              </label>

              <label className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/3 hover:bg-black/5 dark:hover:bg-white/5 cursor-pointer transition-all">
                <div className="pr-4">
                  <span className="text-sm font-semibold block text-cercano-night dark:text-white">
                    Restringir solo a conexiones LAN
                  </span>
                  <span className="text-xs text-cercano-slate dark:text-gray-400">
                    Rechaza conexiones entrantes de IPs públicas o externas fuera de la subred local.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={profile.lan_only}
                  onChange={(e) => setProfile({ ...profile, lan_only: e.target.checked })}
                  className="w-5 h-5 rounded-md accent-cercano-blue cursor-pointer"
                />
              </label>
            </div>
          </AppleCard>
        </div>

        {/* Right Column: Live Apple Mockup & Actions (5 cols) */}
        <div className="lg:col-span-5 space-y-6 sticky top-28">
          {/* Live Preview Card */}
          <div className="rounded-3xl p-6 bg-white/75 dark:bg-zinc-900/75 backdrop-blur-3xl border border-white/60 dark:border-white/10 shadow-apple-card">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-bold uppercase tracking-wider text-cercano-slate dark:text-gray-400">
                Vista Previa en Vivo del Cliente
              </span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cercano-green/20 text-cercano-green-dark dark:text-cercano-green">
                Modo Interactivo
              </span>
            </div>

            {/* Simulated Desktop Window */}
            <div className="rounded-2xl border border-black/10 dark:border-white/15 overflow-hidden shadow-2xl bg-white dark:bg-zinc-950">
              {/* Window Title Bar */}
              <div className="px-3 py-2 bg-gray-100 dark:bg-zinc-900 border-b border-black/5 dark:border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                  <div className="w-2.5 h-2.5 rounded-full bg-green-400" />
                </div>
                <span className="text-[11px] font-bold text-gray-600 dark:text-gray-300 truncate max-w-[180px]">
                  {profile.name}
                </span>
                <div className="w-8" />
              </div>

              {/* Window Body */}
              <div className="p-5 space-y-4">
                {/* Branding Lockup */}
                <div className="flex items-center gap-3 pb-3 border-b border-black/5 dark:border-white/10">
                  <div
                    className="w-12 h-12 rounded-2xl flex items-center justify-center p-2 shadow-sm text-white shrink-0 overflow-hidden"
                    style={{ backgroundColor: profile.accent_color }}
                  >
                    {profile.logo_data ? (
                      <img src={profile.logo_data} alt="Logo" className="w-full h-full object-contain" />
                    ) : (
                      <Laptop size={24} className="text-white" />
                    )}
                  </div>
                  <div>
                    <h3 className="text-sm font-extrabold text-cercano-night dark:text-white leading-tight">
                      {profile.name}
                    </h3>
                    <p className="text-[11px] text-gray-500 dark:text-gray-400">
                      {profile.company_name}
                    </p>
                  </div>
                </div>

                {/* Simulated Device ID Card */}
                <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-zinc-900/80 border border-black/5 dark:border-white/5 space-y-1">
                  <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider block">
                    Tu ID de Conexión
                  </span>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-base font-extrabold tracking-wide text-cercano-night dark:text-white">
                      894 120 455
                    </span>
                    <span className="w-2.5 h-2.5 rounded-full bg-cercano-green pulse-emerald" />
                  </div>
                  <span className="text-[10px] text-gray-400 block pt-1">
                    Listo para conectar vía {profile.rendezvous_server}
                  </span>
                </div>

                {/* Simulated Remote Connect Input */}
                <div className="space-y-1.5">
                  <label className="text-[11px] font-semibold text-gray-600 dark:text-gray-300 block">
                    Conectar a dispositivo remoto
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      readOnly
                      placeholder="Ingresar ID del colega..."
                      className="w-full px-3 py-1.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-xs font-mono"
                    />
                    <button
                      type="button"
                      className="px-3 py-1.5 rounded-xl text-xs font-bold text-white shadow-sm shrink-0"
                      style={{ backgroundColor: profile.accent_color }}
                    >
                      Conectar
                    </button>
                  </div>
                </div>

                {/* Support Footer in Mockup */}
                <div className="pt-2 text-center text-[10px] text-gray-400 border-t border-black/5 dark:border-white/10">
                  {profile.support_info}
                </div>
              </div>
            </div>
          </div>

          {/* Quick Actions & Deployment Scripts */}
          <AppleCard>
            <div className="flex items-center gap-2.5 mb-3 pb-2 border-b border-black/5 dark:border-white/10">
              <div className="w-7 h-7 rounded-lg bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                <FileCode size={16} />
              </div>
              <div>
                <h3 className="text-xs font-bold text-cercano-night dark:text-white">
                  Despliegue Rápido y GPO
                </h3>
                <p className="text-[11px] text-cercano-slate dark:text-gray-400">
                  Comandos para distribución masiva en Active Directory / Intune
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <p className="text-xs text-cercano-slate dark:text-gray-400">
                Copia el comando de aprovisionamiento silencioso para terminales Windows:
              </p>

              <div className="p-3 rounded-xl bg-zinc-900 text-zinc-200 font-mono text-[11px] overflow-x-auto border border-zinc-800 relative">
                <code>
                  cercano.exe --install --silent --server={profile.rendezvous_server} --key={profile.public_key || 'CLAVE_SERVIDOR'}
                </code>
              </div>

              <div className="flex gap-2 pt-1">
                <AppleButton
                  variant="secondary"
                  size="sm"
                  className="w-full justify-center text-xs"
                  onClick={handleGenerateScript}
                  icon={copiedScript ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
                >
                  {copiedScript ? '¡Script Copiado!' : 'Copiar Script (.bat / GPO)'}
                </AppleButton>
              </div>
            </div>
          </AppleCard>
        </div>
      </div>
    </div>
  );
};
