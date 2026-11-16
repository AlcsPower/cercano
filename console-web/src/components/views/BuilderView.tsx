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
  Clock,
  Download,
  AlertTriangle,
  Lock,
  RefreshCw,
  X,
} from 'lucide-react';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { apiClient } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import {
  BuildRole,
  BuildJobRecord,
  BuildJobStatus,
  CercanoProfilePayload,
} from '../../types';

const COLOR_PRESETS = [
  { name: 'Azul Cercano', hex: '#007AFF' },
  { name: 'Verde Esmeralda', hex: '#10B981' },
  { name: 'Índigo Corporativo', hex: '#6366F1' },
  { name: 'Púrpura Dinámico', hex: '#8B5CF6' },
  { name: 'Grafito Neutro', hex: '#1F2937' },
  { name: 'Naranja Alerta', hex: '#F97316' },
];

export const BuilderView: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [activeTab, setActiveTab] = useState<'configure' | 'history'>('configure');
  const [activeRole, setActiveRole] = useState<BuildRole>('soporte');

  const [identity, setIdentity] = useState({
    app_name: 'Cercano Asistencia',
    company_name: 'Mi Organización TI',
    accent_color: '#007AFF',
    support_info: 'Para asistencia técnica comuníquese con Helpdesk TI.',
    logo_data: '',
    about_text: 'Cercano Asistencia - Asistencia remota bajo licencia AGPL-3.0.',
  });

  const [serverConfig, setServerConfig] = useState({
    rendezvous_server: '172.16.8.163:21116',
    relay_server: '172.16.8.163:21117',
    api_server: 'http://172.16.8.163:21114',
    server_public_key: '',
  });

  const [policy, setPolicy] = useState({
    allow_incoming: true,
    allow_outgoing: false,
    unattended_access: false,
    require_approval: true,
    hide_network_settings: true,
    allow_file_transfer: true,
    allow_clipboard: true,
    allow_audio: true,
    allow_terminal: false,
    allow_port_forward: false,
    enable_elevation: false,
    unattended_elevation: false,
  });

  const [installation, setInstallation] = useState({
    mode: 'portable' as 'installed' | 'portable',
    auto_start: false,
    create_desktop_shortcut: true,
    silent: false,
  });

  const [identification, setIdentification] = useState({
    device_group: 'Soporte TI',
    default_owner: '',
  });

  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<BuildJobRecord | null>(null);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);

  const [recentBuilds, setRecentBuilds] = useState<BuildJobRecord[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false);
  const [downloadingJobId, setDownloadingJobId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const [inspectedJob, setInspectedJob] = useState<BuildJobRecord | null>(null);
  const [copiedLogs, setCopiedLogs] = useState<boolean>(false);
  const [copiedScript, setCopiedScript] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    apiClient.getServerPublicKey().then((res) => {
      if (res && res.public_key) {
        setServerConfig((prev) => ({ ...prev, server_public_key: res.public_key }));
      }
    });
  }, []);

  const loadRecentBuilds = async () => {
    setIsLoadingHistory(true);
    try {
      const builds = await apiClient.listBuildJobs({ limit: 20 });
      setRecentBuilds(builds);
    } catch {
      // Offline fallback
    } finally {
      setIsLoadingHistory(false);
    }
  };

  useEffect(() => {
    loadRecentBuilds();
  }, []);

  const handleRoleChange = (newRole: BuildRole) => {
    setActiveRole(newRole);
    setSubmitError(null);

    if (newRole === 'soporte') {
      setIdentity((prev) => ({
        ...prev,
        app_name: 'Cercano Asistencia',
        about_text: 'Cercano Asistencia - Asistencia remota rápida para usuarios finales.',
      }));
      setPolicy((prev) => ({
        ...prev,
        allow_incoming: true,
        allow_outgoing: false,
        unattended_access: false,
        require_approval: true,
        allow_terminal: false,
      }));
      setInstallation((prev) => ({ ...prev, mode: 'portable' }));
    } else {
      setIdentity((prev) => ({
        ...prev,
        app_name: 'Cercano Técnico',
        about_text: 'Cercano Técnico - Cliente para especialistas de soporte TI.',
      }));
      setPolicy((prev) => ({
        ...prev,
        allow_incoming: false,
        allow_outgoing: true,
        unattended_access: false,
        unattended_elevation: false,
        require_approval: false,
        allow_terminal: true,
      }));
      setInstallation((prev) => ({ ...prev, mode: 'installed', create_desktop_shortcut: true }));
    }
  };

  useEffect(() => {
    if (!activeJobId) return;

    let isMounted = true;
    const pollCurrentJob = async () => {
      try {
        const job = await apiClient.getBuildJob(activeJobId);
        if (!isMounted) return false;

        setActiveJob(job);
        setPollError(null);

        setRecentBuilds((prev) => {
          const idx = prev.findIndex((j) => j.id === job.id);
          if (idx >= 0) {
            const nextList = [...prev];
            nextList[idx] = job;
            return nextList;
          }
          return [job, ...prev];
        });

        if (job.status === 'completed' || job.status === 'failed' || job.status === 'revoked') {
          return true;
        }
        return false;
      } catch (err: unknown) {
        if (!isMounted) return false;
        setPollError(err instanceof Error ? err.message : 'Error en sondeo');
        return false;
      }
    };

    pollCurrentJob();

    const timer = setInterval(async () => {
      const isTerminal = await pollCurrentJob();
      if (isTerminal) {
        clearInterval(timer);
      }
    }, 2500);

    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, [activeJobId]);

  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setIdentity((prev) => ({ ...prev, logo_data: reader.result as string }));
      };
      reader.readAsDataURL(file);
    }
  };

  const handleEnqueueBuild = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError(null);

    if (activeRole === 'tecnico' && !isAdmin) {
      setSubmitError('Acceso denegado: La generación de clientes técnicos requiere rol de Administrador.');
      return;
    }

    if (!serverConfig.rendezvous_server || !serverConfig.relay_server || !serverConfig.api_server) {
      setSubmitError('Por favor complete las direcciones de servidor requeridas.');
      return;
    }

    setIsSubmitting(true);

    try {
      const profilePayload: CercanoProfilePayload = {
        schema_version: '1.0.0',
        profile_id:
          typeof crypto !== 'undefined' && crypto.randomUUID
            ? crypto.randomUUID()
            : '0192e300-1111-7111-8111-' + Math.random().toString(36).substring(2, 14).padEnd(12, '0'),
        created_at: new Date().toISOString(),
        role: activeRole,
        server: {
          rendezvous_server: serverConfig.rendezvous_server.trim(),
          relay_server: serverConfig.relay_server.trim(),
          api_server: serverConfig.api_server.trim(),
          server_public_key: serverConfig.server_public_key.trim(),
        },
        identity: {
          app_name: identity.app_name.trim(),
          about_text: identity.about_text.trim(),
          icon: 'branding/png/cercano-icon.ico',
        },
        policy: {
          allow_incoming: activeRole === 'soporte' ? true : policy.allow_incoming,
          allow_outgoing: activeRole === 'soporte' ? false : true,
          unattended_access: activeRole === 'tecnico' ? false : policy.unattended_access,
          require_approval: policy.require_approval,
          allow_file_transfer: policy.allow_file_transfer,
          allow_clipboard: policy.allow_clipboard,
          allow_audio: policy.allow_audio,
          allow_terminal: policy.allow_terminal,
          allow_port_forward: policy.allow_port_forward,
          hide_network_settings: policy.hide_network_settings,
          enable_elevation: policy.enable_elevation,
          unattended_elevation: activeRole === 'tecnico' ? false : policy.unattended_elevation,
        },
        installation: {
          mode: installation.mode,
          install_path: installation.mode === 'installed' ? 'C:\\Program Files\\Cercano' : null,
          auto_start: installation.auto_start,
          create_desktop_shortcut: installation.create_desktop_shortcut,
          silent: installation.silent,
        },
        identification: {
          device_group: identification.device_group.trim() || undefined,
          default_owner: identification.default_owner.trim() || undefined,
        },
        expiration: {
          expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
          max_uses: 100,
        },
      };

      const response = await apiClient.enqueueBuild(profilePayload);
      setActiveJobId(response.id);

      const initialRecord: BuildJobRecord = {
        id: response.id,
        user_id: response.user_id,
        role: activeRole,
        profile_id: response.profile_id,
        status: (response.status as BuildJobStatus) || 'queued',
        created_at: response.created_at,
        expires_at: response.expires_at,
        logs: `[${response.created_at}] Trabajo encolado con ID ${response.id}`,
      };

      setActiveJob(initialRecord);
      setRecentBuilds((prev) => [initialRecord, ...prev.filter((j) => j.id !== response.id)]);
    } catch (err: unknown) {
      setSubmitError(
        err instanceof Error ? err.message : 'Error inesperado al encolar compilación.'
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDownloadArtifact = async (job: BuildJobRecord) => {
    setDownloadingJobId(job.id);
    setDownloadError(null);

    try {
      const blob = await apiClient.downloadBuildArtifact(job.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cercano-${job.role}-${job.id.substring(0, 8)}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setDownloadError(
        err instanceof Error ? err.message : 'Error al descargar paquete compilado.'
      );
    } finally {
      setDownloadingJobId(null);
    }
  };

  const handleRevokeJob = async (id: string) => {
    if (!window.confirm('¿Confirma la revocación de este instalador en el servidor?')) return;
    try {
      await apiClient.revokeBuildJob(id, 'Revocado por administrador desde consola web');
      const updated = await apiClient.getBuildJob(id);
      setRecentBuilds((prev) => prev.map((j) => (j.id === id ? updated : j)));
      if (activeJobId === id) setActiveJob(updated);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Error al revocar instalador.');
    }
  };

  const handleCopyScript = () => {
    const script = `@echo off\n:: Script silencioso Cercano\ncercano.exe --install --silent --server=${serverConfig.rendezvous_server} --relay=${serverConfig.relay_server} --key=${serverConfig.server_public_key}\n`;
    navigator.clipboard.writeText(script);
    setCopiedScript(true);
    setTimeout(() => setCopiedScript(false), 2500);
  };

  const renderStatusBadge = (status: BuildJobStatus) => {
    const map = {
      queued: { label: 'En Cola', bg: 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20' },
      running: { label: 'Compilando', bg: 'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/20' },
      completed: { label: 'Listo', bg: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20' },
      failed: { label: 'Fallo', bg: 'bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20' },
      revoked: { label: 'Revocado', bg: 'bg-gray-500/10 text-gray-700 dark:text-gray-400 border-gray-500/20' },
    }[status] || { label: status, bg: 'bg-gray-500/10 text-gray-700 border-gray-500/20' };

    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold border ${map.bg}`}>
        {status === 'queued' && <Clock size={12} className="animate-pulse" />}
        {status === 'completed' && <CheckCircle2 size={12} />}
        {status === 'failed' && <AlertTriangle size={12} />}
        {status === 'revoked' && <X size={12} />}
        <span>{map.label}</span>
      </span>
    );
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header and View Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-cercano-blue/15 text-cercano-blue dark:bg-cercano-blue/25 dark:text-blue-400">
              Generador de Clientes
            </span>
            <span className="text-xs text-cercano-slate dark:text-gray-400">
              Fase 4 · Paridad Server Pro (F4-07)
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Personalización de Instaladores
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1 max-w-2xl">
            Genera paquetes preconfigurados (.zip con perfil firmado y binarios) para soporte o técnicos autorizados.
          </p>
        </div>

        <div className="flex items-center gap-2 p-1 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/[0.04]">
          <button
            type="button"
            onClick={() => setActiveTab('configure')}
            className={`btn-apple flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
              activeTab === 'configure'
                ? 'bg-white dark:bg-zinc-800 text-cercano-night dark:text-white shadow-sm'
                : 'text-cercano-slate dark:text-gray-400 hover:text-cercano-night dark:hover:text-white'
            }`}
          >
            <FileCode size={15} />
            <span>Configuración</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('history')}
            className={`btn-apple flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all ${
              activeTab === 'history'
                ? 'bg-white dark:bg-zinc-800 text-cercano-night dark:text-white shadow-sm'
                : 'text-cercano-slate dark:text-gray-400 hover:text-cercano-night dark:hover:text-white'
            }`}
          >
            <Server size={15} />
            <span>Historial</span>
            {recentBuilds.length > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[10px] bg-black/10 dark:bg-white/10 font-bold">
                {recentBuilds.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {downloadError && (
        <div role="alert" className="p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-700 dark:text-red-400 flex items-start gap-3 text-xs font-medium">
          <AlertTriangle size={18} className="shrink-0 mt-0.5" />
          <div className="flex-1">
            <strong className="block">Aviso de Descarga:</strong>
            {downloadError}
          </div>
          <button type="button" onClick={() => setDownloadError(null)} className="text-red-600 hover:opacity-80">
            <X size={16} />
          </button>
        </div>
      )}

      {/* Active Job Status Banner */}
      {activeJob && (
        <section
          role="status"
          aria-live="polite"
          className="p-6 rounded-3xl bg-cercano-blue/5 dark:bg-cercano-blue/10 border border-cercano-blue/20 shadow-lg shadow-cercano-blue/5 animate-fade-in"
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2.5">
                <span className="text-xs font-bold uppercase tracking-wider text-cercano-blue">
                  Trabajo en Progreso
                </span>
                {renderStatusBadge(activeJob.status)}
                <span className="font-mono text-xs text-cercano-slate dark:text-gray-400">
                  ID: {activeJob.id}
                </span>
              </div>
              <h2 className="text-lg font-extrabold text-cercano-night dark:text-white">
                Compilando Cliente {activeJob.role === 'soporte' ? 'Soporte' : 'Técnico'}
              </h2>
              <p className="text-xs text-cercano-slate dark:text-gray-400">
                {activeJob.status === 'queued' && 'Encolado en el servidor cercano-api...'}
                {activeJob.status === 'running' && 'Inyectando perfil firmado y empaquetando ZIP...'}
                {activeJob.status === 'completed' && '¡Instalador compilado exitosamente! Listo para descargar.'}
                {activeJob.status === 'failed' && `Error: ${activeJob.error_message || 'Fallo en compilación.'}`}
              </p>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <AppleButton variant="secondary" size="sm" onClick={() => setInspectedJob(activeJob)} icon={<FileCode size={14} />}>
                Ver Logs
              </AppleButton>

              {activeJob.status === 'completed' && (
                <AppleButton
                  variant="primary"
                  size="md"
                  onClick={() => handleDownloadArtifact(activeJob)}
                  isLoading={downloadingJobId === activeJob.id}
                  icon={<Download size={15} />}
                >
                  Descargar Instalador (.zip)
                </AppleButton>
              )}

              {activeJob.status === 'queued' || activeJob.status === 'running' ? (
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-cercano-blue/10 text-cercano-blue text-xs font-semibold">
                  <Clock size={14} className="animate-spin" />
                  <span>Sondeando cada 2.5s</span>
                </div>
              ) : (
                <button type="button" onClick={() => setActiveJobId(null)} className="text-xs text-cercano-slate hover:text-cercano-night px-2 py-1">
                  Cerrar
                </button>
              )}
            </div>
          </div>

          {pollError && (
            <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">
              Nota de sondeo: {pollError}
            </p>
          )}
        </section>
      )}

      {/* Main Configuration Tab */}
      {activeTab === 'configure' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          <div className="lg:col-span-7 space-y-6">
            <form onSubmit={handleEnqueueBuild} className="space-y-6">
              {/* Role Selection Card */}
              <AppleCard>
                <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/[0.04]">
                  <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                    <Laptop size={18} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-cercano-night dark:text-white">
                      Tipo de Cliente y Rol Operativo
                    </h3>
                    <p className="text-xs text-cercano-slate dark:text-gray-400">
                      Invariantes de seguridad aplicadas según la matriz RBAC
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div
                    onClick={() => handleRoleChange('soporte')}
                    className={`p-4 rounded-2xl border transition-all cursor-pointer select-none ${
                      activeRole === 'soporte'
                        ? 'border-cercano-blue bg-cercano-blue/5 dark:bg-cercano-blue/10 ring-2 ring-cercano-blue/30'
                        : 'border-black/10 dark:border-white/[0.06] hover:border-black/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-extrabold text-sm text-cercano-night dark:text-white">Cliente Soporte</span>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-500/10 text-blue-600 dark:text-blue-400">Entrante</span>
                    </div>
                    <p className="text-xs text-cercano-slate dark:text-gray-400 leading-relaxed">
                      Para usuarios finales que reciben asistencia. Conexiones salientes estrictamente bloqueadas.
                    </p>
                    <div className="mt-3 flex items-center gap-1.5 text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 size={13} />
                      <span>Operadores y Administradores</span>
                    </div>
                  </div>

                  <div
                    onClick={() => handleRoleChange('tecnico')}
                    className={`p-4 rounded-2xl border transition-all cursor-pointer select-none ${
                      activeRole === 'tecnico'
                        ? 'border-cercano-blue bg-cercano-blue/5 dark:bg-cercano-blue/10 ring-2 ring-cercano-blue/30'
                        : 'border-black/10 dark:border-white/[0.06] hover:border-black/20'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-extrabold text-sm text-cercano-night dark:text-white">Cliente Técnico</span>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-indigo-500/10 text-indigo-600 dark:text-indigo-400">Saliente</span>
                    </div>
                    <p className="text-xs text-cercano-slate dark:text-gray-400 leading-relaxed">
                      Para personal TI que inicia sesiones salientes. Acceso desatendido prohibido.
                    </p>
                    <div className="mt-3 flex items-center gap-1.5 text-[11px] font-semibold text-cercano-slate dark:text-gray-400">
                      <Lock size={13} className={isAdmin ? 'text-emerald-500' : 'text-amber-500'} />
                      <span>{isAdmin ? 'Autorizado (Admin)' : 'Requiere Administrador'}</span>
                    </div>
                  </div>
                </div>

                {activeRole === 'tecnico' && !isAdmin && (
                  <div role="alert" className="mt-4 p-3.5 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-800 dark:text-amber-300 text-xs flex items-start gap-2.5 font-medium">
                    <AlertTriangle size={16} className="shrink-0 mt-0.5 text-amber-600" />
                    <div>
                      <strong className="block">Generación restringida por RBAC:</strong>
                      Solo administradores pueden generar clientes técnicos (permiso <code className="font-mono text-[10px]">builder:create:tecnico</code>). Rol actual: <span className="capitalize font-bold">{user?.role || 'operador'}</span>.
                    </div>
                  </div>
                )}
              </AppleCard>

              {/* Branding Configuration */}
              <AppleCard>
                <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/[0.04]">
                  <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                    <Palette size={18} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-cercano-night dark:text-white">Identidad Institucional</h3>
                    <p className="text-xs text-cercano-slate dark:text-gray-400">Nombre visible, logotipo y color primario</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Nombre de Aplicación</label>
                      <input
                        type="text"
                        required
                        value={identity.app_name}
                        onChange={(e) => setIdentity({ ...identity, app_name: e.target.value })}
                        className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-sm font-medium"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Nombre Institución</label>
                      <input
                        type="text"
                        required
                        value={identity.company_name}
                        onChange={(e) => setIdentity({ ...identity, company_name: e.target.value })}
                        className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-sm font-medium"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Logotipo Institucional</label>
                    <div className="flex items-center gap-3">
                      <div
                        onClick={() => fileInputRef.current?.click()}
                        className="w-14 h-14 rounded-2xl border-2 border-dashed border-black/15 dark:border-white/[0.08] hover:border-cercano-blue flex items-center justify-center p-2 cursor-pointer bg-black/2 dark:bg-white/2 overflow-hidden shrink-0"
                      >
                        {identity.logo_data ? (
                          <img src={identity.logo_data} alt="Logo" className="w-full h-full object-contain" />
                        ) : (
                          <Upload size={16} className="text-gray-400" />
                        )}
                      </div>
                      <input type="file" ref={fileInputRef} onChange={handleLogoUpload} accept="image/*" className="hidden" />
                      <div className="text-xs text-cercano-slate dark:text-gray-400 space-y-1">
                        <p>PNG/SVG transparente 256×256 px.</p>
                        {identity.logo_data && (
                          <button type="button" onClick={() => setIdentity({ ...identity, logo_data: '' })} className="text-red-500 font-semibold hover:underline">
                            Quitar logotipo
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">Color de Interfaz</label>
                    <div className="flex flex-wrap items-center gap-2">
                      {COLOR_PRESETS.map((p) => (
                        <button
                          key={p.hex}
                          type="button"
                          onClick={() => setIdentity({ ...identity, accent_color: p.hex })}
                          className={`btn-apple flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-semibold ${
                            identity.accent_color === p.hex ? 'border-black/30 dark:border-white/40 ring-2 ring-cercano-blue/20' : 'border-black/10 dark:border-white/[0.06]'
                          }`}
                        >
                          <span className="w-3 h-3 rounded-full" style={{ backgroundColor: p.hex }} />
                          <span>{p.name}</span>
                        </button>
                      ))}
                      <input
                        type="color"
                        value={identity.accent_color}
                        onChange={(e) => setIdentity({ ...identity, accent_color: e.target.value })}
                        className="w-7 h-7 rounded-lg border-0 cursor-pointer p-0 bg-transparent ml-1"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Mensaje de Ayuda</label>
                    <input
                      type="text"
                      value={identity.support_info}
                      onChange={(e) => setIdentity({ ...identity, support_info: e.target.value })}
                      className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-xs font-medium"
                    />
                  </div>
                </div>
              </AppleCard>

              {/* Server Settings */}
              <AppleCard>
                <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/[0.04]">
                  <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                    <Server size={18} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-cercano-night dark:text-white">Conectividad de Servidores</h3>
                    <p className="text-xs text-cercano-slate dark:text-gray-400">Direcciones de red y clave pública Ed25519</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Rendezvous (hbbs)</label>
                      <input
                        type="text"
                        required
                        value={serverConfig.rendezvous_server}
                        onChange={(e) => setServerConfig({ ...serverConfig, rendezvous_server: e.target.value })}
                        className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] font-mono text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Relay (hbbr)</label>
                      <input
                        type="text"
                        required
                        value={serverConfig.relay_server}
                        onChange={(e) => setServerConfig({ ...serverConfig, relay_server: e.target.value })}
                        className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] font-mono text-xs"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Servidor API</label>
                      <input
                        type="text"
                        required
                        value={serverConfig.api_server}
                        onChange={(e) => setServerConfig({ ...serverConfig, api_server: e.target.value })}
                        className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] font-mono text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Grupo / Tag</label>
                      <input
                        type="text"
                        value={identification.device_group}
                        onChange={(e) => setIdentification({ ...identification, device_group: e.target.value })}
                        className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-xs font-medium"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1 ml-1">Clave Pública Ed25519 (Base64)</label>
                    <input
                      type="text"
                      required
                      value={serverConfig.server_public_key}
                      onChange={(e) => setServerConfig({ ...serverConfig, server_public_key: e.target.value })}
                      className="w-full px-4 py-2 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] font-mono text-xs"
                    />
                  </div>
                </div>
              </AppleCard>

              {/* Policies & Mode */}
              <AppleCard>
                <div className="flex items-center gap-2.5 mb-4 pb-3 border-b border-black/5 dark:border-white/[0.04]">
                  <div className="w-8 h-8 rounded-xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-400 flex items-center justify-center">
                    <ShieldCheck size={18} />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-cercano-night dark:text-white">Políticas de Red e Instalación</h3>
                    <p className="text-xs text-cercano-slate dark:text-gray-400">Invariantes validadas por cercano-api</p>
                  </div>
                </div>

                <div className="space-y-3.5">
                  <div className="p-3 rounded-2xl bg-black/2 dark:bg-white/2 border border-black/5 dark:border-white/[0.04]">
                    <span className="text-xs font-bold block text-cercano-night dark:text-white mb-2">Modo de Empaquetado</span>
                    <div className="grid grid-cols-2 gap-3">
                      <button
                        type="button"
                        onClick={() => setInstallation({ ...installation, mode: 'portable' })}
                        className={`btn-apple p-2.5 rounded-xl border text-left transition-all ${
                          installation.mode === 'portable' ? 'border-cercano-blue bg-cercano-blue/5 text-cercano-blue font-bold' : 'border-black/5 text-cercano-slate'
                        }`}
                      >
                        <span className="block text-xs font-extrabold">SOS Portable</span>
                        <span className="block text-[10px] opacity-80">Sin instalación ni servicios</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => setInstallation({ ...installation, mode: 'installed' })}
                        className={`btn-apple p-2.5 rounded-xl border text-left transition-all ${
                          installation.mode === 'installed' ? 'border-cercano-blue bg-cercano-blue/5 text-cercano-blue font-bold' : 'border-black/5 text-cercano-slate'
                        }`}
                      >
                        <span className="block text-xs font-extrabold">Instalado Residente</span>
                        <span className="block text-[10px] opacity-80">Servicio de fondo</span>
                      </button>
                    </div>
                  </div>

                  {/* Policy Invariant Rows */}
                  <div className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/2">
                    <div>
                      <span className="text-xs font-bold text-cercano-night dark:text-white block">Conexiones Entrantes</span>
                      <span className="text-[11px] text-cercano-slate dark:text-gray-400">Permite asistencia remota. {activeRole === 'soporte' && '(Fijo en Soporte)'}</span>
                    </div>
                    {activeRole === 'soporte' ? (
                      <CheckCircle2 size={16} className="text-cercano-blue" />
                    ) : (
                      <input
                        type="checkbox"
                        checked={policy.allow_incoming}
                        onChange={(e) => setPolicy({ ...policy, allow_incoming: e.target.checked })}
                        className="w-4 h-4 rounded accent-cercano-blue cursor-pointer"
                      />
                    )}
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/2">
                    <div>
                      <span className="text-xs font-bold text-cercano-night dark:text-white block">Conexiones Salientes</span>
                      <span className="text-[11px] text-cercano-slate dark:text-gray-400">Inicia sesiones hacia otros terminales. {activeRole === 'soporte' ? '(Prohibido en Soporte)' : '(Fijo en Técnico)'}</span>
                    </div>
                    {activeRole === 'soporte' ? (
                      <X size={16} className="text-gray-400" />
                    ) : (
                      <CheckCircle2 size={16} className="text-cercano-blue" />
                    )}
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-2xl bg-black/2 dark:bg-white/2">
                    <div>
                      <span className="text-xs font-bold text-cercano-night dark:text-white block">Acceso Desatendido</span>
                      <span className="text-[11px] text-cercano-slate dark:text-gray-400">Contraseña fija sin confirmación interactiva. {activeRole === 'tecnico' && '(Prohibido en Técnico)'}</span>
                    </div>
                    {activeRole === 'tecnico' ? (
                      <X size={16} className="text-gray-400" />
                    ) : (
                      <input
                        type="checkbox"
                        checked={policy.unattended_access}
                        onChange={(e) => setPolicy({ ...policy, unattended_access: e.target.checked })}
                        className="w-4 h-4 rounded accent-cercano-blue cursor-pointer"
                      />
                    )}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                    {[
                      { key: 'hide_network_settings' as const, label: 'Bloquear ajustes de red locales' },
                      { key: 'allow_file_transfer' as const, label: 'Transferencia de archivos' },
                      { key: 'allow_terminal' as const, label: 'Terminal remota de comandos' },
                      { key: 'require_approval' as const, label: 'Exigir aprobación manual' },
                    ].map((item) => (
                      <label key={item.key} className="flex items-center gap-2 p-2 rounded-xl bg-black/2 dark:bg-white/2 cursor-pointer text-xs font-medium text-cercano-night dark:text-white">
                        <input
                          type="checkbox"
                          checked={policy[item.key]}
                          onChange={(e) => setPolicy({ ...policy, [item.key]: e.target.checked })}
                          className="w-4 h-4 rounded accent-cercano-blue cursor-pointer"
                        />
                        <span>{item.label}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </AppleCard>

              {submitError && (
                <div role="alert" className="p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-700 dark:text-red-400 text-xs font-medium flex items-start gap-3">
                  <AlertTriangle size={18} className="shrink-0 mt-0.5" />
                  <div>
                    <strong className="block">Error al procesar:</strong>
                    {submitError}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-1">
                <AppleButton
                  type="submit"
                  variant="primary"
                  size="lg"
                  isLoading={isSubmitting}
                  disabled={isSubmitting || (activeRole === 'tecnico' && !isAdmin)}
                  icon={<Sparkles size={18} />}
                >
                  {isSubmitting
                    ? 'Encolando en el servidor...'
                    : activeRole === 'tecnico' && !isAdmin
                    ? 'Requiere Rol Administrador'
                    : `Generar Instalador ${activeRole === 'soporte' ? 'Soporte' : 'Técnico'} (.zip)`}
                </AppleButton>
              </div>
            </form>
          </div>

          {/* Right Column: Live Mockup */}
          <div className="lg:col-span-5 space-y-6 sticky top-28">
            <div className="rounded-3xl p-6 bg-white/75 dark:bg-zinc-900/75 backdrop-blur-3xl border border-black/5 dark:border-white/[0.04] shadow-xl shadow-black/5 dark:shadow-black/40">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-bold uppercase tracking-wider text-cercano-slate dark:text-gray-400">
                  Vista Previa en Vivo
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cercano-green/20 text-cercano-green-dark dark:text-cercano-green">
                  {installation.mode === 'portable' ? 'SOS Portable' : 'Instalado Residente'}
                </span>
              </div>

              <div className="rounded-2xl border border-black/10 dark:border-white/[0.08] overflow-hidden shadow-2xl bg-white dark:bg-zinc-950">
                <div className="px-3 py-2 bg-gray-100 dark:bg-zinc-900 border-b border-black/5 dark:border-white/[0.04] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                    <div className="w-2.5 h-2.5 rounded-full bg-amber-400" />
                    <div className="w-2.5 h-2.5 rounded-full bg-green-400" />
                  </div>
                  <span className="text-[11px] font-bold text-gray-600 dark:text-gray-300 truncate max-w-[180px]">
                    {identity.app_name}
                  </span>
                  <div className="w-8" />
                </div>

                <div className="p-5 space-y-4">
                  <div className="flex items-center gap-3 pb-3 border-b border-black/5 dark:border-white/[0.04]">
                    <div
                      className="w-12 h-12 rounded-2xl flex items-center justify-center p-2 shadow-sm text-white shrink-0 overflow-hidden"
                      style={{ backgroundColor: identity.accent_color }}
                    >
                      {identity.logo_data ? (
                        <img src={identity.logo_data} alt="Logo" className="w-full h-full object-contain" />
                      ) : (
                        <Laptop size={22} className="text-white" />
                      )}
                    </div>
                    <div>
                      <h3 className="text-sm font-extrabold text-cercano-night dark:text-white leading-tight">
                        {identity.app_name}
                      </h3>
                      <p className="text-[11px] text-gray-500 dark:text-gray-400">
                        {identity.company_name}
                      </p>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-zinc-900/80 border border-black/5 dark:border-white/5 space-y-1">
                    <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider block">
                      {activeRole === 'soporte' ? 'Tu ID de Asistencia' : 'ID del Especialista TI'}
                    </span>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-base font-extrabold tracking-wide text-cercano-night dark:text-white">
                        894 120 455
                      </span>
                      <span className="w-2.5 h-2.5 rounded-full bg-cercano-green pulse-emerald" />
                    </div>
                    <span className="text-[10px] text-gray-400 block pt-1">
                      Conectado a {serverConfig.rendezvous_server}
                    </span>
                  </div>

                  <div className="pt-2 text-center text-[10px] text-gray-400 border-t border-black/5 dark:border-white/[0.04]">
                    {identity.support_info}
                  </div>
                </div>
              </div>
            </div>

            <AppleCard>
              <div className="flex items-center gap-2 mb-2 pb-2 border-b border-black/5 dark:border-white/[0.04]">
                <FileCode size={15} className="text-cercano-blue" />
                <h3 className="text-xs font-bold text-cercano-night dark:text-white">
                  Despliegue Silencioso (GPO / Intune)
                </h3>
              </div>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mb-2">
                Comando para aprovisionar clientes en segundo plano:
              </p>
              <div className="p-3 rounded-xl bg-zinc-900 text-zinc-200 font-mono text-[11px] overflow-x-auto border border-zinc-800">
                <code>
                  cercano.exe --install --silent --server={serverConfig.rendezvous_server} --key={serverConfig.server_public_key || 'SERVER_KEY'}
                </code>
              </div>
              <AppleButton
                variant="secondary"
                size="sm"
                className="w-full justify-center text-xs mt-3"
                onClick={handleCopyScript}
                icon={copiedScript ? <Check size={14} className="text-green-500" /> : <Copy size={14} />}
              >
                {copiedScript ? '¡Script Copiado!' : 'Copiar Comando de Despliegue'}
              </AppleButton>
            </AppleCard>
          </div>
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div className="space-y-6 animate-fade-in">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-extrabold text-cercano-night dark:text-white">
                Cola de Compilación e Instaladores Generados
              </h2>
              <p className="text-xs text-cercano-slate dark:text-gray-400">
                Historial de paquetes generados por cercano-api (retención: 7 días)
              </p>
            </div>
            <AppleButton variant="secondary" size="sm" onClick={loadRecentBuilds} isLoading={isLoadingHistory} icon={<RefreshCw size={14} />}>
              Actualizar
            </AppleButton>
          </div>

          <AppleCard className="p-0 overflow-hidden">
            {recentBuilds.length === 0 ? (
              <div className="text-center py-16 px-4">
                <FileCode size={28} className="mx-auto text-gray-400 mb-2" />
                <h3 className="text-sm font-bold text-cercano-night dark:text-white">No hay trabajos de compilación</h3>
                <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1 max-w-sm mx-auto">
                  Configura y solicita un instalador para comenzar.
                </p>
                <AppleButton variant="primary" size="sm" className="mt-4" onClick={() => setActiveTab('configure')}>
                  Configurar Nuevo Instalador
                </AppleButton>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-black/5 dark:border-white/[0.04] bg-black/2 dark:bg-white/2 text-cercano-slate dark:text-gray-400 uppercase tracking-wider text-[10px] font-bold">
                      <th className="py-3 px-4">ID / Rol</th>
                      <th className="py-3 px-4">Fecha</th>
                      <th className="py-3 px-4">Estado</th>
                      <th className="py-3 px-4">Caducidad</th>
                      <th className="py-3 px-4 text-right">Acciones</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-black/5 dark:divide-white/[0.04]">
                    {recentBuilds.map((job) => (
                      <tr key={job.id} className="hover:bg-black/2 dark:hover:bg-white/2 transition-colors font-medium">
                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase ${
                                job.role === 'soporte'
                                  ? 'bg-blue-500/10 text-blue-600 dark:text-blue-400'
                                  : 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400'
                              }`}
                            >
                              {job.role}
                            </span>
                            <span className="font-mono text-xs text-cercano-night dark:text-white">{job.id}</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 text-cercano-slate dark:text-gray-400">
                          {new Date(job.created_at).toLocaleString()}
                        </td>
                        <td className="py-3.5 px-4">{renderStatusBadge(job.status)}</td>
                        <td className="py-3.5 px-4 text-cercano-slate dark:text-gray-400">
                          {job.expires_at ? new Date(job.expires_at).toLocaleDateString() : '7 días'}
                        </td>
                        <td className="py-3.5 px-4 text-right space-x-2">
                          <button
                            type="button"
                            onClick={() => setInspectedJob(job)}
                            className="btn-apple inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-black/5 dark:bg-white/5 hover:bg-black/10 dark:hover:bg-white/10 text-cercano-night dark:text-white"
                          >
                            <FileCode size={13} />
                            <span>Logs</span>
                          </button>

                          {job.status === 'completed' && (
                            <AppleButton
                              variant="primary"
                              size="sm"
                              onClick={() => handleDownloadArtifact(job)}
                              isLoading={downloadingJobId === job.id}
                              icon={<Download size={13} />}
                            >
                              Descargar ZIP
                            </AppleButton>
                          )}

                          {isAdmin && job.status !== 'revoked' && (
                            <button
                              type="button"
                              onClick={() => handleRevokeJob(job.id)}
                              title="Revocar instalador"
                              className="btn-apple p-1.5 rounded-lg text-xs text-red-500 hover:bg-red-500/10 transition-colors"
                            >
                              <X size={14} />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </AppleCard>
        </div>
      )}

      {/* Modal: Inspection & Logs */}
      {inspectedJob && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-logs-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in"
        >
          <div className="w-full max-w-2xl rounded-3xl bg-white dark:bg-zinc-900 border border-black/10 dark:border-white/10 shadow-2xl overflow-hidden p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-black/5 dark:border-white/[0.04]">
              <div>
                <h3 id="modal-logs-title" className="text-base font-extrabold text-cercano-night dark:text-white">
                  Detalles del Trabajo de Compilación
                </h3>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="font-mono text-xs text-cercano-slate dark:text-gray-400">ID: {inspectedJob.id}</span>
                  {renderStatusBadge(inspectedJob.status)}
                </div>
              </div>
              <button type="button" onClick={() => setInspectedJob(null)} className="p-1 rounded-full text-gray-400 hover:text-gray-600 dark:hover:text-white">
                <X size={20} />
              </button>
            </div>

            {inspectedJob.error_message && (
              <div role="alert" className="p-3.5 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-700 dark:text-red-400 text-xs font-semibold">
                Error: {inspectedJob.error_message}
              </div>
            )}

            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-cercano-slate dark:text-gray-400">Traza de Ejecución y Manifiesto:</span>
                {inspectedJob.logs && (
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(inspectedJob.logs || '');
                      setCopiedLogs(true);
                      setTimeout(() => setCopiedLogs(false), 2000);
                    }}
                    className="text-xs text-cercano-blue hover:underline flex items-center gap-1 font-semibold"
                  >
                    {copiedLogs ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                    <span>{copiedLogs ? '¡Copiado!' : 'Copiar Logs'}</span>
                  </button>
                )}
              </div>

              <div className="p-4 rounded-2xl bg-zinc-950 text-zinc-300 font-mono text-xs border border-zinc-800 max-h-64 overflow-y-auto whitespace-pre-wrap select-text">
                {inspectedJob.logs || 'No se han generado logs para este trabajo.'}
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-cercano-slate dark:text-gray-400">
                Creado: {new Date(inspectedJob.created_at).toLocaleString()}
              </span>
              <div className="flex items-center gap-2">
                {inspectedJob.status === 'completed' && (
                  <AppleButton
                    variant="primary"
                    size="sm"
                    onClick={() => {
                      handleDownloadArtifact(inspectedJob);
                      setInspectedJob(null);
                    }}
                    icon={<Download size={14} />}
                  >
                    Descargar Instalador (.zip)
                  </AppleButton>
                )}
                <AppleButton variant="secondary" size="sm" onClick={() => setInspectedJob(null)}>
                  Cerrar
                </AppleButton>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
