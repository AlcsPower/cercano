// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import {
  Server,
  Monitor,
  Activity,
  Cpu,
  ShieldCheck,
  ArrowUpRight,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { ActiveTab, SystemMetrics } from '../../types';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { StatusPill } from '../common/StatusPill';

interface DashboardViewProps {
  setActiveTab: (tab: ActiveTab) => void;
  openRotateKeyModal: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  setActiveTab,
  openRotateKeyModal,
}) => {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = async () => {
    setLoading(true);
    try {
      const data = await apiClient.getSystemMetrics();
      setMetrics(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 15000);
    return () => clearInterval(interval);
  }, []);

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${d}d ${h}h ${m}m`;
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Welcome & Quick Refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-2">
        <div>
          <h1 className="text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Panel de Control
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
            Supervisión en tiempo real de infraestructura, nodos y sesiones
          </p>
        </div>

        <div className="flex items-center gap-2">
          <AppleButton
            variant="secondary"
            size="sm"
            onClick={fetchMetrics}
            icon={<RefreshCw size={14} className={loading ? 'animate-spin' : ''} />}
          >
            Actualizar
          </AppleButton>
          <AppleButton
            variant="primary"
            size="sm"
            onClick={openRotateKeyModal}
            icon={<ShieldCheck size={14} />}
          >
            Rotar Clave Servidor
          </AppleButton>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Total Devices */}
        <AppleCard
          hoverable
          onClick={() => setActiveTab('devices')}
          className="p-4 relative overflow-hidden group"
        >
          <div className="flex items-center justify-between text-cercano-slate dark:text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">
              Dispositivos
            </span>
            <div className="p-2 rounded-xl bg-cercano-blue/10 text-cercano-blue dark:bg-cercano-blue/20 dark:text-blue-300">
              <Monitor size={18} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
              {metrics ? metrics.total_devices : '—'}
            </span>
            <span className="text-xs font-medium text-emerald-700 dark:text-emerald-400 flex items-center">
              <StatusPill status="online" size="sm" pulse={false} label={`${metrics?.online_devices ?? 0} en línea`} />
            </span>
          </div>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-2 flex items-center justify-between">
            <span>Directorio de agentes</span>
            <ArrowUpRight size={14} className="opacity-0 group-hover:opacity-100 transition-opacity" />
          </p>
        </AppleCard>

        {/* Active Remote Sessions */}
        <AppleCard className="p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-cercano-slate dark:text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">
              Sesiones Activas
            </span>
            <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-300">
              <Activity size={18} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-apple-display text-cercano-night dark:text-white">
              {metrics?.active_sessions != null ? metrics.active_sessions : 'Sin telemetría'}
            </span>
          </div>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-2">
            {metrics?.active_sessions != null ? 'Conexiones P2P/Relay' : 'Métricas de sesión en Fase 2'}
          </p>
        </AppleCard>

        {/* Server Load */}
        <AppleCard className="p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-cercano-slate dark:text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">
              Carga del Servidor
            </span>
            <div className="p-2 rounded-xl bg-purple-500/10 text-purple-600 dark:bg-purple-500/20 dark:text-purple-300">
              <Cpu size={18} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-apple-display text-cercano-night dark:text-white">
              {metrics?.cpu_percent != null ? `${metrics.cpu_percent}%` : 'Sin telemetría'}
            </span>
          </div>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-2">
            {metrics?.cpu_percent != null ? 'Uso de CPU' : 'Telemetría de host en Fase 2'}
          </p>
        </AppleCard>

        {/* Uptime / API Connectivity */}
        <AppleCard className="p-4 relative overflow-hidden">
          <div className="flex items-center justify-between text-cercano-slate dark:text-gray-400 mb-3">
            <span className="text-xs font-semibold uppercase tracking-wider">
              Control Plane
            </span>
            <div className="p-2 rounded-xl bg-amber-500/10 text-amber-600 dark:bg-amber-500/20 dark:text-amber-300">
              <Server size={18} />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-apple-display text-cercano-night dark:text-white">
              {typeof metrics?.uptime_seconds === 'number' ? formatUptime(metrics.uptime_seconds) : 'Puerto :21114'}
            </span>
          </div>
          <p className="text-xs text-emerald-700 dark:text-emerald-400 mt-2 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            API Conectada y Operativa
          </p>
        </AppleCard>
      </div>

      {/* Services and Ports Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Core Services Status (hbbs, hbbr, api, nat) */}
        <div className="lg:col-span-2">
          <AppleCard className="h-full">
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-black/5 dark:border-white/[0.04]">
              <div>
                <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white">
                  Servicios y Procesos Nucleares
                </h2>
                <p className="text-xs text-cercano-slate dark:text-gray-400">
                  Estado operacional de los componentes de backend y retransmisión
                </p>
              </div>
              <button
                onClick={() => setActiveTab('network')}
                className="text-xs font-semibold text-cercano-blue hover:text-cercano-blue-dark flex items-center gap-1 cursor-pointer"
              >
                <span>Ver Red</span>
                <ArrowUpRight size={14} />
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {metrics?.services.map((srv) => (
                <div
                  key={srv.name}
                  className="p-4 rounded-2xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-2 hover:border-black/10 dark:hover:border-white/10 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cercano-night dark:text-white">
                      {srv.name}
                    </span>
                    <StatusPill status={srv.status || 'operational'} label={srv.status === 'stopped' ? 'Detenido' : 'Operativo'} size="sm" pulse={false} />
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-cercano-slate dark:text-gray-400">
                    <span className="px-1.5 py-0.5 rounded bg-cercano-blue/10 text-cercano-blue font-mono font-semibold">
                      Port {srv.port} ({srv.protocol})
                    </span>
                    <span>{srv.role}</span>
                  </div>
                  <p className="text-[11px] text-cercano-slate dark:text-gray-400 line-clamp-2">
                    {srv.description}
                  </p>
                </div>
              ))}
            </div>
          </AppleCard>
        </div>

        {/* Quick Actions Panel */}
        <div>
          <AppleCard className="h-full flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 pb-4 mb-4 border-b border-black/5 dark:border-white/[0.04] text-cercano-blue">
                <Sparkles size={18} />
                <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white">
                  Acciones Rápidas
                </h2>
              </div>

              <div className="space-y-3">
                <button
                  onClick={() => setActiveTab('devices')}
                  className="btn-apple w-full p-3 rounded-xl bg-black/5 hover:bg-black/10 dark:bg-white/5 dark:hover:bg-white/10 flex items-center justify-between text-left transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <Monitor size={18} className="text-cercano-blue" />
                    <div>
                      <p className="text-sm font-semibold text-cercano-night dark:text-white">
                        Explorar Dispositivos
                      </p>
                      <p className="text-xs text-cercano-slate dark:text-gray-400">
                        Búsqueda y detalle de terminales
                      </p>
                    </div>
                  </div>
                  <ArrowUpRight size={16} className="text-gray-400" />
                </button>

                <button
                  onClick={() => setActiveTab('security')}
                  className="btn-apple w-full p-3 rounded-xl bg-black/5 hover:bg-black/10 dark:bg-white/5 dark:hover:bg-white/10 flex items-center justify-between text-left transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <ShieldCheck size={18} className="text-cercano-green-dark dark:text-cercano-green" />
                    <div>
                      <p className="text-sm font-semibold text-cercano-night dark:text-white">
                        Firma Ed25519
                      </p>
                      <p className="text-xs text-cercano-slate dark:text-gray-400">
                        Ver huella SHA-256 y rotar
                      </p>
                    </div>
                  </div>
                  <ArrowUpRight size={16} className="text-gray-400" />
                </button>

                <button
                  onClick={() => setActiveTab('builder')}
                  className="btn-apple w-full p-3 rounded-xl bg-black/5 hover:bg-black/10 dark:bg-white/5 dark:hover:bg-white/10 flex items-center justify-between text-left transition-colors cursor-pointer"
                >
                  <div className="flex items-center gap-3">
                    <Sparkles size={18} className="text-purple-500" />
                    <div>
                      <p className="text-sm font-semibold text-cercano-night dark:text-white">
                        Personalizador de Clientes
                      </p>
                      <p className="text-xs text-cercano-slate dark:text-gray-400">
                        Marca propia y perfiles de conexión
                      </p>
                    </div>
                  </div>
                  <ArrowUpRight size={16} className="text-gray-400" />
                </button>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-black/5 dark:border-white/[0.04] text-xs text-cercano-slate dark:text-gray-400">
              <p className="font-semibold text-cercano-night dark:text-white mb-1">
                Servidor Cercano LAN
              </p>
              <p>
                Rendezvous y Relay en escucha local activa. Clientes configurados con la clave pública de este servidor pueden enlazarse sin conexión a internet.
              </p>
            </div>
          </AppleCard>
        </div>
      </div>
    </div>
  );
};
