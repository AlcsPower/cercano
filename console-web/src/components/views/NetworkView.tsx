// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import {
  Copy,
  Check,
  Server,
  ArrowDownToLine,
  ShieldAlert,
  Monitor,
  Smartphone,
  Laptop,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { ServerPortService, ServerPublicKeyResponse } from '../../types';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { StatusPill } from '../common/StatusPill';

export const NetworkView: React.FC = () => {
  const [services, setServices] = useState<ServerPortService[]>([]);
  const [keyInfo, setKeyInfo] = useState<ServerPublicKeyResponse | null>(null);
  const [serverHost, setServerHost] = useState('192.168.10.10');
  const [copiedString, setCopiedString] = useState(false);
  const [copiedPortSummary, setCopiedPortSummary] = useState(false);

  useEffect(() => {
    const load = async () => {
      const metrics = await apiClient.getSystemMetrics();
      setServices(metrics.services);
      const key = await apiClient.getServerPublicKey();
      setKeyInfo(key);
    };
    load();
  }, []);

  const connectionString = `host=${serverHost}:21116,key=${keyInfo?.public_key || ''}`;

  const copyConnectionString = () => {
    navigator.clipboard.writeText(connectionString);
    setCopiedString(true);
    setTimeout(() => setCopiedString(false), 2000);
  };

  const copyPortsSummary = () => {
    const text = services.map((s) => `${s.name}: ${s.port}/${s.protocol} (${s.role})`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedPortSummary(true);
    setTimeout(() => setCopiedPortSummary(false), 2000);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Servidor y Configuración de Red
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
            Topología de puertos, directivas de enlace LAN y distribución de instaladores preconfigurados
          </p>
        </div>
      </div>

      {/* Ports Matrix Table / Cards */}
      <AppleCard>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 mb-4 border-b border-black/5 dark:border-white/10">
          <div>
            <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white">
              Matriz de Puertos y Servicios
            </h2>
            <p className="text-xs text-cercano-slate dark:text-gray-400">
              Todos los puertos deben estar permitidos en el firewall interno de la organización
            </p>
          </div>

          <AppleButton
            variant="secondary"
            size="sm"
            onClick={copyPortsSummary}
            icon={copiedPortSummary ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
          >
            {copiedPortSummary ? 'Puertos Copiados' : 'Copiar Lista de Puertos'}
          </AppleButton>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-black/5 dark:border-white/10 text-[11px] font-semibold text-cercano-slate dark:text-gray-400 uppercase tracking-wider">
                <th className="py-3 px-3">Servicio</th>
                <th className="py-3 px-3">Puerto</th>
                <th className="py-3 px-3">Protocolo</th>
                <th className="py-3 px-3">Función Técnica</th>
                <th className="py-3 px-3 text-right">Estado</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-black/[0.04] dark:divide-white/[0.04] text-xs">
              {services.map((svc) => (
                <tr key={svc.name} className="hover:bg-black/[0.02] dark:hover:bg-white/[0.02] transition-colors">
                  <td className="py-3.5 px-3 font-bold text-cercano-night dark:text-white">
                    {svc.name}
                  </td>
                  <td className="py-3.5 px-3 font-mono font-semibold text-cercano-blue dark:text-blue-300">
                    {svc.port}
                  </td>
                  <td className="py-3.5 px-3 font-mono text-gray-500 dark:text-gray-400">
                    {svc.protocol}
                  </td>
                  <td className="py-3.5 px-3 text-cercano-slate dark:text-gray-300">
                    <span className="font-semibold">{svc.role}</span> — {svc.description}
                  </td>
                  <td className="py-3.5 px-3 text-right">
                    <StatusPill status={svc.status} size="sm" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AppleCard>

      {/* LAN Configuration String Generator */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AppleCard className="h-full">
            <div className="pb-4 mb-4 border-b border-black/5 dark:border-white/10">
              <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white">
                Cadena de Conexión LAN para Clientes
              </h2>
              <p className="text-xs text-cercano-slate dark:text-gray-400">
                Pega esta cadena en la ventana de configuración del cliente Cercano o en el archivo de despliegue silencioso
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-400 mb-1.5 ml-1">
                  Host o IP del Servidor en LAN
                </label>
                <input
                  type="text"
                  value={serverHost}
                  onChange={(e) => setServerHost(e.target.value)}
                  placeholder="192.168.10.10"
                  className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-cercano-night dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-400 mb-1.5 ml-1">
                  Cadena de Parámetros Embebida
                </label>
                <div className="p-3.5 rounded-xl bg-black/[0.03] dark:bg-black/30 border border-black/8 dark:border-white/10 font-mono text-xs text-cercano-night dark:text-blue-200 break-all select-all flex items-center justify-between">
                  <span>{connectionString}</span>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end">
                <AppleButton
                  variant="primary"
                  size="md"
                  onClick={copyConnectionString}
                  icon={copiedString ? <Check size={16} className="text-emerald-300" /> : <Copy size={16} />}
                >
                  {copiedString ? 'Cadena Copiada al Portapapeles' : 'Copiar Cadena de Conexión'}
                </AppleButton>
              </div>
            </div>
          </AppleCard>
        </div>

        {/* Firewall Guidelines */}
        <div>
          <AppleCard className="h-full flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-2 pb-4 mb-4 border-b border-black/5 dark:border-white/10 text-amber-600 dark:text-amber-400">
                <ShieldAlert size={20} />
                <h2 className="text-base font-bold tracking-apple-title text-cercano-night dark:text-white">
                  Reglas de Firewall LAN
                </h2>
              </div>

              <ul className="space-y-3 text-xs text-cercano-slate dark:text-gray-300">
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cercano-blue mt-1.5 shrink-0" />
                  <span><strong>TCP 21114-21117</strong>: tráfico entrante obligatorio al host del servidor.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cercano-blue mt-1.5 shrink-0" />
                  <span><strong>UDP 21116</strong>: señalización de baja latencia entre clientes.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cercano-blue mt-1.5 shrink-0" />
                  <span><strong>UDP 21115</strong>: requerido para determinar el tipo de NAT de la subred.</span>
                </li>
              </ul>
            </div>

            <div className="mt-6 p-3 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 text-[11px] text-gray-400">
              Operación 100% aislada: no se requiere conectividad a internet ni dependencias externas.
            </div>
          </AppleCard>
        </div>
      </div>

      {/* Client Downloads Grid */}
      <div>
        <h2 className="text-xl font-bold tracking-apple-title text-cercano-night dark:text-white mb-4">
          Descargas de Clientes Preconfigurados
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Windows */}
          <AppleCard className="flex flex-col justify-between p-5">
            <div>
              <div className="p-3 rounded-2xl bg-blue-500/10 text-blue-600 dark:text-blue-400 w-fit mb-3">
                <Monitor size={24} />
              </div>
              <h3 className="font-bold text-sm text-cercano-night dark:text-white">
                Cercano para Windows
              </h3>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
                Windows 10, 11 y Server (x64)
              </p>
            </div>
            <div className="mt-5 pt-3 border-t border-black/5 dark:border-white/10">
              <AppleButton
                variant="secondary"
                size="sm"
                className="w-full justify-center"
                icon={<ArrowDownToLine size={14} />}
                onClick={() => alert('Descarga iniciada para el instalador Cercano-Setup.exe con configuración LAN.')}
              >
                Descargar .exe
              </AppleButton>
            </div>
          </AppleCard>

          {/* Linux */}
          <AppleCard className="flex flex-col justify-between p-5">
            <div>
              <div className="p-3 rounded-2xl bg-amber-500/10 text-amber-600 dark:text-amber-400 w-fit mb-3">
                <Server size={24} />
              </div>
              <h3 className="font-bold text-sm text-cercano-night dark:text-white">
                Cercano para Linux
              </h3>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
                Ubuntu, Debian, RHEL (amd64 / arm64)
              </p>
            </div>
            <div className="mt-5 pt-3 border-t border-black/5 dark:border-white/10">
              <AppleButton
                variant="secondary"
                size="sm"
                className="w-full justify-center"
                icon={<ArrowDownToLine size={14} />}
                onClick={() => alert('Descarga iniciada para el paquete cercano-client.deb.')}
              >
                Descargar .deb
              </AppleButton>
            </div>
          </AppleCard>

          {/* macOS */}
          <AppleCard className="flex flex-col justify-between p-5">
            <div>
              <div className="p-3 rounded-2xl bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 w-fit mb-3">
                <Laptop size={24} />
              </div>
              <h3 className="font-bold text-sm text-cercano-night dark:text-white">
                Cercano para macOS
              </h3>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
                Apple Silicon (M1/M2/M3/M4) e Intel
              </p>
            </div>
            <div className="mt-5 pt-3 border-t border-black/5 dark:border-white/10">
              <AppleButton
                variant="secondary"
                size="sm"
                className="w-full justify-center"
                icon={<ArrowDownToLine size={14} />}
                onClick={() => alert('Descarga iniciada para Cercano.dmg.')}
              >
                Descargar .dmg
              </AppleButton>
            </div>
          </AppleCard>

          {/* Android */}
          <AppleCard className="flex flex-col justify-between p-5">
            <div>
              <div className="p-3 rounded-2xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 w-fit mb-3">
                <Smartphone size={24} />
              </div>
              <h3 className="font-bold text-sm text-cercano-night dark:text-white">
                Cercano para Android
              </h3>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
                Android 9.0 o superior (APK universal)
              </p>
            </div>
            <div className="mt-5 pt-3 border-t border-black/5 dark:border-white/10">
              <AppleButton
                variant="secondary"
                size="sm"
                className="w-full justify-center"
                icon={<ArrowDownToLine size={14} />}
                onClick={() => alert('Descarga iniciada para cercano-client.apk.')}
              >
                Descargar .apk
              </AppleButton>
            </div>
          </AppleCard>
        </div>
      </div>
    </div>
  );
};
