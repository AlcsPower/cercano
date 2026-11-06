// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import {
  Copy,
  Check,
  Server,
  ShieldAlert,
  Sparkles,
  ArrowRight,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { ActiveTab, ServerPortService, ServerPublicKeyResponse } from '../../types';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { StatusPill } from '../common/StatusPill';

interface NetworkViewProps {
  setActiveTab?: (tab: ActiveTab) => void;
}

export const NetworkView: React.FC<NetworkViewProps> = ({ setActiveTab }) => {
  const [services, setServices] = useState<ServerPortService[]>([]);
  const [keyInfo, setKeyInfo] = useState<ServerPublicKeyResponse | null>(null);
  const [serverHost, setServerHost] = useState('127.0.0.1');
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
              {services.map((srv) => (
                <tr key={srv.name} className="hover:bg-black/[0.01] dark:hover:bg-white/[0.01] transition-colors">
                  <td className="py-3 px-3 font-semibold text-cercano-night dark:text-white flex items-center gap-2">
                    <Server size={14} className="text-cercano-blue" />
                    <span>{srv.name}</span>
                  </td>
                  <td className="py-3 px-3 font-mono font-bold text-cercano-blue dark:text-blue-400">
                    {srv.port}
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded-md bg-black/5 dark:bg-white/10 font-mono text-[10px]">
                      {srv.protocol}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-cercano-slate dark:text-gray-400 max-w-md">
                    {srv.description}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <StatusPill status="online" label="En escucha" size="sm" pulse={false} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AppleCard>

      {/* Manual Connection String & Directives */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AppleCard>
          <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white mb-2">
            Cadena de Conexión Manual para Clientes
          </h2>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mb-4">
            Parámetros necesarios para apuntar manualmente un cliente al servidor local sin configuración automática.
          </p>

          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-cercano-night dark:text-gray-200 mb-1">
                IP o Hostname del Servidor LAN
              </label>
              <input
                type="text"
                value={serverHost}
                onChange={(e) => setServerHost(e.target.value)}
                className="w-full px-3 py-2 rounded-xl text-xs bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono focus:outline-none focus:ring-2 focus:ring-cercano-blue"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-cercano-night dark:text-gray-200 mb-1">
                Cadena de Parámetros de Enlace
              </label>
              <div className="relative">
                <input
                  type="text"
                  readOnly
                  value={connectionString}
                  className="w-full pl-3 pr-20 py-2 rounded-xl text-xs bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 font-mono text-cercano-slate dark:text-gray-400 select-all"
                />
                <button
                  onClick={copyConnectionString}
                  className="absolute right-1 top-1 bottom-1 px-3 rounded-lg bg-cercano-blue text-white text-xs font-medium flex items-center gap-1 hover:bg-cercano-blue-dark transition-colors cursor-pointer"
                >
                  {copiedString ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedString ? 'Listo' : 'Copiar'}</span>
                </button>
              </div>
            </div>
          </div>
        </AppleCard>

        <AppleCard className="flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2 text-amber-600 dark:text-amber-400">
              <ShieldAlert size={20} />
              <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white">
                Requisitos de Firewall Interno
              </h2>
            </div>
            <p className="text-xs text-cercano-slate dark:text-gray-400 mb-4">
              Para garantizar que los clientes de la red corporativa establezcan conexiones directas sin intermediación externa:
            </p>

            <ul className="space-y-2 text-xs text-cercano-slate dark:text-gray-300">
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cercano-blue mt-1.5 shrink-0" />
                <span><strong>21115/UDP</strong> requerido para el descubrimiento de NAT (STUN) inter-cliente.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cercano-blue mt-1.5 shrink-0" />
                <span><strong>21116/TCP y UDP</strong> para la señalización inicial de enlace y estado.</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cercano-blue mt-1.5 shrink-0" />
                <span><strong>21117/TCP</strong> como puente de retransmisión (relay) si los clientes están en subredes aisladas.</span>
              </li>
            </ul>
          </div>

          <div className="mt-4 p-3 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 text-[11px] text-cercano-slate dark:text-gray-400">
            Operación 100% LAN aislada: el sistema opera sin acceso a servidores externos ni telemetría foránea.
          </div>
        </AppleCard>
      </div>

      {/* Client Distribution Card */}
      <AppleCard className="p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-xl font-bold tracking-apple-title text-cercano-night dark:text-white flex items-center gap-2">
              <Sparkles size={20} className="text-cercano-blue" />
              <span>Personalización y Distribución de Clientes</span>
            </h2>
            <p className="text-xs text-cercano-slate dark:text-gray-400 max-w-2xl">
              Configura instaladores con la identidad corporativa de tu organización (logo, color institucional), directivas de seguridad de acceso desatendido y perfiles de conexión empaquetados.
            </p>
          </div>
          {setActiveTab && (
            <AppleButton
              variant="primary"
              onClick={() => setActiveTab('builder')}
              icon={<ArrowRight size={16} />}
            >
              Abrir Personalizador
            </AppleButton>
          )}
        </div>
      </AppleCard>
    </div>
  );
};
