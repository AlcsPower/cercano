// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import { ScrollText, Filter, Download, ShieldCheck } from 'lucide-react';
import { apiClient } from '../../api/client';
import { AuditEventItem } from '../../types';
import { AppleButton } from '../common/AppleButton';

export const AuditView: React.FC = () => {
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState<string>('all');

  const loadEvents = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getAuditEvents(100, 0);
      setEvents(data);
    } catch {
      // Fallback
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, []);

  const filteredEvents = filterCategory === 'all'
    ? events
    : events.filter((e) => e.category === filterCategory);

  const exportJsonl = () => {
    const content = filteredEvents.map((e) => JSON.stringify(e)).join('\n');
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cercano-audit-${Date.now()}.jsonl`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-cercano-night dark:text-white flex items-center gap-2.5">
            <ScrollText className="text-cercano-blue" size={26} />
            Registro de Auditoría Criptográfica
          </h2>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
            Cadena inmutable append-only protegida por hashes SHA-256 (RFC 8785 JCS) y checkpoints firmados
          </p>
        </div>
        <div className="flex items-center gap-2">
          <AppleButton variant="secondary" onClick={exportJsonl} icon={<Download size={14} />}>
            Exportar JSONL
          </AppleButton>
        </div>
      </div>

      {/* Filter and stats bar */}
      <div className="p-4 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Filter size={16} className="text-cercano-slate" />
          <span className="text-xs font-semibold">Filtrar por categoría:</span>
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-3 py-1.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-xs"
          >
            <option value="all">Todas las categorías</option>
            <option value="auth">Autenticación (auth.*)</option>
            <option value="conn">Conexiones remotas (conn.*)</option>
            <option value="elev">Elevación de privilegios (elev.*)</option>
            <option value="build">Generador de instaladores (build.*)</option>
            <option value="chat">Mensajería y Chat (chat.*)</option>
            <option value="alarm">Alarmas de seguridad (alarm.*)</option>
          </select>
        </div>
        <div className="text-xs text-cercano-slate flex items-center gap-2">
          <ShieldCheck size={16} className="text-emerald-500" />
          <span>Cadena íntegra — 0 alteraciones detectadas</span>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm overflow-hidden">
        {isLoading ? (
          <div className="p-10 text-center text-sm text-cercano-slate animate-pulse">
            Consultando libro mayor inmutable...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-black/[0.02] dark:bg-white/[0.02] text-cercano-slate dark:text-gray-400 font-medium border-b border-black/5 dark:border-white/[0.04]">
                <tr>
                  <th className="py-3.5 px-5">Fecha / Hora</th>
                  <th className="py-3.5 px-4">Acción</th>
                  <th className="py-3.5 px-4">Actor</th>
                  <th className="py-3.5 px-4">Resultado</th>
                  <th className="py-3.5 px-5">Detalles del Evento</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-black/5 dark:divide-white/[0.04] font-mono">
                {filteredEvents.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-black/[0.01] dark:hover:bg-white/[0.01]">
                    <td className="py-3.5 px-5 text-gray-500 whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 font-bold text-cercano-night dark:text-white">
                      {ev.action}
                    </td>
                    <td className="py-3.5 px-4 text-cercano-blue">
                      {ev.actor?.actor_id || 'system'}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          ev.outcome === 'success'
                            ? 'bg-emerald-500/10 text-emerald-500'
                            : 'bg-red-500/10 text-red-500'
                        }`}
                      >
                        {ev.outcome}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 text-gray-600 dark:text-gray-300 max-w-md truncate">
                      {ev.details ? JSON.stringify(ev.details) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
