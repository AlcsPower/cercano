// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useMemo, useState, useRef } from 'react';
import {
  Search,
  Monitor,
  Smartphone,
  Laptop,
  Server,
  Trash2,
  Copy,
  Check,
  Plus,
  RefreshCw,
  Clock,
  Wifi,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { Device } from '../../types';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { AppleSheet } from '../common/AppleSheet';
import { StatusPill } from '../common/StatusPill';

export const DevicesView: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedOs, setSelectedOs] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<'all' | 'online' | 'offline'>('all');
  const [activeDevice, setActiveDevice] = useState<Device | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const lastActiveDeviceRef = useRef<Device | null>(null);
  if (activeDevice) {
    lastActiveDeviceRef.current = activeDevice;
  }
  const modalDevice = activeDevice || lastActiveDeviceRef.current;

  // New Device Modal State
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newDevName, setNewDevName] = useState('');
  const [newDevOs, setNewDevOs] = useState('Windows 11');
  const [newDevIp, setNewDevIp] = useState('192.168.10.');

  const fetchDevices = async () => {
    setLoading(true);
    try {
      const list = await apiClient.getDevices();
      setDevices(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 10000);
    return () => clearInterval(interval);
  }, []);

  // INSTANT SEARCH AND FILTERING - 0 DEBOUNCE DELAY
  const filteredDevices = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return devices.filter((dev) => {
      // Search query check
      const matchesSearch =
        !q ||
        dev.name.toLowerCase().includes(q) ||
        dev.id.toLowerCase().includes(q) ||
        (dev.hostname && dev.hostname.toLowerCase().includes(q)) ||
        (dev.ip_address && dev.ip_address.toLowerCase().includes(q)) ||
        (dev.os && dev.os.toLowerCase().includes(q));

      // OS filter check
      let matchesOs = true;
      if (selectedOs !== 'all') {
        const osLower = (dev.os || '').toLowerCase();
        if (selectedOs === 'windows') matchesOs = osLower.includes('win');
        else if (selectedOs === 'linux') matchesOs = osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian');
        else if (selectedOs === 'macos') matchesOs = osLower.includes('mac') || osLower.includes('darwin');
        else if (selectedOs === 'android') matchesOs = osLower.includes('android');
      }

      // Status filter check
      let matchesStatus = true;
      if (selectedStatus !== 'all') {
        matchesStatus = dev.status === selectedStatus;
      }

      return matchesSearch && matchesOs && matchesStatus;
    });
  }, [devices, searchQuery, selectedOs, selectedStatus]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(text);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDeleteDevice = async (id: string) => {
    if (window.confirm(`¿Está seguro de eliminar el dispositivo ${id}?`)) {
      await apiClient.deleteDevice(id);
      setActiveDevice(null);
      await fetchDevices();
    }
  };

  const handleRegisterDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDevName.trim()) return;

    const newId = `cercano-${Math.floor(100000 + Math.random() * 900000)}`;
    await apiClient.addOrHeartbeatDevice({
      id: newId,
      name: newDevName.trim(),
      hostname: newDevName.trim().toUpperCase().replace(/\s+/g, '-'),
      os: newDevOs,
      ip_address: newDevIp || '192.168.10.150',
      version: '1.4.0',
    });

    setIsAddModalOpen(false);
    setNewDevName('');
    await fetchDevices();
  };

  const getOsIcon = (os?: string | null) => {
    const lower = (os || '').toLowerCase();
    if (lower.includes('win')) return <Monitor size={18} className="text-blue-500" />;
    if (lower.includes('mac')) return <Laptop size={18} className="text-gray-700 dark:text-gray-300" />;
    if (lower.includes('android')) return <Smartphone size={18} className="text-emerald-500" />;
    if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian')) {
      return <Server size={18} className="text-amber-500" />;
    }
    return <Monitor size={18} className="text-cercano-slate" />;
  };

  const formatRelativeTime = (isoString?: string | null) => {
    if (!isoString) return 'Nunca';
    const diffSeconds = Math.max(0, Math.floor((Date.now() - new Date(isoString).getTime()) / 1000));
    if (diffSeconds < 30) return 'Hace unos segundos';
    if (diffSeconds < 60) return `Hace ${diffSeconds}s`;
    if (diffSeconds < 3600) return `Hace ${Math.floor(diffSeconds / 60)}m`;
    if (diffSeconds < 86400) return `Hace ${Math.floor(diffSeconds / 3600)}h`;
    return `Hace ${Math.floor(diffSeconds / 86400)}d`;
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Directorio de Dispositivos
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
            Gestión, telemetría y supervisión de agentes conectados en la red
          </p>
        </div>

        <div className="flex items-center gap-2">
          <AppleButton
            variant="secondary"
            size="sm"
            onClick={fetchDevices}
            icon={<RefreshCw size={14} className={loading ? 'animate-spin' : ''} />}
          >
            Actualizar
          </AppleButton>
          <AppleButton
            variant="primary"
            size="sm"
            onClick={() => setIsAddModalOpen(true)}
            icon={<Plus size={16} />}
          >
            Añadir Dispositivo
          </AppleButton>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="space-y-3">
        {/* Instant Search Input */}
        <div className="relative">
          <Search
            size={18}
            className="absolute left-4 top-3.5 text-cercano-slate dark:text-gray-400"
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por ID, nombre, hostname, IP o sistema operativo (búsqueda instantánea)..."
            className="w-full pl-11 pr-4 py-3 rounded-2xl bg-white/80 dark:bg-zinc-800/80 backdrop-blur-xl border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white placeholder:text-gray-400 text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 shadow-sm transition-all"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3.5 top-3 text-xs px-2 py-1 rounded-md bg-black/5 hover:bg-black/10 dark:bg-white/10 text-cercano-slate dark:text-gray-300"
            >
              Borrar
            </button>
          )}
        </div>

        {/* Filter Pills: OS & Status */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          {/* OS Selector */}
          <div className="flex items-center gap-1.5 overflow-x-auto py-1">
            <span className="text-xs font-semibold text-cercano-slate dark:text-gray-400 mr-1">
              SO:
            </span>
            {[
              { id: 'all', label: 'Todos' },
              { id: 'windows', label: 'Windows' },
              { id: 'linux', label: 'Linux' },
              { id: 'macos', label: 'macOS' },
              { id: 'android', label: 'Android' },
            ].map((os) => (
              <button
                key={os.id}
                onClick={() => setSelectedOs(os.id)}
                className={`btn-apple px-3 py-1 rounded-xl text-xs font-medium cursor-pointer transition-all ${
                  selectedOs === os.id
                    ? 'bg-cercano-blue text-white shadow-sm'
                    : 'bg-black/5 dark:bg-white/5 text-cercano-slate dark:text-gray-300 hover:bg-black/10 dark:hover:bg-white/10'
                }`}
              >
                {os.label}
              </button>
            ))}
          </div>

          {/* Status Selector */}
          <div className="flex items-center gap-1.5 py-1">
            <span className="text-xs font-semibold text-cercano-slate dark:text-gray-400 mr-1">
              Estado:
            </span>
            {[
              { id: 'all', label: 'Todos' },
              { id: 'online', label: 'En Línea' },
              { id: 'offline', label: 'Desconectados' },
            ].map((st) => (
              <button
                key={st.id}
                onClick={() => setSelectedStatus(st.id as any)}
                className={`btn-apple px-3 py-1 rounded-xl text-xs font-medium cursor-pointer transition-all ${
                  selectedStatus === st.id
                    ? 'bg-cercano-night dark:bg-white text-white dark:text-cercano-night shadow-sm'
                    : 'bg-black/5 dark:bg-white/5 text-cercano-slate dark:text-gray-300 hover:bg-black/10 dark:hover:bg-white/10'
                }`}
              >
                {st.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Devices List Cards */}
      {filteredDevices.length === 0 ? (
        <AppleCard className="text-center py-12">
          <Monitor size={36} className="mx-auto text-cercano-slate/40 mb-3" />
          <h3 className="text-base font-bold text-cercano-night dark:text-white">
            No se encontraron dispositivos
          </h3>
          <p className="text-xs text-cercano-slate dark:text-gray-400 max-w-sm mx-auto mt-1">
            Ningún dispositivo coincide con los filtros actuales o la búsqueda «{searchQuery}».
          </p>
        </AppleCard>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredDevices.map((dev) => {
            return (
              <AppleCard
                key={dev.id}
                hoverable
                onClick={() => setActiveDevice(dev)}
                className="flex flex-col justify-between group p-5"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2.5 rounded-2xl bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/5">
                        {getOsIcon(dev.os)}
                      </div>
                      <div>
                        <h3 className="font-bold text-sm text-cercano-night dark:text-white group-hover:text-cercano-blue transition-colors">
                          {dev.name}
                        </h3>
                        <p className="text-xs text-cercano-slate dark:text-gray-400 font-mono">
                          {dev.hostname || dev.id}
                        </p>
                      </div>
                    </div>
                    <StatusPill status={dev.status} size="sm" />
                  </div>

                  <div className="space-y-1.5 text-xs text-cercano-slate dark:text-gray-300 pt-1">
                    <div className="flex justify-between items-center py-0.5 border-b border-black/[0.04] dark:border-white/[0.04]">
                      <span className="text-cercano-slate dark:text-gray-400">ID:</span>
                      <span className="font-mono text-[11px] font-semibold text-cercano-night dark:text-white">
                        {dev.id}
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-0.5 border-b border-black/[0.04] dark:border-white/[0.04]">
                      <span className="text-cercano-slate dark:text-gray-400">IP LAN:</span>
                      <span className="font-mono text-[11px]">
                        {dev.ip_address || '—'}
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-0.5">
                      <span className="text-cercano-slate dark:text-gray-400">Sistema:</span>
                      <span className="truncate max-w-[170px]">
                        {dev.os || 'Desconocido'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/[0.04] flex items-center justify-between text-[11px] text-cercano-slate dark:text-gray-400">
                  <span className="flex items-center gap-1">
                    <Clock size={12} />
                    {formatRelativeTime(dev.last_seen_at)}
                  </span>
                  <span className="text-cercano-blue dark:text-blue-400 font-semibold group-hover:underline">
                    Ver detalles →
                  </span>
                </div>
              </AppleCard>
            );
          })}
        </div>
      )}

      {/* Device Details Apple Sheet Modal */}
      <AppleSheet
        isOpen={!!activeDevice}
        onClose={() => setActiveDevice(null)}
        title={modalDevice?.name || ''}
        subtitle={modalDevice ? `Dispositivo registrado en Cercano API • ID: ${modalDevice.id}` : ''}
      >
        {modalDevice && (
          <div className="space-y-6">
            {/* Status & Live Card */}
            <div className="p-4 rounded-2xl bg-black/[0.03] dark:bg-white/[0.04] border border-black/5 dark:border-white/[0.04] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-2xl bg-white dark:bg-zinc-800 shadow-sm">
                  {getOsIcon(modalDevice.os)}
                </div>
                <div>
                  <p className="text-xs text-cercano-slate dark:text-gray-400">
                    Estado en tiempo real
                  </p>
                  <p className="text-sm font-bold text-cercano-night dark:text-white flex items-center gap-2 mt-0.5">
                    <StatusPill status={modalDevice.status} />
                  </p>
                </div>
              </div>

              <AppleButton
                variant="secondary"
                size="sm"
                onClick={() => copyToClipboard(modalDevice.id)}
                icon={copiedId === modalDevice.id ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
              >
                {copiedId === modalDevice.id ? '¡Copiado!' : 'Copiar ID'}
              </AppleButton>
            </div>

            {/* Technical Specifications Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-1">
                <span className="text-cercano-slate dark:text-gray-400">Hostname</span>
                <p className="text-sm font-semibold text-cercano-night dark:text-white font-mono">
                  {modalDevice.hostname || '—'}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-1">
                <span className="text-cercano-slate dark:text-gray-400">Dirección IP de Red</span>
                <p className="text-sm font-semibold text-cercano-night dark:text-white font-mono flex items-center gap-1.5">
                  <Wifi size={14} className="text-cercano-blue" />
                  {modalDevice.ip_address || '127.0.0.1'}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-1">
                <span className="text-cercano-slate dark:text-gray-400">Sistema Operativo</span>
                <p className="text-sm font-semibold text-cercano-night dark:text-white">
                  {modalDevice.os || 'Desconocido'}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-1">
                <span className="text-cercano-slate dark:text-gray-400">Versión del Cliente Cercano</span>
                <p className="text-sm font-semibold text-cercano-night dark:text-white font-mono">
                  v{modalDevice.version || '1.4.0'}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-1">
                <span className="text-cercano-slate dark:text-gray-400">Último Heartbeat</span>
                <p className="text-xs font-semibold text-cercano-night dark:text-white font-mono">
                  {modalDevice.last_seen_at ? new Date(modalDevice.last_seen_at).toLocaleString() : '—'}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 space-y-1">
                <span className="text-cercano-slate dark:text-gray-400">Fecha de Alta</span>
                <p className="text-xs font-semibold text-cercano-night dark:text-white font-mono">
                  {new Date(modalDevice.created_at).toLocaleString()}
                </p>
              </div>
            </div>

            {/* Actions */}
            <div className="pt-4 border-t border-black/5 dark:border-white/[0.04] flex items-center justify-between">
              <AppleButton
                variant="danger"
                size="sm"
                onClick={() => handleDeleteDevice(modalDevice.id)}
                icon={<Trash2 size={14} />}
              >
                Eliminar Registro
              </AppleButton>

              <AppleButton
                variant="secondary"
                size="sm"
                onClick={() => setActiveDevice(null)}
              >
                Cerrar
              </AppleButton>
            </div>
          </div>
        )}
      </AppleSheet>

      {/* Add Device Modal */}
      <AppleSheet
          isOpen={isAddModalOpen}
          onClose={() => setIsAddModalOpen(false)}
          title="Añadir / Registrar Dispositivo"
          subtitle="Registra un agente manual o emite un heartbeat de prueba en cercano-api"
        >
          <form onSubmit={handleRegisterDevice} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                Nombre del Equipo / Estación
              </label>
              <input
                type="text"
                required
                value={newDevName}
                onChange={(e) => setNewDevName(e.target.value)}
                placeholder="Ej. Laptop Mantenimiento 03"
                className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                  Sistema Operativo
                </label>
                <select
                  value={newDevOs}
                  onChange={(e) => setNewDevOs(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-xl bg-black/5 dark:bg-zinc-800 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40"
                >
                  <option value="Windows 11 Pro">Windows 11 Pro</option>
                  <option value="Windows 10 Enterprise">Windows 10 Enterprise</option>
                  <option value="Ubuntu Linux 24.04">Ubuntu Linux 24.04</option>
                  <option value="Debian 12 Bookworm">Debian 12 Bookworm</option>
                  <option value="macOS Sequoia 15.1">macOS Sequoia 15.1</option>
                  <option value="Android 14">Android 14</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                  Dirección IP
                </label>
                <input
                  type="text"
                  value={newDevIp}
                  onChange={(e) => setNewDevIp(e.target.value)}
                  placeholder="192.168.10.55"
                  className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40 font-mono"
                />
              </div>
            </div>

            <div className="pt-4 border-t border-black/5 dark:border-white/[0.04] flex items-center justify-end gap-3">
              <AppleButton
                type="button"
                variant="ghost"
                size="md"
                onClick={() => setIsAddModalOpen(false)}
              >
                Cancelar
              </AppleButton>
              <AppleButton
                type="submit"
                variant="primary"
                size="md"
                icon={<Plus size={16} />}
              >
                Guardar Dispositivo
              </AppleButton>
            </div>
          </form>
      </AppleSheet>
    </div>
  );
};
