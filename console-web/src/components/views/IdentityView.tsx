// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import {
  Users,
  BookOpen,
  Sliders,
  ShieldCheck,
  Activity,
  Plus,
  Trash2,
  RefreshCw,
  Search,
  AlertCircle,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { useAuth } from '../../context/AuthContext';
import {
  AddressBookItem,
  EffectivePolicyResponse,
  GroupItem,
  IdpItem,
  PolicyItem,
} from '../../types';
import { AppleButton } from '../common/AppleButton';
import { AppleCard } from '../common/AppleCard';
import { StatusPill } from '../common/StatusPill';

type IdentitySubTab = 'groups' | 'address-book' | 'policies' | 'diagnostic' | 'idp';

export const IdentityView: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const isAuditor = user?.role === 'auditor';

  const [activeSubTab, setActiveSubTab] = useState<IdentitySubTab>('groups');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Groups state
  const [groups, setGroups] = useState<GroupItem[]>([]);
  const [newGroupName, setNewGroupName] = useState('');
  const [newGroupKind, setNewGroupKind] = useState<'user' | 'device'>('user');
  const [newGroupDesc, setNewGroupDesc] = useState('');

  // Address book state
  const [addressBook, setAddressBook] = useState<AddressBookItem[]>([]);
  const [bookSearch, setBookSearch] = useState('');
  const [newContactName, setNewContactName] = useState('');
  const [newContactDeviceId, setNewContactDeviceId] = useState('');
  const [newContactHost, setNewContactHost] = useState('');
  const [newContactPort, setNewContactPort] = useState<number>(21118);

  // Policies state
  const [policies, setPolicies] = useState<PolicyItem[]>([]);

  // Diagnostics state
  const [diagDeviceId, setDiagDeviceId] = useState('');
  const [evaluatingDiag, setEvaluatingDiag] = useState(false);
  const [diagResult, setDiagResult] = useState<EffectivePolicyResponse | null>(null);

  // IdP state
  const [idps, setIdps] = useState<IdpItem[]>([]);
  const [testingIdpId, setTestingIdpId] = useState<string | null>(null);
  const [idpTestStatus, setIdpTestStatus] = useState<Record<string, string>>({});

  const loadData = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      if (activeSubTab === 'groups') {
        const data = await apiClient.listGroups();
        setGroups(data);
      } else if (activeSubTab === 'address-book') {
        const data = await apiClient.listAddressBook();
        setAddressBook(data);
      } else if (activeSubTab === 'policies') {
        const data = await apiClient.listPolicies();
        setPolicies(data);
      } else if (activeSubTab === 'idp') {
        const data = await apiClient.listIdps();
        setIdps(data);
      }
    } catch (e: any) {
      setErrorMsg(e.message || 'Error al cargar datos desde el API.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeSubTab !== 'diagnostic') {
      loadData();
    }
  }, [activeSubTab]);

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGroupName.trim()) return;
    try {
      await apiClient.createGroup({
        name: newGroupName.trim(),
        kind: newGroupKind,
        description: newGroupDesc.trim() || undefined,
      });
      setNewGroupName('');
      setNewGroupDesc('');
      loadData();
    } catch (e: any) {
      alert(e.message || 'Error al crear grupo');
    }
  };

  const handleDeleteGroup = async (id: string) => {
    if (!confirm('¿Eliminar este grupo de Cercano?')) return;
    try {
      await apiClient.deleteGroup(id);
      loadData();
    } catch (e: any) {
      alert(e.message || 'Error al eliminar grupo');
    }
  };

  const handleCreateAddressBook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newContactName.trim()) return;
    try {
      await apiClient.createAddressBook({
        name: newContactName.trim(),
        device_id: newContactDeviceId.trim() || undefined,
        host: newContactHost.trim() || undefined,
        port: newContactPort || undefined,
      });
      setNewContactName('');
      setNewContactDeviceId('');
      setNewContactHost('');
      loadData();
    } catch (e: any) {
      alert(e.message || 'Error al crear contacto');
    }
  };

  const handleDeleteContact = async (id: string) => {
    if (!confirm('¿Eliminar este contacto de la libreta?')) return;
    try {
      await apiClient.deleteAddressBook(id);
      loadData();
    } catch (e: any) {
      alert(e.message || 'Error al eliminar contacto');
    }
  };

  const handleEvaluatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!diagDeviceId.trim()) return;
    setEvaluatingDiag(true);
    setErrorMsg(null);
    try {
      const res = await apiClient.getEffectivePolicy(diagDeviceId.trim());
      setDiagResult(res);
    } catch (e: any) {
      setErrorMsg(e.message || 'Error al evaluar política');
      setDiagResult(null);
    } finally {
      setEvaluatingDiag(false);
    }
  };

  const handleTestIdp = async (id: string) => {
    setTestingIdpId(id);
    try {
      const res = await apiClient.testIdp(id);
      setIdpTestStatus((prev) => ({
        ...prev,
        [id]: res.ok ? 'Saludable (200 OK)' : `Fallo: ${res.error || 'No responde'}`,
      }));
    } catch {
      setIdpTestStatus((prev) => ({
        ...prev,
        [id]: 'Error de conexión',
      }));
    } finally {
      setTestingIdpId(null);
    }
  };

  const filteredContacts = addressBook.filter((c) => {
    const q = bookSearch.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      (c.device_id && c.device_id.toLowerCase().includes(q)) ||
      (c.host && c.host.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6 pt-4 animate-fade-in">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-cercano-night dark:text-white">
            Control de Acceso, Identidad y Estrategias
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
            Gestión de grupos N:M, libreta corporativa, políticas centrales y diagnóstico explicable (Fase 5).
          </p>
        </div>
        <div className="flex items-center gap-2">
          <AppleButton variant="secondary" onClick={loadData} disabled={loading}>
            <RefreshCw size={15} className={`mr-2 ${loading ? 'animate-spin' : ''}`} />
            Actualizar
          </AppleButton>
        </div>
      </div>

      {/* Subtabs Navigation */}
      <div className="flex flex-wrap border-b border-black/5 dark:border-white/10 gap-2">
        <button
          onClick={() => setActiveSubTab('groups')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'groups'
              ? 'border-cercano-blue text-cercano-blue dark:text-blue-400 dark:border-blue-400'
              : 'border-transparent text-cercano-slate hover:text-cercano-night dark:text-gray-400 dark:hover:text-white'
          }`}
        >
          <Users size={16} />
          Grupos ({groups.length})
        </button>

        {!isAuditor && (
          <button
            onClick={() => setActiveSubTab('address-book')}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeSubTab === 'address-book'
                ? 'border-cercano-blue text-cercano-blue dark:text-blue-400 dark:border-blue-400'
                : 'border-transparent text-cercano-slate hover:text-cercano-night dark:text-gray-400 dark:hover:text-white'
            }`}
          >
            <BookOpen size={16} />
            Libreta de Direcciones
          </button>
        )}

        <button
          onClick={() => setActiveSubTab('policies')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'policies'
              ? 'border-cercano-blue text-cercano-blue dark:text-blue-400 dark:border-blue-400'
              : 'border-transparent text-cercano-slate hover:text-cercano-night dark:text-gray-400 dark:hover:text-white'
          }`}
        >
          <Sliders size={16} />
          Estrategias Centrales
        </button>

        <button
          onClick={() => setActiveSubTab('diagnostic')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'diagnostic'
              ? 'border-cercano-blue text-cercano-blue dark:text-blue-400 dark:border-blue-400'
              : 'border-transparent text-cercano-slate hover:text-cercano-night dark:text-gray-400 dark:hover:text-white'
          }`}
        >
          <Activity size={16} />
          Diagnóstico de Política Efectiva
        </button>

        {isAdmin && (
          <button
            onClick={() => setActiveSubTab('idp')}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeSubTab === 'idp'
                ? 'border-cercano-blue text-cercano-blue dark:text-blue-400 dark:border-blue-400'
                : 'border-transparent text-cercano-slate hover:text-cercano-night dark:text-gray-400 dark:hover:text-white'
            }`}
          >
            <ShieldCheck size={16} />
            Proveedores SSO (OIDC/LDAP)
          </button>
        )}
      </div>

      {errorMsg && (
        <div className="p-3.5 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/50 rounded-xl flex items-center gap-3 text-sm text-red-700 dark:text-red-300">
          <AlertCircle size={18} className="shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Subtab 1: Grupos */}
      {activeSubTab === 'groups' && (
        <div className="space-y-6">
          {isAdmin && (
            <AppleCard className="p-5">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-cercano-slate dark:text-gray-400 mb-3">
                Crear Nuevo Grupo
              </h2>
              <form onSubmit={handleCreateGroup} className="flex flex-col sm:flex-row gap-3 items-end">
                <div className="flex-1 w-full">
                  <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                    Nombre del Grupo
                  </label>
                  <input
                    type="text"
                    required
                    value={newGroupName}
                    onChange={(e) => setNewGroupName(e.target.value)}
                    placeholder="ej. Mesa de Ayuda IT"
                    className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                  />
                </div>
                <div className="w-full sm:w-44">
                  <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                    Tipo de Ámbito
                  </label>
                  <select
                    value={newGroupKind}
                    onChange={(e) => setNewGroupKind(e.target.value as any)}
                    className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                  >
                    <option value="user">Usuarios (Técnicos)</option>
                    <option value="device">Dispositivos (Parque)</option>
                  </select>
                </div>
                <div className="flex-1 w-full">
                  <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                    Descripción (opcional)
                  </label>
                  <input
                    type="text"
                    value={newGroupDesc}
                    onChange={(e) => setNewGroupDesc(e.target.value)}
                    placeholder="Descripción funcional..."
                    className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                  />
                </div>
                <AppleButton type="submit" variant="primary">
                  <Plus size={16} className="mr-1.5" />
                  Crear Grupo
                </AppleButton>
              </form>
            </AppleCard>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {groups.map((g) => (
              <AppleCard key={g.id} className="p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-cercano-slate dark:text-gray-400">
                      ID: {g.id.slice(0, 8)}...
                    </span>
                    <StatusPill
                      status={g.kind === 'user' ? 'online' : 'operational'}
                      label={g.kind === 'user' ? 'Grupo Usuarios' : 'Grupo Dispositivos'}
                    />
                  </div>
                  <h3 className="text-base font-semibold text-cercano-night dark:text-white mt-2">
                    {g.name}
                  </h3>
                  <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1 line-clamp-2">
                    {g.description || 'Sin descripción'}
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/5 flex items-center justify-between text-xs text-cercano-slate dark:text-gray-500">
                  <span>Creado: {new Date(g.created_at).toLocaleDateString()}</span>
                  {isAdmin && (
                    <button
                      onClick={() => handleDeleteGroup(g.id)}
                      className="p-1 text-red-500 hover:text-red-700 transition-colors"
                      title="Eliminar grupo"
                    >
                      <Trash2 size={15} />
                    </button>
                  )}
                </div>
              </AppleCard>
            ))}

            {groups.length === 0 && !loading && (
              <div className="col-span-full p-8 text-center text-sm text-cercano-slate dark:text-gray-500 border border-dashed border-black/10 dark:border-white/10 rounded-2xl">
                No hay grupos configurados actualmente.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtab 2: Libreta de Direcciones */}
      {activeSubTab === 'address-book' && (
        <div className="space-y-6">
          {isAdmin && (
            <AppleCard className="p-5">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-cercano-slate dark:text-gray-400 mb-3">
                Nuevo Contacto en Libreta
              </h2>
              <form onSubmit={handleCreateAddressBook} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
                <div>
                  <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                    Nombre o Etiqueta
                  </label>
                  <input
                    type="text"
                    required
                    value={newContactName}
                    onChange={(e) => setNewContactName(e.target.value)}
                    placeholder="Estación Nómina"
                    className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                    Device ID
                  </label>
                  <input
                    type="text"
                    value={newContactDeviceId}
                    onChange={(e) => setNewContactDeviceId(e.target.value)}
                    placeholder="cercano-dev-XXXXX"
                    className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                    Host / IP LAN
                  </label>
                  <input
                    type="text"
                    value={newContactHost}
                    onChange={(e) => setNewContactHost(e.target.value)}
                    placeholder="172.16.8.50"
                    className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                  />
                </div>
                <div className="flex gap-2">
                  <div className="w-24">
                    <label className="block text-xs font-medium mb-1 text-cercano-slate dark:text-gray-400">
                      Puerto
                    </label>
                    <input
                      type="number"
                      value={newContactPort}
                      onChange={(e) => setNewContactPort(Number(e.target.value))}
                      className="w-full px-3 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
                    />
                  </div>
                  <AppleButton type="submit" variant="primary" className="flex-1">
                    <Plus size={16} />
                  </AppleButton>
                </div>
              </form>
            </AppleCard>
          )}

          <div className="flex items-center gap-2">
            <div className="relative flex-1 max-w-md">
              <Search size={16} className="absolute left-3 top-2.5 text-cercano-slate dark:text-gray-400" />
              <input
                type="text"
                placeholder="Buscar por nombre, device_id o host..."
                value={bookSearch}
                onChange={(e) => setBookSearch(e.target.value)}
                className="w-full pl-9 pr-4 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
              />
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-black/10 dark:border-white/10">
            <table className="w-full text-left text-sm">
              <thead className="bg-black/[0.02] dark:bg-white/[0.02] border-b border-black/10 dark:border-white/10 text-xs font-semibold uppercase text-cercano-slate dark:text-gray-400">
                <tr>
                  <th className="px-4 py-3">Nombre</th>
                  <th className="px-4 py-3">Device ID</th>
                  <th className="px-4 py-3">Host / Conexión</th>
                  <th className="px-4 py-3">Creado</th>
                  {isAdmin && <th className="px-4 py-3 text-right">Acciones</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-black/5 dark:divide-white/5">
                {filteredContacts.map((c) => (
                  <tr key={c.id} className="hover:bg-black/[0.01] dark:hover:bg-white/[0.01]">
                    <td className="px-4 py-3 font-medium text-cercano-night dark:text-white">
                      {c.name}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-cercano-slate dark:text-gray-400">
                      {c.device_id || '—'}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">
                      {c.host ? `${c.host}:${c.port || 21118}` : 'Rendezvous automático'}
                    </td>
                    <td className="px-4 py-3 text-xs text-cercano-slate dark:text-gray-400">
                      {new Date(c.created_at).toLocaleDateString()}
                    </td>
                    {isAdmin && (
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => handleDeleteContact(c.id)}
                          className="p-1 text-red-500 hover:text-red-700 transition-colors"
                        >
                          <Trash2 size={15} />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
                {filteredContacts.length === 0 && (
                  <tr>
                    <td colSpan={isAdmin ? 5 : 4} className="px-4 py-8 text-center text-cercano-slate dark:text-gray-500">
                      No hay contactos en la libreta.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Subtab 3: Estrategias Centrales */}
      {activeSubTab === 'policies' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {policies.map((p) => (
              <AppleCard key={p.id} className="p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs uppercase font-semibold text-cercano-blue dark:text-blue-400">
                      {p.scope_type} {p.scope_id ? `(${p.scope_id.slice(0, 8)})` : ''}
                    </span>
                    <StatusPill
                      status={p.state === 'active' ? 'online' : 'offline'}
                      label={p.state.toUpperCase()}
                    />
                  </div>
                  <div className="mt-2 text-xs font-mono text-cercano-slate dark:text-gray-400">
                    Versión: v{p.version} | ID: {p.id.slice(0, 8)}...
                  </div>
                  <div className="mt-3 bg-black/[0.03] dark:bg-white/[0.05] p-2.5 rounded-lg font-mono text-xs text-cercano-night dark:text-white overflow-x-auto max-h-36">
                    <pre>{JSON.stringify(p.document, null, 2)}</pre>
                  </div>
                </div>
                <div className="mt-3 pt-2 border-t border-black/5 dark:border-white/5 flex items-center justify-between text-xs text-cercano-slate dark:text-gray-500">
                  <span className="truncate max-w-[200px]" title={p.document_sha256}>
                    SHA: {p.document_sha256.slice(0, 12)}...
                  </span>
                  <span>{new Date(p.created_at).toLocaleDateString()}</span>
                </div>
              </AppleCard>
            ))}

            {policies.length === 0 && !loading && (
              <div className="col-span-full p-8 text-center text-sm text-cercano-slate dark:text-gray-500 border border-dashed border-black/10 dark:border-white/10 rounded-2xl">
                No hay políticas centrales registradas.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtab 4: Diagnóstico de Política Efectiva (TC-F5-061) */}
      {activeSubTab === 'diagnostic' && (
        <div className="space-y-6">
          <AppleCard className="p-5">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-cercano-slate dark:text-gray-400 mb-2">
              Evaluación y Explicabilidad de Política Efectiva (TC-F5-061)
            </h2>
            <p className="text-xs text-cercano-slate dark:text-gray-400 mb-4">
              Resuelve determinísticamente la política resultante para un dispositivo según las capas P0 (perfil firmado) → P1 (global) → P2 (grupos) → P3 (dispositivo).
            </p>
            <form onSubmit={handleEvaluatePolicy} className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                required
                value={diagDeviceId}
                onChange={(e) => setDiagDeviceId(e.target.value)}
                placeholder="Introduzca el identificador del dispositivo (ej. cercano-dev-91820)"
                className="flex-1 px-4 py-2 bg-black/[0.03] dark:bg-white/[0.05] border border-black/10 dark:border-white/10 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue"
              />
              <AppleButton type="submit" variant="primary" disabled={evaluatingDiag}>
                <Activity size={16} className={`mr-2 ${evaluatingDiag ? 'animate-spin' : ''}`} />
                Evaluar Política
              </AppleButton>
            </form>
          </AppleCard>

          {diagResult && (
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900 rounded-xl text-sm text-blue-900 dark:text-blue-200">
                <div>
                  <span className="font-semibold">Dispositivo:</span> {diagResult.device_id} |{' '}
                  <span className="font-semibold">Perfil P0 Base:</span> {diagResult.p0_role}
                </div>
                <div className="text-xs text-blue-700 dark:text-blue-300">
                  Evaluado: {new Date(diagResult.evaluated_at).toLocaleTimeString()}
                </div>
              </div>

              <div className="overflow-x-auto rounded-xl border border-black/10 dark:border-white/10">
                <table className="w-full text-left text-sm">
                  <thead className="bg-black/[0.02] dark:bg-white/[0.02] border-b border-black/10 dark:border-white/10 text-xs font-semibold uppercase text-cercano-slate dark:text-gray-400">
                    <tr>
                      <th className="px-4 py-3">Clave de Estrategia</th>
                      <th className="px-4 py-3">Valor Efectivo</th>
                      <th className="px-4 py-3">Fuente de Precedencia</th>
                      <th className="px-4 py-3">Regla Aplicada</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-black/5 dark:divide-white/5 font-mono text-xs">
                    {Object.entries(diagResult.explanation).map(([key, exp]) => (
                      <tr key={key} className="hover:bg-black/[0.01] dark:hover:bg-white/[0.01]">
                        <td className="px-4 py-3 font-semibold text-cercano-night dark:text-white">
                          {key}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs ${
                            exp.value === true
                              ? 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300'
                              : exp.value === false
                              ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300'
                              : 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300'
                          }`}>
                            {String(exp.value)}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-cercano-blue dark:text-blue-400 font-medium">
                          {exp.source}
                        </td>
                        <td className="px-4 py-3 text-cercano-slate dark:text-gray-400">
                          {exp.rule}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Subtab 5: Proveedores SSO (OIDC/LDAP) */}
      {activeSubTab === 'idp' && isAdmin && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {idps.map((idp) => (
              <AppleCard key={idp.id} className="p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs uppercase font-semibold text-cercano-blue dark:text-blue-400">
                      {idp.kind.toUpperCase()} SSO
                    </span>
                    <StatusPill
                      status={idp.enabled ? 'online' : 'offline'}
                      label={idp.enabled ? 'ACTIVO' : 'DESHABILITADO'}
                    />
                  </div>
                  <h3 className="text-base font-semibold text-cercano-night dark:text-white mt-2">
                    {idp.name}
                  </h3>
                  <div className="mt-2 text-xs font-mono text-cercano-slate dark:text-gray-400 space-y-1">
                    {idp.config.issuer && <div>Issuer: {idp.config.issuer}</div>}
                    {idp.config.client_id && <div>Client ID: {idp.config.client_id}</div>}
                    {idp.config.url && <div>URL: {idp.config.url}</div>}
                    {idp.config.base_dn && <div>Base DN: {idp.config.base_dn}</div>}
                    <div>Secretos: ******** (Enmascarados en servidor)</div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/5 flex items-center justify-between">
                  <span className="text-xs text-cercano-slate dark:text-gray-500">
                    {idpTestStatus[idp.id] || 'Estado no verificado'}
                  </span>
                  <AppleButton
                    variant="secondary"
                    onClick={() => handleTestIdp(idp.id)}
                    disabled={testingIdpId === idp.id}
                  >
                    {testingIdpId === idp.id ? 'Probando...' : 'Probar Conectividad'}
                  </AppleButton>
                </div>
              </AppleCard>
            ))}

            {idps.length === 0 && !loading && (
              <div className="col-span-full p-8 text-center text-sm text-cercano-slate dark:text-gray-500 border border-dashed border-black/10 dark:border-white/10 rounded-2xl">
                No hay proveedores de identidad configurados.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
