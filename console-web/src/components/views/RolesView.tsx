// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import { ShieldCheck, Info, Check, X, Search, Shield, Lock, Users, AlertCircle } from 'lucide-react';
import { apiClient } from '../../api/client';
import { RoleDetail } from '../../types';

interface MatrixRow {
  permission: string;
  category: string;
  description: string;
  admin: 'yes' | 'no' | 'own';
  operator: 'yes' | 'no' | 'own';
  auditor: 'yes' | 'no' | 'own';
  user: 'yes' | 'no' | 'own';
}

const PERMISSION_MATRIX: MatrixRow[] = [
  {
    permission: 'users:read',
    category: 'Usuarios',
    description: 'Consultar listado de cuentas institucionales',
    admin: 'yes',
    operator: 'own',
    auditor: 'own',
    user: 'own',
  },
  {
    permission: 'users:manage',
    category: 'Usuarios',
    description: 'Crear, actualizar roles y eliminar cuentas de usuarios',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'roles:read',
    category: 'Roles y Privilegios',
    description: 'Inspeccionar matriz de permisos del sistema',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'roles:manage',
    category: 'Roles y Privilegios',
    description: 'Modificar directivas de asignación de roles',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'devices:read',
    category: 'Dispositivos',
    description: 'Ver inventario de terminales de soporte conectadas',
    admin: 'yes',
    operator: 'yes',
    auditor: 'yes',
    user: 'yes',
  },
  {
    permission: 'devices:manage',
    category: 'Dispositivos',
    description: 'Eliminar o modificar configuraciones de terminales',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'audit:read',
    category: 'Auditoría',
    description: 'Consultar eventos forenses en bitácora de seguridad',
    admin: 'yes',
    operator: 'no',
    auditor: 'yes',
    user: 'no',
  },
  {
    permission: 'audit:export',
    category: 'Auditoría',
    description: 'Descargar exportaciones forenses JSONL/CSV verificadas',
    admin: 'yes',
    operator: 'no',
    auditor: 'yes',
    user: 'no',
  },
  {
    permission: 'settings:read',
    category: 'Ajustes',
    description: 'Visualizar directivas globales de la consola y servidor',
    admin: 'yes',
    operator: 'yes',
    auditor: 'yes',
    user: 'yes',
  },
  {
    permission: 'settings:manage',
    category: 'Ajustes',
    description: 'Actualizar configuración institucional del sistema',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'builder:create:soporte',
    category: 'Generador',
    description: 'Generar clientes personalizados de soporte rápido',
    admin: 'yes',
    operator: 'yes',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'builder:create:tecnico',
    category: 'Generador',
    description: 'Generar clientes con acceso técnico desatendido',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'builder:download',
    category: 'Generador',
    description: 'Descargar binarios generados desde la cola de compilación',
    admin: 'yes',
    operator: 'yes',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'chat:attend',
    category: 'Chat',
    description: 'Tomar y responder sesiones entrantes de asistencia',
    admin: 'yes',
    operator: 'yes',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'chat:manage',
    category: 'Chat',
    description: 'Configurar marca institucional y textos del chat',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: 'chat:read',
    category: 'Chat',
    description: 'Supervisar y auditar historial de conversaciones',
    admin: 'yes',
    operator: 'yes',
    auditor: 'yes',
    user: 'yes',
  },
  {
    permission: 'server:keys:rotate',
    category: 'Seguridad',
    description: 'Rotar llaves criptográficas Ed25519 del servidor',
    admin: 'yes',
    operator: 'no',
    auditor: 'no',
    user: 'no',
  },
  {
    permission: '2fa:enroll',
    category: 'Segundo Factor (2FA)',
    description: 'Enrolar y confirmar factor TOTP RFC 6238 propio',
    admin: 'yes',
    operator: 'yes',
    auditor: 'yes',
    user: 'yes',
  },
  {
    permission: '2fa:revoke',
    category: 'Segundo Factor (2FA)',
    description: 'Revocar factor 2FA (administrador: todos; operador: propio)',
    admin: 'yes',
    operator: 'own',
    auditor: 'no',
    user: 'no',
  },
];

export const RolesView: React.FC = () => {
  const [roles, setRoles] = useState<RoleDetail[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchRoles = async () => {
      setIsLoading(true);
      try {
        const data = await apiClient.getRoles();
        setRoles(data);
      } catch (err: unknown) {
        if (err instanceof Error) setError(err.message);
      } finally {
        setIsLoading(false);
      }
    };
    fetchRoles();
  }, []);

  const categories = ['all', ...Array.from(new Set(PERMISSION_MATRIX.map((r) => r.category)))];

  const filteredRows = PERMISSION_MATRIX.filter((row) => {
    const matchesSearch =
      row.permission.toLowerCase().includes(searchTerm.toLowerCase()) ||
      row.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = categoryFilter === 'all' || row.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  const renderBadge = (val: 'yes' | 'no' | 'own') => {
    if (val === 'yes') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
          <Check size={12} strokeWidth={2.5} /> Sí
        </span>
      );
    }
    if (val === 'own') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-600 dark:text-amber-400">
          Propio
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-zinc-500/10 text-zinc-400 dark:text-zinc-500">
        <X size={12} strokeWidth={2.5} /> No
      </span>
    );
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 animate-fade-in">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-cercano-night dark:text-white flex items-center gap-2.5">
            <ShieldCheck className="text-cercano-blue" size={26} />
            Matriz de Roles y Permisos (RBAC)
          </h2>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
            Definición estricta de directivas de seguridad y capacidades por rol institucional
          </p>
        </div>
      </div>

      {/* Info Callout */}
      <div className="p-4 rounded-3xl bg-cercano-blue/5 border border-cercano-blue/15 text-cercano-slate dark:text-gray-300 text-xs flex items-start gap-3">
        <Info size={18} className="text-cercano-blue shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-cercano-night dark:text-white">
            Gobernanza y Aplicación en Servidor (Axum / cercano-api)
          </p>
          <p className="leading-relaxed text-[11.5px] text-gray-600 dark:text-gray-400">
            La matriz de permisos se aplica directamente mediante middleware de autorización en cada endpoint
            REST de la API institucional (<code className="font-mono bg-black/5 dark:bg-white/5 px-1 py-0.5 rounded">RequirePermission</code>).
            Los roles son inmutables en versión 1.0 para garantizar integridad forense.
          </p>
        </div>
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

      {/* Roles Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-purple-500/10 text-purple-600 dark:text-purple-400">
                admin
              </span>
              <Lock size={16} className="text-purple-500/60" />
            </div>
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">Administrador</h3>
            <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
              Control total del sistema, rotación de llaves criptográficas, gestión de usuarios, auditoría forense y 2FA.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/[0.04] text-[11px] font-mono text-purple-600 dark:text-purple-400 font-semibold">
            Todos los permisos habilitados
          </div>
        </div>

        <div className="p-5 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-cercano-blue/10 text-cercano-blue">
                operator
              </span>
              <Shield size={16} className="text-cercano-blue/60" />
            </div>
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">Operador Técnico</h3>
            <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
              Atención de terminales remotas, chat en vivo y generación de instaladores de soporte rápido.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/[0.04] text-[11px] font-mono text-cercano-blue font-semibold">
            Operación y asistencia activa
          </div>
        </div>

        <div className="p-5 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                auditor
              </span>
              <ShieldCheck size={16} className="text-emerald-500/60" />
            </div>
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">Auditor Forense</h3>
            <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
              Inspección de bitácoras, exportación forense inmutable y supervisión sin permisos de escritura ni operación.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/[0.04] text-[11px] font-mono text-emerald-600 dark:text-emerald-400 font-semibold">
            Solo lectura y verificación
          </div>
        </div>

        <div className="p-5 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-zinc-500/10 text-zinc-500">
                user (legacy)
              </span>
              <Users size={16} className="text-zinc-400" />
            </div>
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">Usuario Básico</h3>
            <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
              Acceso restringido de solo lectura tratado como operador sin privilegios hasta su migración por un admin.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/[0.04] text-[11px] font-mono text-zinc-500 font-semibold">
            Privilegios mínimos
          </div>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-sm">
          <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Buscar permiso o descripción..."
            className="w-full pl-9 pr-3.5 py-2 text-xs rounded-xl bg-white/80 dark:bg-zinc-800/80 border border-black/10 dark:border-white/10 text-cercano-night dark:text-white focus:outline-none focus:ring-2 focus:ring-cercano-blue/40"
          />
        </div>

        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all whitespace-nowrap cursor-pointer ${
                categoryFilter === cat
                  ? 'bg-cercano-blue text-white shadow-sm'
                  : 'bg-black/5 dark:bg-white/5 text-cercano-slate dark:text-gray-300 hover:bg-black/10 dark:hover:bg-white/10'
              }`}
            >
              {cat === 'all' ? 'Todas las categorías' : cat}
            </button>
          ))}
        </div>
      </div>

      {/* Permissions Matrix Table */}
      <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm overflow-hidden">
        <div className="p-4 border-b border-black/5 dark:border-white/[0.04] flex items-center justify-between">
          <h3 className="font-semibold text-xs sm:text-sm text-cercano-night dark:text-white">
            Matriz Comparativa de Capacidades ({filteredRows.length} permisos, {roles.length || 4} roles institucionales)
          </h3>
          {isLoading && (
            <span className="text-[11px] text-cercano-slate animate-pulse">Sincronizando con servidor...</span>
          )}
        </div>

        {filteredRows.length === 0 ? (
          <div className="p-12 text-center text-xs text-cercano-slate dark:text-gray-400">
            No se encontraron permisos que coincidan con la búsqueda.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs" aria-label="Matriz de roles y permisos">
              <thead className="bg-black/[0.02] dark:bg-white/[0.02] text-cercano-slate dark:text-gray-400 font-medium border-b border-black/5 dark:border-white/[0.04]">
                <tr>
                  <th className="py-3 px-5">Permiso</th>
                  <th className="py-3 px-4">Categoría</th>
                  <th className="py-3 px-4">Descripción Funcional</th>
                  <th className="py-3 px-3 text-center">Admin</th>
                  <th className="py-3 px-3 text-center">Operator</th>
                  <th className="py-3 px-3 text-center">Auditor</th>
                  <th className="py-3 px-4 text-center">User (legacy)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-black/5 dark:divide-white/[0.04]">
                {filteredRows.map((row) => (
                  <tr key={row.permission} className="hover:bg-black/[0.015] dark:hover:bg-white/[0.015] transition-colors">
                    <td className="py-3 px-5 font-mono font-semibold text-cercano-night dark:text-white">
                      {row.permission}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded-lg bg-black/5 dark:bg-white/5 text-[11px] font-medium text-gray-600 dark:text-gray-300">
                        {row.category}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-cercano-slate dark:text-gray-400 text-[11.5px] max-w-xs">
                      {row.description}
                    </td>
                    <td className="py-3 px-3 text-center">{renderBadge(row.admin)}</td>
                    <td className="py-3 px-3 text-center">{renderBadge(row.operator)}</td>
                    <td className="py-3 px-3 text-center">{renderBadge(row.auditor)}</td>
                    <td className="py-3 px-4 text-center">{renderBadge(row.user)}</td>
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
