// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import { Users as UsersIcon, Shield, UserPlus, Trash2, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';
import { apiClient } from '../../api/client';
import { UserDetail, RoleDetail, UserRole } from '../../types';
import { AppleButton } from '../common/AppleButton';

export const UsersView: React.FC = () => {
  const [users, setUsers] = useState<UserDetail[]>([]);
  const [roles, setRoles] = useState<RoleDetail[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('operator');
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [u, r] = await Promise.all([apiClient.getUsers(), apiClient.getRoles()]);
      setUsers(u);
      setRoles(r);
    } catch {
      setError('Error al cargar usuarios y roles');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) return;
    try {
      await apiClient.createUser({
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
      });
      setShowAddModal(false);
      setNewUsername('');
      setNewPassword('');
      loadData();
    } catch (err: unknown) {
      if (err instanceof Error) setError(err.message);
    }
  };

  const handleToggleActive = async (user: UserDetail) => {
    try {
      await apiClient.updateUser(user.id, { is_active: !user.is_active });
      loadData();
    } catch (err: unknown) {
      if (err instanceof Error) setError(err.message);
    }
  };

  const handleDeleteUser = async (user: UserDetail) => {
    if (!confirm(`¿Eliminar al usuario ${user.username}?`)) return;
    try {
      await apiClient.deleteUser(user.id);
      loadData();
    } catch (err: unknown) {
      if (err instanceof Error) setError(err.message);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-cercano-night dark:text-white flex items-center gap-2.5">
            <UsersIcon className="text-cercano-blue" size={26} />
            Gestión de Usuarios y Roles (RBAC)
          </h2>
          <p className="text-xs text-cercano-slate dark:text-gray-400 mt-1">
            Administración de cuentas institucionales, directivas 2FA y privilegios de acceso
          </p>
        </div>
        <AppleButton
          variant="primary"
          onClick={() => setShowAddModal(true)}
          icon={<UserPlus size={16} />}
        >
          Nuevo Usuario
        </AppleButton>
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

      {/* Roles Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {roles.map((r) => (
          <div
            key={r.role}
            className="p-5 rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-cercano-blue/10 text-cercano-blue">
                  {r.role}
                </span>
                <Shield size={16} className="text-cercano-slate/60 dark:text-gray-400" />
              </div>
              <p className="text-xs text-cercano-slate dark:text-gray-300 mt-1">
                {r.description}
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-black/5 dark:border-white/[0.04] text-[11px] text-gray-500 font-mono">
              {r.permissions.length} permisos aplicados
            </div>
          </div>
        ))}
      </div>

      {/* Users Table */}
      <div className="rounded-3xl bg-white/70 dark:bg-zinc-800/60 backdrop-blur-xl border border-black/5 dark:border-white/[0.04] shadow-sm overflow-hidden">
        <div className="p-5 border-b border-black/5 dark:border-white/[0.04] flex items-center justify-between">
          <h3 className="font-semibold text-sm text-cercano-night dark:text-white">
            Cuentas Registradas ({users.length})
          </h3>
        </div>

        {isLoading ? (
          <div className="p-10 text-center text-sm text-cercano-slate animate-pulse">
            Cargando usuarios...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-black/[0.02] dark:bg-white/[0.02] text-cercano-slate dark:text-gray-400 font-medium border-b border-black/5 dark:border-white/[0.04]">
                <tr>
                  <th className="py-3.5 px-5">Usuario</th>
                  <th className="py-3.5 px-4">Rol</th>
                  <th className="py-3.5 px-4 text-center">Estado</th>
                  <th className="py-3.5 px-4 text-center">2FA Configurado</th>
                  <th className="py-3.5 px-4 text-center">2FA Requerido</th>
                  <th className="py-3.5 px-5 text-right">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-black/5 dark:divide-white/[0.04]">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-black/[0.01] dark:hover:bg-white/[0.01]">
                    <td className="py-3.5 px-5 font-semibold text-cercano-night dark:text-white">
                      {u.username}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="font-mono px-2 py-0.5 rounded bg-black/5 dark:bg-white/5">
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <button
                        onClick={() => handleToggleActive(u)}
                        className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-medium cursor-pointer ${
                          u.is_active
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                            : 'bg-zinc-500/10 text-zinc-500'
                        }`}
                      >
                        {u.is_active ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                        {u.is_active ? 'Activo' : 'Inactivo'}
                      </button>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <span className={u.totp_enabled ? 'text-emerald-500 font-semibold' : 'text-gray-400'}>
                        {u.totp_enabled ? '✓ Sí' : '— No'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      <span className={u.is_2fa_required ? 'text-amber-500 font-semibold' : 'text-gray-400'}>
                        {u.is_2fa_required ? 'Obligatorio' : 'Opcional'}
                      </span>
                    </td>
                    <td className="py-3.5 px-5 text-right space-x-2">
                      <button
                        onClick={() => handleDeleteUser(u)}
                        disabled={u.username === 'admin'}
                        className="p-1.5 rounded-xl hover:bg-red-500/10 text-red-500 disabled:opacity-30 disabled:hover:bg-transparent"
                        title="Eliminar usuario"
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add User Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md bg-white dark:bg-zinc-900 rounded-3xl p-6 shadow-2xl border border-black/10 dark:border-white/[0.08]">
            <h3 className="text-lg font-bold text-cercano-night dark:text-white mb-4">
              Crear Nuevo Usuario
            </h3>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold mb-1">Nombre de usuario</label>
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-xs focus:ring-2 focus:ring-cercano-blue"
                  placeholder="ej. operador01"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1">Contraseña temporal</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-xs focus:ring-2 focus:ring-cercano-blue"
                  placeholder="••••••••••••"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1">Rol institucional</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as UserRole)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/10 text-xs focus:ring-2 focus:ring-cercano-blue"
                >
                  <option value="operator">Operator (Soporte / Chat)</option>
                  <option value="auditor">Auditor (Solo lectura / Forense)</option>
                  <option value="admin">Admin (Control total)</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <AppleButton variant="secondary" onClick={() => setShowAddModal(false)}>
                  Cancelar
                </AppleButton>
                <AppleButton variant="primary" type="submit">
                  Crear Cuenta
                </AppleButton>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
