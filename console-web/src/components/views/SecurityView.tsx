// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect, useState } from 'react';
import {
  KeyRound,
  ShieldCheck,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  Fingerprint,
  Lock,
  FileCheck2,
} from 'lucide-react';
import { apiClient } from '../../api/client';
import { ServerPublicKeyResponse } from '../../types';
import { AppleCard } from '../common/AppleCard';
import { AppleButton } from '../common/AppleButton';
import { AppleSheet } from '../common/AppleSheet';

interface SecurityViewProps {
  isRotateModalOpen: boolean;
  setIsRotateModalOpen: (open: boolean) => void;
}

export const SecurityView: React.FC<SecurityViewProps> = ({
  isRotateModalOpen,
  setIsRotateModalOpen,
}) => {
  const [keyInfo, setKeyInfo] = useState<ServerPublicKeyResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);

  // Rotation form state
  const [rotationReason, setRotationReason] = useState('');
  const [isRotating, setIsRotating] = useState(false);
  const [rotationResult, setRotationResult] = useState<string | null>(null);

  const fetchKeyInfo = async () => {
    setLoading(true);
    try {
      const data = await apiClient.getServerPublicKey();
      setKeyInfo(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchKeyInfo();
  }, []);

  const handleCopyKey = () => {
    if (!keyInfo) return;
    navigator.clipboard.writeText(keyInfo.public_key);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleCopyFingerprint = () => {
    if (!keyInfo?.fingerprint) return;
    navigator.clipboard.writeText(keyInfo.fingerprint);
    setCopiedFingerprint(true);
    setTimeout(() => setCopiedFingerprint(false), 2000);
  };

  const handleExecuteRotation = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsRotating(true);
    try {
      const result = await apiClient.rotateServerKeys(rotationReason || 'Rotación programada desde Consola Web');
      setRotationResult(`Clave rotada exitosamente a las ${new Date(result.rotated_at).toLocaleTimeString()}`);
      setRotationReason('');
      await fetchKeyInfo();
      setTimeout(() => {
        setIsRotateModalOpen(false);
        setRotationResult(null);
      }, 1500);
    } finally {
      setIsRotating(false);
    }
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-apple-display text-cercano-night dark:text-white">
            Gestión de Claves y Seguridad
          </h1>
          <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
            Supervisión de clave de firma Ed25519 del servidor y parámetros de cifrado punto a punto
          </p>
        </div>

        <div className="flex items-center gap-2">
          <AppleButton
            variant="secondary"
            size="sm"
            onClick={fetchKeyInfo}
            icon={<RefreshCw size={14} className={loading ? 'animate-spin' : ''} />}
          >
            Actualizar
          </AppleButton>
          <AppleButton
            variant="primary"
            size="sm"
            onClick={() => setIsRotateModalOpen(true)}
            icon={<KeyRound size={14} />}
          >
            Rotar Clave del Servidor
          </AppleButton>
        </div>
      </div>

      {/* Main Public Key Display Card */}
      <AppleCard className="p-6 sm:p-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-black/5 dark:border-white/[0.04]">
          <div className="flex items-center gap-3.5">
            <div className="p-3.5 rounded-2xl bg-cercano-blue/10 dark:bg-cercano-blue/20 text-cercano-blue dark:text-blue-300">
              <ShieldCheck size={26} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold tracking-apple-title text-cercano-night dark:text-white">
                  Clave Pública de Firma Ed25519 Activa
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20">
                  Válida y en servicio
                </span>
              </div>
              <p className="text-xs text-cercano-slate dark:text-gray-400 mt-0.5">
                Utilizada por todos los clientes Cercano para verificar la identidad auténtica del servidor de señalización
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <AppleButton
              variant="secondary"
              size="sm"
              onClick={handleCopyKey}
              icon={copiedKey ? <Check size={14} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={14} />}
            >
              {copiedKey ? 'Clave Copiada' : 'Copiar Clave'}
            </AppleButton>
          </div>
        </div>

        {/* Monospace Key Block */}
        <div className="mt-6">
          <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-400 uppercase tracking-wider mb-2">
            Cadena de Clave Pública (Base64)
          </label>
          <div className="relative p-4 rounded-2xl bg-black/[0.03] dark:bg-black/30 border border-black/10 dark:border-white/[0.06] font-mono text-sm text-cercano-night dark:text-blue-200 break-all select-all flex items-center justify-between">
            <span>{keyInfo ? keyInfo.public_key : 'Cargando clave criptográfica...'}</span>
          </div>
        </div>

        {/* SHA-256 Fingerprint */}
        <div className="mt-5 p-4 rounded-2xl bg-black/[0.02] dark:bg-white/[0.02] border border-black/5 dark:border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Fingerprint size={20} className="text-cercano-slate dark:text-gray-400 shrink-0" />
            <div>
              <span className="text-xs text-cercano-slate dark:text-gray-400 font-medium">
                Huella Digital SHA-256 (Verificación Manual):
              </span>
              <p className="font-mono text-xs font-semibold text-cercano-night dark:text-white mt-0.5">
                {keyInfo?.fingerprint || 'Calculando digestión SHA-256...'}
              </p>
            </div>
          </div>

          <button
            onClick={handleCopyFingerprint}
            className="btn-apple self-start sm:self-center text-xs font-medium text-cercano-blue dark:text-blue-400 hover:underline flex items-center gap-1.5"
          >
            {copiedFingerprint ? <Check size={14} className="text-emerald-600 dark:text-emerald-400" /> : <Copy size={14} />}
            <span>{copiedFingerprint ? 'Huella copiada' : 'Copiar huella'}</span>
          </button>
        </div>
      </AppleCard>

      {/* Security Architecture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <AppleCard>
          <div className="flex items-center gap-2.5 mb-2 text-cercano-blue">
            <Lock size={18} />
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">
              Cifrado Extremo a Extremo
            </h3>
          </div>
          <p className="text-xs text-cercano-slate dark:text-gray-400 leading-relaxed">
            Las sesiones directas P2P y retransmitidas por <code className="font-mono">hbbr</code> utilizan curvas elípticas Curve25519 con claves efímeras derivadas en cada sesión, garantizando secreto perfecto hacia adelante (PFS).
          </p>
        </AppleCard>

        <AppleCard>
          <div className="flex items-center gap-2.5 mb-2 text-cercano-green-dark dark:text-cercano-green">
            <ShieldCheck size={18} />
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">
              Anti Man-in-the-Middle (MITM)
            </h3>
          </div>
          <p className="text-xs text-cercano-slate dark:text-gray-400 leading-relaxed">
            El cliente Cercano valida estrictamente la firma del servidor contra la clave pública embebida. Ningún servidor no autorizado puede interceptar ni descifrar la señalización.
          </p>
        </AppleCard>

        <AppleCard>
          <div className="flex items-center gap-2.5 mb-2 text-purple-500">
            <FileCheck2 size={18} />
            <h3 className="text-sm font-bold text-cercano-night dark:text-white">
              Rotación con Respaldo
            </h3>
          </div>
          <p className="text-xs text-cercano-slate dark:text-gray-400 leading-relaxed">
            Cada rotación de par de claves en <code className="font-mono">cercano-api</code> crea automáticamente una copia de respaldo con sello de tiempo del par anterior en disco, permitiendo auditorías forenses.
          </p>
        </AppleCard>
      </div>

      {/* Rotate Key Modal / Apple Sheet */}
      <AppleSheet
          isOpen={isRotateModalOpen}
          onClose={() => setIsRotateModalOpen(false)}
          title="Rotar Clave de Firma del Servidor"
          subtitle="Genera un nuevo par de claves de firma Ed25519 y archiva el par actual"
        >
          {rotationResult ? (
            <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-800 dark:text-emerald-300 text-sm flex items-center gap-3">
              <Check size={20} className="text-emerald-500 shrink-0" />
              <span>{rotationResult}</span>
            </div>
          ) : (
            <form onSubmit={handleExecuteRotation} className="space-y-5">
              {/* Security Advisory Warning */}
              <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-start gap-3">
                <AlertTriangle size={20} className="text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <div className="text-xs text-amber-900 dark:text-amber-200 space-y-1">
                  <p className="font-bold">Aviso Crítico de Seguridad</p>
                  <p className="leading-relaxed">
                    Al rotar la clave pública, los clientes Cercano existentes con la clave anterior requerirán actualizar su configuración o recibir el nuevo perfil preconfigurado para poder conectarse al servidor de señalización.
                  </p>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-cercano-slate dark:text-gray-300 mb-1.5 ml-1">
                  Motivo de la rotación (para registro de auditoría)
                </label>
                <input
                  type="text"
                  value={rotationReason}
                  onChange={(e) => setRotationReason(e.target.value)}
                  placeholder="Ej. Rotación semestral de seguridad programada"
                  className="w-full px-4 py-2.5 rounded-xl bg-black/5 dark:bg-white/5 border border-black/10 dark:border-white/[0.06] text-cercano-night dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-cercano-blue/40"
                />
              </div>

              <div className="pt-3 border-t border-black/5 dark:border-white/[0.04] flex items-center justify-end gap-3">
                <AppleButton
                  type="button"
                  variant="ghost"
                  size="md"
                  onClick={() => setIsRotateModalOpen(false)}
                >
                  Cancelar
                </AppleButton>
                <AppleButton
                  type="submit"
                  variant="primary"
                  size="md"
                  isLoading={isRotating}
                  icon={<RefreshCw size={14} />}
                >
                  Confirmar y Generar Nueva Clave
                </AppleButton>
              </div>
            </form>
          )}
        </AppleSheet>
    </div>
  );
};
