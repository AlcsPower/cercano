// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React from 'react';

interface StatusPillProps {
  status: 'online' | 'offline' | 'operational' | 'idle' | 'warning' | 'stopped';
  label?: string;
  size?: 'sm' | 'md';
  pulse?: boolean;
}

export const StatusPill: React.FC<StatusPillProps> = ({
  status,
  label,
  size = 'md',
  pulse = false,
}) => {
  const isOnline = status === 'online' || status === 'operational';
  const isWarning = status === 'warning';
  const isIdle = status === 'idle';

  const defaultLabel = isOnline
    ? 'En Línea'
    : isIdle
    ? 'En Espera'
    : isWarning
    ? 'Advertencia'
    : status === 'stopped'
    ? 'Detenido'
    : 'Desconectado';

  const displayLabel = label || defaultLabel;

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium rounded-full ${
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs'
      } ${
        isOnline
          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20'
          : isWarning
          ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/20'
          : 'bg-black/5 dark:bg-white/10 text-cercano-slate dark:text-gray-400 border border-black/5 dark:border-white/[0.04]'
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          isOnline
            ? `bg-cercano-green ${pulse ? 'pulse-emerald' : ''}`
            : isWarning
            ? 'bg-amber-400'
            : isIdle
            ? 'bg-blue-400'
            : 'bg-gray-400'
        }`}
      />
      <span>{displayLabel}</span>
    </span>
  );
};
