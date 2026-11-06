// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React from 'react';

interface AppleCardProps {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
  hoverable?: boolean;
}

export const AppleCard: React.FC<AppleCardProps> = ({
  children,
  className = '',
  onClick,
  hoverable = false,
}) => {
  const isInteractive = hoverable || Boolean(onClick);

  return (
    <div
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
      className={`apple-card-surface rounded-2xl p-6 transition-[box-shadow,border-color,transform] duration-150 ease-out ${
        isInteractive
          ? 'hover:shadow-lg hover:border-cercano-blue/30 hover:-translate-y-0.5 active:scale-[0.98] cursor-pointer'
          : ''
      } ${
        onClick
          ? 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40'
          : ''
      } ${className}`}
    >
      {children}
    </div>
  );
};
