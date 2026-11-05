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
  return (
    <div
      onClick={onClick}
      className={`apple-card-surface rounded-2xl p-6 transition-all duration-200 ${
        hoverable ? 'hover:shadow-lg hover:border-cercano-blue/30 cursor-pointer' : ''
      } ${className}`}
    >
      {children}
    </div>
  );
};
