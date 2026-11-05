// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React from 'react';

interface CercanoLogoProps {
  size?: number;
  showWordmark?: boolean;
  className?: string;
  theme?: 'light' | 'dark' | 'auto';
}

export const CercanoLogo: React.FC<CercanoLogoProps> = ({
  size = 32,
  showWordmark = false,
  className = '',
}) => {
  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      {/* Official Cercano Vector Icon */}
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 64 64"
        width={size}
        height={size}
        role="img"
        aria-label="Cercano Icon"
        className="shrink-0 transition-transform duration-200 hover:scale-[1.03]"
      >
        {/* Rounded rect background - Azul Cercano #3B5BFF */}
        <rect x="0" y="0" width="64" height="64" rx="16" fill="#3B5BFF" />
        {/* White open ring "C" */}
        <path
          d="M47.32 19.14 A20 20 0 1 0 47.32 44.86"
          fill="none"
          stroke="#FFFFFF"
          strokeWidth="7"
          strokeLinecap="round"
        />
        {/* Remote control cursor - Verde #2DD4A7 */}
        <path
          d="M34 24 L34 41 L38.5 37 L42 45 L45.5 43.5 L42 35.8 L48 35.8 Z"
          fill="#2DD4A7"
          stroke="#2DD4A7"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />
      </svg>

      {showWordmark && (
        <span
          className="font-extrabold tracking-[-0.04em] text-cercano-night dark:text-white leading-none font-sans"
          style={{ fontSize: `${Math.max(18, size * 0.65)}px` }}
        >
          cercano
        </span>
      )}
    </div>
  );
};
