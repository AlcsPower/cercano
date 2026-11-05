// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React from 'react';

interface AppleButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'accent';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  icon?: React.ReactNode;
}

export const AppleButton: React.FC<AppleButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  icon,
  className = '',
  disabled,
  ...props
}) => {
  const baseStyles =
    'btn-apple font-medium rounded-xl select-none outline-none focus-visible:ring-2 focus-visible:ring-cercano-blue/40 disabled:opacity-40 disabled:pointer-events-none cursor-pointer';

  const sizeStyles = {
    sm: 'text-xs px-3 py-1.5 gap-1.5',
    md: 'text-sm px-4 py-2.5 gap-2',
    lg: 'text-base px-5 py-3 gap-2.5',
  }[size];

  const variantStyles = {
    primary:
      'bg-cercano-blue hover:bg-cercano-blue-hover text-white shadow-sm shadow-cercano-blue/20 border-t border-white/25',
    secondary:
      'bg-black/5 hover:bg-black/8 dark:bg-white/10 dark:hover:bg-white/15 text-cercano-night dark:text-white border border-black/5 dark:border-white/10 backdrop-blur-md',
    ghost:
      'bg-transparent hover:bg-black/5 dark:hover:bg-white/5 text-cercano-slate dark:text-gray-300 hover:text-cercano-night dark:hover:text-white',
    danger:
      'bg-red-500/10 hover:bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/20',
    accent:
      'bg-cercano-green/15 hover:bg-cercano-green/20 text-cercano-green-dark dark:text-cercano-green border border-cercano-green/30 font-semibold',
  }[variant];

  return (
    <button
      className={`${baseStyles} ${sizeStyles} ${variantStyles} ${className}`}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <svg
          className="animate-spin h-4 w-4 shrink-0"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      ) : (
        icon && <span className="shrink-0">{icon}</span>
      )}
      <span>{children}</span>
    </button>
  );
};
