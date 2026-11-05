// Copyright (C) 2026 Cercano Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface AppleSheetProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  maxWidth?: string;
}

export const AppleSheet: React.FC<AppleSheetProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = 'max-w-xl',
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    if (isOpen) {
      document.body.style.overflow = 'hidden';
      window.addEventListener('keydown', handleKeyDown);
    } else {
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
      {/* Dimming Scrim with backdrop blur */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-md transition-opacity duration-300 animate-fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Floating Apple Sheet / Card Modal */}
      <div
        role="dialog"
        aria-modal="true"
        className={`relative w-full ${maxWidth} bg-white/90 dark:bg-zinc-900/90 backdrop-blur-2xl rounded-3xl p-6 sm:p-8 shadow-2xl border border-black/10 dark:border-white/15 animate-sheet-in z-10`}
      >
        {/* Sheet Grab Handle / Top pill */}
        <div className="flex justify-center -mt-2 mb-4">
          <div className="w-12 h-1.5 rounded-full bg-black/15 dark:bg-white/20" />
        </div>

        {/* Header */}
        <div className="flex items-start justify-between pb-4 mb-6 border-b border-black/5 dark:border-white/10">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-apple-title text-cercano-night dark:text-white">
              {title}
            </h2>
            {subtitle && (
              <p className="text-sm text-cercano-slate dark:text-gray-400 mt-1">
                {subtitle}
              </p>
            )}
          </div>

          <button
            onClick={onClose}
            className="btn-apple p-2 rounded-full bg-black/5 hover:bg-black/10 dark:bg-white/10 dark:hover:bg-white/15 text-cercano-slate dark:text-gray-300 transition-colors"
            aria-label="Cerrar modal"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="max-h-[75vh] overflow-y-auto pr-1">
          {children}
        </div>
      </div>
    </div>
  );
};
